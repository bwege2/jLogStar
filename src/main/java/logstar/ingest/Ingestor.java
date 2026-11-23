package logstar.ingest;

import logstar.Json;
import logstar.index.Fields;
import logstar.index.IndexMeta;
import logstar.index.LogAnalyzer;
import org.apache.lucene.codecs.lucene104.Lucene104Codec;
import org.apache.lucene.document.*;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.index.NoMergePolicy;
import org.apache.lucene.search.Sort;
import org.apache.lucene.search.SortField;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.util.BytesRef;

import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.ZoneId;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;

/** Parallel ingestion of log files into a Lucene index. */
public final class Ingestor {
    public static final int MAX_TEXT = 32 * 1024;
    static final long CHUNK = 48L << 20;

    private final Path indexDir;
    private final ZoneId zone;
    private final int threads;
    private final KeyDict dict = new KeyDict();
    private final AtomicLong bytesDone = new AtomicLong();
    private final AtomicLong eventsDone = new AtomicLong();
    private IndexWriter writer;

    public Ingestor(Path indexDir, ZoneId zone, int threads) {
        this.indexDir = indexDir;
        this.zone = zone;
        this.threads = threads;
    }

    public IndexMeta run(List<Path> inputs) throws Exception {
        long t0 = System.currentTimeMillis();
        FormatDetector fd = new FormatDetector(zone);
        List<LogFile> files = fd.expand(inputs);
        if (files.isEmpty()) throw new IOException("no input files");
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        // detect formats in parallel
        List<Future<?>> fs = new ArrayList<>();
        for (LogFile f : files) fs.add(pool.submit(() -> fd.detect(f)));
        for (Future<?> f : fs) f.get();
        for (LogFile f : files) if (f.skipped == null && f.timeOnly) fd.alignTimeOnly(f, files);
        long totalBytes = 0;
        for (LogFile f : files) {
            if (f.skipped != null) System.out.printf("  skip %s (%s)%n", f.path, f.skipped);
            else {
                System.out.printf("  %-60s %8.1f MB  %s%s%s%n", shorten(f.path, 60), f.size / 1e6, f.layout,
                        f.timeOnly ? " (time only, day " + java.time.LocalDate.ofEpochDay(f.baseDay) + ")" : "", f.gzip ? " gz" : "");
                totalBytes += f.size;
            }
        }

        Files.createDirectories(indexDir);
        Path lucene = indexDir.resolve("lucene");
        IndexWriterConfig cfg = new IndexWriterConfig(LogAnalyzer.perField());
        cfg.setOpenMode(IndexWriterConfig.OpenMode.CREATE);
        cfg.setCodec(new Lucene104Codec(Lucene104Codec.Mode.BEST_COMPRESSION));
        cfg.setIndexSort(new Sort(new SortField(Fields.TS, SortField.Type.LONG)));
        long maxHeapMb = Runtime.getRuntime().maxMemory() >> 20;
        cfg.setRAMBufferSizeMB(Math.max(64, Math.min(2048, maxHeapMb / 3)));
        cfg.setUseCompoundFile(false);
        // no merging while ingesting: merges of sorted, compressed segments cost more than they save for this
        // read-mostly index; searches run segment-parallel anyway
        cfg.setMergePolicy(NoMergePolicy.INSTANCE);
        writer = new IndexWriter(FSDirectory.open(lucene), cfg);

        // build tasks: big plain files are split into chunks; others whole
        List<Callable<Void>> tasks = new ArrayList<>();
        List<LogFile> ordered = new ArrayList<>(files);
        ordered.sort(Comparator.comparingLong((LogFile f) -> f.size).reversed());
        for (LogFile f : ordered) {
            if (f.skipped != null) continue;
            if (f.splittable() && f.size > CHUNK * 3 / 2) {
                for (long s = 0; s < f.size; s += CHUNK) {
                    long start = s, end = Math.min(f.size, s + CHUNK);
                    tasks.add(() -> { new Worker().process(f, start, end); return null; });
                }
            } else tasks.add(() -> { new Worker().process(f, 0, Long.MAX_VALUE); return null; });
        }
        final long total = totalBytes;
        ScheduledExecutorService ticker = Executors.newSingleThreadScheduledExecutor();
        ticker.scheduleAtFixedRate(() -> {
            double s = (System.currentTimeMillis() - t0) / 1000.0;
            System.out.printf("\r  %,8.0f MB  %,12d events  %,7.0f MB/s  %,9.0f ev/s  %d templates   ",
                    bytesDone.get() / 1e6, eventsDone.get(), bytesDone.get() / 1e6 / s, eventsDone.get() / s, dict.size());
        }, 1, 1, TimeUnit.SECONDS);
        long tc;
        try {
            for (Future<Void> f : pool.invokeAll(tasks)) f.get();
            System.out.printf("%n  parsed in %.1f s, writing index …%n", (System.currentTimeMillis() - t0) / 1000.0);
            tc = System.currentTimeMillis();
            // flush the in-memory segments in parallel (commit alone would flush them one after another)
            List<Callable<Void>> flushers = new ArrayList<>();
            for (int i = 0; i < threads; i++) flushers.add(() -> {
                while (writer.flushNextBuffer()) { }
                return null;
            });
            for (Future<Void> f : pool.invokeAll(flushers)) f.get();
        } finally {
            ticker.shutdownNow();
            pool.shutdown();
        }
        writer.commit();
        writer.close();
        System.out.printf("  committed in %.1f s%n", (System.currentTimeMillis() - tc) / 1000.0);

        IndexMeta meta = new IndexMeta();
        meta.zone = zone.getId();
        meta.created = System.currentTimeMillis();
        meta.files = files;
        meta.inputBytes = totalBytes;
        meta.ingestMs = System.currentTimeMillis() - t0;
        for (LogFile f : files) {
            meta.events += f.events;
            if (f.events > 0) {
                meta.minTs = Math.min(meta.minTs, f.minTs);
                meta.maxTs = Math.max(meta.maxTs, f.maxTs);
            }
        }
        meta.keys = dict.size();
        Json.write(indexDir.resolve("meta.json"), meta);
        Json.write(indexDir.resolve("keys.json"), dict.all());
        meta.rawBytes = bytesDone.get();
        System.out.printf("  %,d events, %,d templates, %.2f GB log text (%.2f GB on disk) in %.1f s (%.0f MB/s)%n", meta.events, meta.keys,
                meta.rawBytes / 1e9, total / 1e9, meta.ingestMs / 1000.0, meta.rawBytes / 1e6 / (meta.ingestMs / 1000.0));
        return meta;
    }

    private static String shorten(String s, int n) {
        return s.length() <= n ? s : "…" + s.substring(s.length() - n + 1);
    }

    // ------------------------------------------------------------------------------------------------ worker

    private final class Worker {
        final TsParser tsp = new TsParser(zone);
        final TsParser.Result r = new TsParser.Result();
        final Matcher[] cache = new Matcher[1];
        RawEvent ev = new RawEvent();
        RawEvent next = new RawEvent();
        final HashMap<String, KeyInfo> localKeys = new HashMap<>();
        final Layout.JsonLayout json = new Layout.JsonLayout();
        Layout layout;
        LogFile file;
        boolean active;
        long count, minTs = Long.MAX_VALUE, maxTs = Long.MIN_VALUE;
        long day;
        long prevMsOfDay = -1;

        void process(LogFile f, long start, long end) throws IOException {
            this.file = f;
            this.layout = f.json ? null : FormatDetector.layoutByName(f.layout);
            this.day = f.baseDay;
            InputStream in;
            long srcStart = 0;
            if (start > 0) {
                FileChannel ch = FileChannel.open(f.file, StandardOpenOption.READ);
                ch.position(start - 1);
                in = Channels.newInputStream(ch);
                srcStart = start - 1;
            } else in = f.open();
            long lastReported = srcStart;
            try (LineSource src = new LineSource(in, srcStart, 1 << 20)) {
                if (start > 0) src.next(); // discard partial line; next line begins at >= start
                String line;
                int n = 0;
                while ((line = src.next()) != null) {
                    long off = src.lineOffset;
                    int st = startEvent(line, off);
                    boolean isStart = st == 1;
                    if (st == 2) continue; // merged into the previous event (stderr stack trace line)
                    if (isStart && off >= end) {
                        // belongs to the next chunk; flush and stop (undo the speculative start)
                        active = false;
                        break;
                    }
                    if (!isStart && active) {
                        if (ev.text.length() < MAX_TEXT) {
                            ev.text.append('\n').append(line, 0, Math.min(line.length(), MAX_TEXT - ev.text.length()));
                        } else ev.truncated = true;
                        ev.lines++;
                    }
                    if (++n % 4096 == 0) {
                        long p = src.position();
                        bytesDone.addAndGet(p - lastReported);
                        lastReported = p;
                    }
                }
                if (active) flush();
                bytesDone.addAndGet(Math.min(src.position(), end == Long.MAX_VALUE ? src.position() : end) - lastReported);
            }
            file.addStats(count, minTs, maxTs);
        }

        /**
         * 0 = continuation line, 1 = new event (previous one flushed, ev initialised),
         * 2 = header line merged into the previous event (WildFly logs printStackTrace() line by line as [stderr]).
         */
        private int startEvent(String line, long off) {
            if (line.isEmpty()) return 0;
            next.reset();
            if (file.json) {
                if (line.charAt(0) != '{') return 0;
                if (!json.parseJson(line, next, tsp, r)) return 0;
            } else {
                char c = line.charAt(0);
                if (!(c >= '0' && c <= '9') && c != '[') return 0;
                if (!tsp.parse(line, 0, r)) return 0;
                if (r.timeOnly) {
                    if (prevMsOfDay >= 0 && r.msOfDay < prevMsOfDay - 3_600_000L) day++;
                    prevMsOfDay = r.msOfDay;
                    next.ts = tsp.toEpoch(day, r.msOfDay);
                } else next.ts = r.epochMs;
                if (!layout.parse(line, r.end, next, cache, 0)) Layout.GENERIC.parse(line, r.end, next, cache, 0);
                next.text.append(line, 0, Math.min(line.length(), MAX_TEXT));
                next.bodyStart = next.text.length();
            }
            if (active && isStdStream(ev.logger) && ev.logger.equals(next.logger) && ev.thread.equals(next.thread)
                    && next.ts - ev.ts <= 2000 && isTraceLine(next.message)) {
                if (ev.text.length() < MAX_TEXT) ev.text.append('\n').append(next.message, 0, Math.min(next.message.length(), MAX_TEXT - ev.text.length()));
                else ev.truncated = true;
                ev.lines++;
                return 2;
            }
            if (active) flush();
            RawEvent t = ev;
            ev = next;
            next = t;
            ev.offset = off;
            ev.fileId = file.id;
            ev.lines = 1;
            active = true;
            return 1;
        }

        private static boolean isStdStream(String logger) {
            return "stderr".equals(logger) || "stdout".equals(logger);
        }

        private static boolean isTraceLine(String msg) {
            String m = msg.strip();
            if (m.startsWith("at ") || m.startsWith("Caused by: ") || m.startsWith("Suppressed: ") || m.startsWith("... ")) return true;
            int e = 0;
            while (e < m.length() && m.charAt(e) != ':' && m.charAt(e) != ' ') e++;
            return ExceptionInfo.isExceptionClass(m, 0, e);
        }

        private void flush() {
            active = false;
            ExceptionInfo ex = ExceptionInfo.parse(ev.text, ev.bodyStart, ev.message);
            String msg = ev.message == null ? "" : ev.message;
            String code = null;
            if (msg.length() >= 5) {
                Matcher m = ExceptionInfo.CODE.matcher(msg.length() > 160 ? msg.substring(0, 160) : msg);
                if (m.find()) code = m.group(1);
            }
            if (code == null && !ex.codes.isEmpty()) code = ex.codes.getFirst();
            String masked = Masker.mask(msg);
            String key = ev.level + "\u0001" + ev.logger + "\u0001" + masked + "\u0001" + ex.signature;
            KeyInfo ki = localKeys.get(key);
            if (ki == null) {
                ki = dict.get(key);
                if (ki == null) {
                    if (dict.size() >= KeyDict.MAX_KEYS) {
                        String[] toks = masked.split(" ", 4);
                        masked = String.join(" ", Arrays.copyOf(toks, Math.min(3, toks.length))) + " …";
                        key = ev.level + "\u0001" + ev.logger + "\u0001" + masked + "\u0001" + ex.signature;
                    }
                    KeyInfo p = new KeyInfo();
                    p.level = ev.level;
                    p.logger = ev.logger;
                    p.template = masked;
                    p.code = code;
                    p.exOuter = ex.outer;
                    p.exRoot = ex.root;
                    p.exSig = ex.signature;
                    p.exClasses = ex.classes.isEmpty() ? null : String.join(" ", ex.classes);
                    p.sample = msg.length() > 400 ? msg.substring(0, 400) : msg;
                    p.rootMessage = ex.rootMessage;
                    ki = dict.add(key, p);
                }
                if (localKeys.size() > 50_000) localKeys.clear();
                localKeys.put(key, ki);
            }
            Document d = new Document();
            d.add(new LongPoint(Fields.TS, ev.ts));
            d.add(new NumericDocValuesField(Fields.TS, ev.ts));
            d.add(new StoredField(Fields.TS, ev.ts));
            d.add(new IntPoint(Fields.LVL, ev.level));
            d.add(new NumericDocValuesField(Fields.LVL, ev.level));
            d.add(new StringField(Fields.LEVEL, Level.name(ev.level), Field.Store.NO));
            String logger = ev.logger == null ? "" : ev.logger;
            d.add(new StringField(Fields.LOGGER, logger, Field.Store.YES));
            d.add(new SortedDocValuesField(Fields.LOGGER, new BytesRef(logger)));
            String thread = ev.thread == null ? "" : ev.thread;
            d.add(new StringField(Fields.THREAD, thread, Field.Store.YES));
            d.add(new SortedDocValuesField(Fields.THREAD, new BytesRef(thread)));
            if (code != null) {
                d.add(new StringField(Fields.CODE, code, Field.Store.NO));
                d.add(new SortedDocValuesField(Fields.CODE, new BytesRef(code)));
            }
            for (String c : ex.codes) if (!c.equals(code)) d.add(new StringField(Fields.CODE, c, Field.Store.NO));
            for (String c : ex.classes) {
                d.add(new StringField(Fields.EX, c, Field.Store.NO));
                int dot = c.lastIndexOf('.');
                if (dot > 0) d.add(new StringField(Fields.EX, c.substring(dot + 1), Field.Store.NO));
            }
            d.add(new IntPoint(Fields.KEY, ki.id));
            d.add(new NumericDocValuesField(Fields.KEY, ki.id));
            d.add(new StoredField(Fields.KEY, ki.id));
            d.add(new IntPoint(Fields.FILE, ev.fileId));
            d.add(new NumericDocValuesField(Fields.FILE, ev.fileId));
            d.add(new StoredField(Fields.FILE, ev.fileId));
            d.add(new LongPoint(Fields.OFF, ev.offset));
            d.add(new NumericDocValuesField(Fields.OFF, ev.offset));
            d.add(new StoredField(Fields.OFF, ev.offset));
            if (ev.truncated) ev.text.append("\n… [truncated by logStar]");
            String text = ev.text.toString();
            d.add(new TextField(Fields.TEXT, text, Field.Store.NO));
            d.add(new StoredField(Fields.RAW, text));
            try {
                writer.addDocument(d);
            } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
            count++;
            if (ev.ts < minTs) minTs = ev.ts;
            if (ev.ts > maxTs) maxTs = ev.ts;
            eventsDone.incrementAndGet();
        }
    }
}
