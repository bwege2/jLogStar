package logstar.ingest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.zip.ZipFile;

/** Expands inputs into log files and detects the layout of each one by sampling its first lines. */
public final class FormatDetector {
    private static final Pattern FILE_DATE = Pattern.compile("(20\\d{2})[-_.]?(\\d{2})[-_.]?(\\d{2})");
    private static final int SAMPLE_LINES = 3000;

    private final ZoneId zone;

    public FormatDetector(ZoneId zone) {
        this.zone = zone;
    }

    public List<LogFile> expand(List<Path> inputs) throws IOException {
        List<LogFile> out = new ArrayList<>();
        for (Path p : inputs) {
            if (Files.isDirectory(p)) {
                try (Stream<Path> s = Files.walk(p)) {
                    for (Path f : s.filter(Files::isRegularFile).sorted().toList()) addFile(f, out);
                }
            } else if (Files.isRegularFile(p)) addFile(p, out);
            else throw new IOException("Not found: " + p);
        }
        for (int i = 0; i < out.size(); i++) out.get(i).id = i;
        return out;
    }

    private static boolean ignorable(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        return n.startsWith(".") || n.endsWith(".jar") || n.endsWith(".class") || n.endsWith(".png") || n.endsWith(".jpg")
                || n.endsWith(".pdf") || n.endsWith(".lck") || n.endsWith(".pid") || n.endsWith(".exe") || n.endsWith(".so")
                || n.equals("ground_truth.json");
    }

    private void addFile(Path f, List<LogFile> out) throws IOException {
        String name = f.getFileName().toString();
        if (ignorable(name)) return;
        if (name.toLowerCase(Locale.ROOT).endsWith(".zip")) {
            try (ZipFile zf = new ZipFile(f.toFile())) {
                var en = zf.entries();
                while (en.hasMoreElements()) {
                    var e = en.nextElement();
                    if (e.isDirectory() || ignorable(Path.of(e.getName()).getFileName().toString())) continue;
                    LogFile lf = new LogFile();
                    lf.file = f;
                    lf.zipEntry = e.getName();
                    lf.path = f + "!/" + e.getName();
                    lf.size = e.getCompressedSize();
                    lf.mtime = e.getTime();
                    out.add(lf);
                }
            }
            return;
        }
        LogFile lf = new LogFile();
        lf.file = f;
        lf.path = f.toString();
        lf.gzip = name.toLowerCase(Locale.ROOT).endsWith(".gz");
        lf.size = Files.size(f);
        lf.mtime = Files.getLastModifiedTime(f).toMillis();
        out.add(lf);
    }

    /** Detects layout. Sets lf.skipped if the file does not look like a log. */
    public void detect(LogFile lf) {
        TsParser tsp = new TsParser(zone);
        TsParser.Result r = new TsParser.Result();
        Layout.JsonLayout json = new Layout.JsonLayout();
        RawEvent ev = new RawEvent();
        int lines = 0, dated = 0, timeOnly = 0, jsonLines = 0, binary = 0;
        List<String> headers = new ArrayList<>();
        try (LineSource src = new LineSource(lf.open(), 0, 1 << 16)) {
            String line;
            while ((line = src.next()) != null && lines < SAMPLE_LINES) {
                lines++;
                if (line.indexOf('\u0000') >= 0) { binary++; continue; }
                if (!line.isEmpty() && line.charAt(0) == '{') {
                    ev.reset();
                    if (json.parseJson(line, ev, tsp, r)) { jsonLines++; continue; }
                }
                if (tsp.parse(line, 0, r)) {
                    if (r.timeOnly) timeOnly++; else dated++;
                    if (headers.size() < 500) headers.add(line);
                }
            }
        } catch (IOException e) {
            lf.skipped = "read error: " + e.getMessage();
            return;
        }
        if (lines == 0) { lf.skipped = "empty"; return; }
        if (binary > lines / 10) { lf.skipped = "binary"; return; }
        if (jsonLines > 0 && jsonLines >= dated + timeOnly) {
            lf.json = true;
            lf.layout = "json";
            return;
        }
        if (dated + timeOnly == 0 || (dated + timeOnly) < Math.min(5, lines)) {
            lf.skipped = "no timestamps recognised";
            return;
        }
        lf.timeOnly = timeOnly > dated;
        // choose the layout that parses most header lines
        Layout best = Layout.GENERIC;
        int bestHits = 0;
        java.util.regex.Matcher[] cache = new java.util.regex.Matcher[Layout.TEXT_LAYOUTS.size()];
        for (int li = 0; li < Layout.TEXT_LAYOUTS.size(); li++) {
            Layout l = Layout.TEXT_LAYOUTS.get(li);
            int hits = 0;
            for (String h : headers) {
                if (!tsp.parse(h, 0, r)) continue;
                ev.reset();
                if (l.parse(h, r.end, ev, cache, li)) hits++;
            }
            if (hits > bestHits) { bestHits = hits; best = l; }
        }
        if (bestHits < headers.size() * 0.5) best = Layout.GENERIC;
        lf.layout = best.name;
        if (lf.timeOnly) lf.baseDay = baseDay(lf, tsp, r);
    }

    /** For time-only logs: first day = date in file name, else (mtime day - number of day rollovers in the file). */
    private long baseDay(LogFile lf, TsParser tsp, TsParser.Result r) {
        Matcher m = FILE_DATE.matcher(lf.zipEntry != null ? lf.zipEntry : lf.file.getFileName().toString());
        if (m.find()) {
            try {
                return LocalDate.of(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3))).toEpochDay();
            } catch (Exception ignored) { }
        }
        int rollovers = 0;
        long prev = -1;
        try (LineSource src = new LineSource(lf.open(), 0, 1 << 20)) {
            String line;
            while ((line = src.next()) != null) {
                if (tsp.parse(line, 0, r) && r.timeOnly) {
                    if (prev >= 0 && r.msOfDay < prev - 3_600_000L) rollovers++;
                    prev = r.msOfDay;
                }
            }
        } catch (IOException ignored) { }
        return Instant.ofEpochMilli(lf.mtime).atZone(zone).toLocalDate().toEpochDay() - rollovers;
    }

    /**
     * Time-only logs (WildFly console.log) usually repeat lines of a dated server.log. If the file name carries no date,
     * find one of its first lines in a dated file and take the date from there. Returns true if aligned.
     */
    public boolean alignTimeOnly(LogFile t, List<LogFile> files) {
        if (FILE_DATE.matcher(t.zipEntry != null ? t.zipEntry : t.file.getFileName().toString()).find()) return false;
        TsParser tsp = new TsParser(zone);
        TsParser.Result r = new TsParser.Result();
        java.util.HashMap<String, Integer> sample = new java.util.HashMap<>(); // line -> day offset within file
        try (LineSource src = new LineSource(t.open(), 0, 1 << 16)) {
            String line;
            int dayOff = 0;
            long prev = -1;
            while ((line = src.next()) != null && sample.size() < 400) {
                if (tsp.parse(line, 0, r) && r.timeOnly) {
                    if (prev >= 0 && r.msOfDay < prev - 3_600_000L) dayOff++;
                    prev = r.msOfDay;
                    sample.putIfAbsent(line, dayOff);
                }
            }
        } catch (IOException e) {
            return false;
        }
        if (sample.isEmpty()) return false;
        for (LogFile d : files) {
            if (d == t || d.skipped != null || d.timeOnly || d.json) continue;
            long budget = 400L << 20;
            try (LineSource src = new LineSource(d.open(), 0, 1 << 20)) {
                String line;
                while ((line = src.next()) != null && src.position() < budget) {
                    if (line.length() > 11 && line.charAt(4) == '-' && line.charAt(10) == ' ') {
                        Integer off = sample.get(line.substring(11));
                        if (off != null && tsp.parse(line, 0, r) && !r.timeOnly) {
                            long day = LocalDate.of(Integer.parseInt(line.substring(0, 4)), Integer.parseInt(line.substring(5, 7)),
                                    Integer.parseInt(line.substring(8, 10))).toEpochDay();
                            t.baseDay = day - off;
                            t.layout = t.layout + " (Datum aus " + d.file.getFileName() + ")";
                            return true;
                        }
                    }
                }
            } catch (Exception ignored) { }
        }
        return false;
    }

    public static Layout layoutByName(String name) {
        int sp = name.indexOf(' ');
        if (sp > 0) name = name.substring(0, sp);
        for (Layout l : Layout.TEXT_LAYOUTS) if (l.name.equals(name)) return l;
        return Layout.GENERIC;
    }
}
