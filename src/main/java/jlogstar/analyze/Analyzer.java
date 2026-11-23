package jlogstar.analyze;

import jlogstar.Json;
import jlogstar.index.Fields;
import jlogstar.index.IndexMeta;
import jlogstar.ingest.KeyInfo;
import jlogstar.ingest.Level;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.LongPoint;
import org.apache.lucene.index.*;
import org.apache.lucene.search.*;
import org.apache.lucene.store.FSDirectory;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicIntegerArray;
import java.util.concurrent.atomic.AtomicLongArray;

/** Post-ingest analysis: clustering, time series, anomaly detectors, rule matching. Writes analysis.json. */
public final class Analyzer {
    static final int MAX_BUCKETS = 6000;

    private final Path indexDir;
    private final int threads;
    private DateTimeFormatter fmt;

    public Analyzer(Path indexDir, int threads) {
        this.indexDir = indexDir;
        this.threads = threads;
    }

    // ------------------------------------------------------------------------------------ full scan

    static final class ScanLocal {
        long[] keyCount, keyMin, keyMax;
        int[] vol, err, warn;

        ScanLocal(int nk, int nb) {
            keyCount = new long[nk];
            keyMin = new long[nk];
            keyMax = new long[nk];
            Arrays.fill(keyMin, Long.MAX_VALUE);
            Arrays.fill(keyMax, Long.MIN_VALUE);
            vol = new int[nb];
            err = new int[nb];
            warn = new int[nb];
        }
    }

    public Model.Analysis run() throws Exception {
        long t0 = System.currentTimeMillis();
        IndexMeta meta = Json.read(indexDir.resolve("meta.json"), IndexMeta.class);
        List<KeyInfo> keys = Arrays.asList(Json.read(indexDir.resolve("keys.json"), KeyInfo[].class));
        fmt = DateTimeFormatter.ofPattern("dd.MM. HH:mm").withZone(ZoneId.of(meta.zone));
        int nk = keys.size();
        Model.Analysis a = new Model.Analysis();
        long span = Math.max(1, meta.maxTs - meta.minTs + 1);
        a.bucketMs = Stats.niceBucket(span, MAX_BUCKETS);
        a.start = Math.floorDiv(meta.minTs, a.bucketMs) * a.bucketMs;
        a.end = meta.maxTs;
        final int nb = (int) ((meta.maxTs - a.start) / a.bucketMs) + 1;
        final long bstart = a.start, bms = a.bucketMs;

        try (DirectoryReader reader = DirectoryReader.open(FSDirectory.open(indexDir.resolve("lucene")))) {
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            try {
                // ---- scan 1: key stats + volume
                List<ScanLocal> locals = Collections.synchronizedList(new ArrayList<>());
                ThreadLocal<ScanLocal> tl = ThreadLocal.withInitial(() -> {
                    ScanLocal l = new ScanLocal(nk, nb);
                    locals.add(l);
                    return l;
                });
                List<Future<?>> fs = new ArrayList<>();
                for (LeafReaderContext ctx : reader.leaves()) {
                    fs.add(pool.submit(() -> {
                        ScanLocal l = tl.get();
                        LeafReader lr = ctx.reader();
                        NumericDocValues ts = DocValues.getNumeric(lr, Fields.TS);
                        NumericDocValues kv = DocValues.getNumeric(lr, Fields.KEY);
                        NumericDocValues lv = DocValues.getNumeric(lr, Fields.LVL);
                        int max = lr.maxDoc();
                        for (int d = 0; d < max; d++) {
                            if (!ts.advanceExact(d) || !kv.advanceExact(d)) continue;
                            long t = ts.longValue();
                            int k = (int) kv.longValue();
                            int level = lv.advanceExact(d) ? (int) lv.longValue() : Level.INFO;
                            int b = (int) ((t - bstart) / bms);
                            if (b < 0) b = 0; else if (b >= nb) b = nb - 1;
                            l.vol[b]++;
                            if (level >= Level.ERROR) l.err[b]++;
                            else if (level == Level.WARN) l.warn[b]++;
                            l.keyCount[k]++;
                            if (t < l.keyMin[k]) l.keyMin[k] = t;
                            if (t > l.keyMax[k]) l.keyMax[k] = t;
                        }
                        return null;
                    }));
                }
                for (Future<?> f : fs) f.get();
                ScanLocal g = new ScanLocal(nk, nb);
                for (ScanLocal l : locals) {
                    for (int k = 0; k < nk; k++) {
                        g.keyCount[k] += l.keyCount[k];
                        g.keyMin[k] = Math.min(g.keyMin[k], l.keyMin[k]);
                        g.keyMax[k] = Math.max(g.keyMax[k], l.keyMax[k]);
                    }
                    for (int b = 0; b < nb; b++) { g.vol[b] += l.vol[b]; g.err[b] += l.err[b]; g.warn[b] += l.warn[b]; }
                }
                a.volume = g.vol;
                a.errors = g.err;
                a.warnings = g.warn;

                // ---- clustering
                a.keyToCluster = Clusterer.cluster(keys, g.keyCount, a.clusters);
                for (Model.Cluster c : a.clusters) fillCluster(c, keys, g);

                // ---- scan 2: per-cluster series (WARN+) and presence bitsets (all)
                int nc = a.clusters.size();
                int words = (nb + 63) / 64;
                AtomicIntegerArray[] series = new AtomicIntegerArray[nc];
                AtomicLongArray[] presence = new AtomicLongArray[nc];
                for (Model.Cluster c : a.clusters) {
                    if (c.level >= Level.WARN) series[c.id] = new AtomicIntegerArray(nb);
                    else if (c.count >= 10) presence[c.id] = new AtomicLongArray(words);
                }
                final int[] k2c = a.keyToCluster;
                fs.clear();
                for (LeafReaderContext ctx : reader.leaves()) {
                    fs.add(pool.submit(() -> {
                        LeafReader lr = ctx.reader();
                        NumericDocValues ts = DocValues.getNumeric(lr, Fields.TS);
                        NumericDocValues kv = DocValues.getNumeric(lr, Fields.KEY);
                        int max = lr.maxDoc();
                        for (int d = 0; d < max; d++) {
                            if (!ts.advanceExact(d) || !kv.advanceExact(d)) continue;
                            int c = k2c[(int) kv.longValue()];
                            if (c < 0) continue;
                            int b = (int) ((ts.longValue() - bstart) / bms);
                            if (b < 0) b = 0; else if (b >= nb) b = nb - 1;
                            AtomicIntegerArray s = series[c];
                            if (s != null) s.incrementAndGet(b);
                            else {
                                AtomicLongArray p = presence[c];
                                if (p != null) {
                                    long mask = 1L << (b & 63);
                                    if ((p.get(b >>> 6) & mask) == 0) p.getAndAccumulate(b >>> 6, mask, (x, y) -> x | y);
                                }
                            }
                        }
                        return null;
                    }));
                }
                for (Future<?> f : fs) f.get();
                int[][] ser = new int[nc][];
                for (int c = 0; c < nc; c++) {
                    if (series[c] == null) continue;
                    ser[c] = new int[nb];
                    for (int b = 0; b < nb; b++) ser[c][b] = series[c].get(b);
                }

                IndexSearcher searcher = new IndexSearcher(reader);
                applyRules(a);
                markers(a, searcher);
                detectSpikes(a, ser);
                detectErrorRate(a);
                detectNew(a);
                detectSilence(a, ser);
                detectSilenced(a, presence, ser);
                detectCrashes(a, searcher, ser);
                knownPatterns(a);
            } finally {
                pool.shutdown();
            }
        }
        a.anomalies.sort((x, y) -> y.score != x.score ? Integer.compare(y.score, x.score) : Long.compare(x.from, y.from));
        buildIncidents(a);
        a.analyzeMs = System.currentTimeMillis() - t0;
        Json.write(indexDir.resolve("analysis.json"), a);
        System.out.printf("  analysis: %,d templates -> %,d groups, %d anomalies in %.1f s%n", keys.size(), a.clusters.size(),
                a.anomalies.size(), a.analyzeMs / 1000.0);
        return a;
    }

    private static void fillCluster(Model.Cluster c, List<KeyInfo> keys, ScanLocal g) {
        long best = -1;
        c.first = Long.MAX_VALUE;
        c.last = Long.MIN_VALUE;
        for (int k : c.keys) {
            KeyInfo ki = keys.get(k);
            c.count += g.keyCount[k];
            c.first = Math.min(c.first, g.keyMin[k]);
            c.last = Math.max(c.last, g.keyMax[k]);
            if (g.keyCount[k] > best) {
                best = g.keyCount[k];
                c.level = ki.level;
                c.logger = ki.logger;
                c.code = ki.code;
                c.exOuter = ki.exOuter;
                c.exRoot = ki.exRoot;
                c.exClasses = ki.exClasses;
                c.sample = ki.sample;
                c.rootMessage = ki.rootMessage;
            }
        }
        c.subsystem = Rules.subsystem(c.code, c.logger);
        c.category = c.exRoot != null ? Rules.simpleName(c.exRoot) : "(ohne Exception)";
    }

    private String t(long ts) {
        return fmt.format(Instant.ofEpochMilli(ts));
    }

    private static String label(Model.Cluster c) {
        String s = c.exRoot != null ? Rules.simpleName(c.exRoot) + ": " : "";
        String tpl = c.template.length() > 90 ? c.template.substring(0, 90) + "…" : c.template;
        return s + tpl;
    }

    // ------------------------------------------------------------------------------------ incidents

    /**
     * Groups time-local anomalies (spikes, error rate, new types, silence, crashes) that overlap within a few minutes
     * into incidents. The earliest signal of an incident is the first root-cause candidate.
     */
    private void buildIncidents(Model.Analysis a) {
        Set<String> local = Set.of("spike", "error-rate", "new", "silence", "crash", "start-errors");
        List<Integer> idx = new ArrayList<>();
        for (int i = 0; i < a.anomalies.size(); i++) {
            Model.Anomaly an = a.anomalies.get(i);
            // "new" types that keep occurring for days are not local events; use their first appearance only
            if (local.contains(an.type)) idx.add(i);
        }
        long slack = Math.max(5 * 60_000L, 2 * a.bucketMs);
        idx.sort(Comparator.comparingLong(i -> a.anomalies.get(i).from));
        Model.Incident cur = null;
        long curEnd = Long.MIN_VALUE;
        for (int i : idx) {
            Model.Anomaly an = a.anomalies.get(i);
            long end = an.type.equals("new") ? an.from + slack : an.to;
            if (cur == null || an.from > curEnd + slack) {
                cur = new Model.Incident();
                cur.id = a.incidents.size();
                cur.from = an.from;
                a.incidents.add(cur);
                curEnd = Long.MIN_VALUE;
            }
            cur.anomalies.add(i);
            curEnd = Math.max(curEnd, end);
            cur.to = curEnd;
            for (int c : an.clusters) if (!cur.clusters.contains(c) && cur.clusters.size() < 40) cur.clusters.add(c);
            an.incident = cur.id;
        }
        for (Model.Incident inc : a.incidents) {
            Model.Anomaly top = null, first = null;
            Set<String> types = new LinkedHashSet<>();
            for (int i : inc.anomalies) {
                Model.Anomaly an = a.anomalies.get(i);
                types.add(an.type);
                if (top == null || an.score > top.score) top = an;
                if (first == null || an.from < first.from) first = an;
            }
            // more independent signals = more confidence
            inc.score = (int) Math.min(100, top.score + 2 * (inc.anomalies.size() - 1));
            inc.title = top.title;
            inc.types = new ArrayList<>(types);
            inc.firstSignal = first.title;
            inc.firstSignalTs = first.from;
        }
        a.incidents.sort((x, y) -> Integer.compare(y.score, x.score));
    }

    // ------------------------------------------------------------------------------------ rules

    private void applyRules(Model.Analysis a) {
        for (Model.Cluster c : a.clusters) {
            String hay = Rules.haystack(c);
            for (Rules.Rule r : Rules.RULES) {
                if (r.match().matcher(hay).find()) {
                    // INFO/DEBUG messages only count for the most severe rules (OOM written at INFO is still OOM)
                    if (c.level < Level.WARN && r.severity() < 90) continue;
                    c.rules.add(r.id());
                    c.severity = Math.max(c.severity, r.severity());
                }
            }
            if (c.severity >= 70 && c.level >= Level.WARN) c.flags.add("CRIT");
        }
    }

    private void knownPatterns(Model.Analysis a) {
        for (Rules.Rule r : Rules.RULES) {
            List<Model.Cluster> hits = a.clusters.stream().filter(c -> c.rules.contains(r.id()) && c.level >= Level.WARN).toList();
            if (hits.isEmpty()) continue;
            Model.Anomaly an = new Model.Anomaly();
            an.type = "known";
            an.title = r.title();
            long n = 0;
            an.from = Long.MAX_VALUE;
            an.to = Long.MIN_VALUE;
            for (Model.Cluster c : hits) {
                n += c.count;
                an.from = Math.min(an.from, c.first);
                an.to = Math.max(an.to, c.last);
                if (an.clusters.size() < 30) an.clusters.add(c.id);
            }
            an.score = (int) Math.min(100, r.severity() * (0.6 + 0.1 * Math.min(4, Math.log10(n + 1))));
            an.detail = String.format(Locale.GERMANY, "%,d Ereignisse in %d Gruppe(n), %s – %s. %s", n, hits.size(), t(an.from), t(an.to), r.explanation());
            an.metrics.put("events", n);
            an.metrics.put("rule", r.id());
            an.metrics.put("advice", r.advice());
            an.metrics.put("severity", r.severity());
            a.anomalies.add(an);
        }
    }

    // ------------------------------------------------------------------------------------ markers

    private static final String[][] MARKER_CODES = {
            {"WFLYSRV0049", "start"}, {"WFLYSRV0025", "started"}, {"WFLYSRV0026", "started-errors"}, {"WFLYSRV0050", "stop"},
            {"WFLYSRV0010", "deploy"}, {"WFLYSRV0016", "deploy"}, {"WFLYSRV0009", "undeploy"}, {"WFLYSRV0028", "undeploy"}
    };

    private void markers(Model.Analysis a, IndexSearcher s) throws IOException {
        for (String[] mc : MARKER_CODES) {
            TopDocs td = s.search(new TermQuery(new Term(Fields.CODE, mc[0])), 5000);
            StoredFields sf = s.storedFields();
            for (ScoreDoc sd : td.scoreDocs) {
                Document d = sf.document(sd.doc, Set.of(Fields.TS, Fields.RAW));
                String raw = d.get(Fields.RAW);
                int nl = raw.indexOf('\n');
                String first = nl > 0 ? raw.substring(0, nl) : raw;
                int ci = first.indexOf(mc[0]);
                String text = ci >= 0 ? first.substring(ci) : first;
                if (text.length() > 200) text = text.substring(0, 200);
                a.markers.add(new Model.Marker(mc[1], d.getField(Fields.TS).numericValue().longValue(), text));
            }
        }
        a.markers.sort(Comparator.comparingLong(m -> m.ts));
        // the same event often appears in several files (server.log + console.log): drop duplicates within 60 s
        List<Model.Marker> dedup = new ArrayList<>();
        for (Model.Marker m : a.markers) {
            boolean dup = false;
            for (int i = dedup.size() - 1; i >= 0 && m.ts - dedup.get(i).ts <= 60_000; i--) {
                if (dedup.get(i).type.equals(m.type) && dedup.get(i).text.equals(m.text)) { dup = true; break; }
            }
            if (!dup) dedup.add(m);
        }
        a.markers = dedup;
    }

    // ------------------------------------------------------------------------------------ spikes

    record Episode(int from, int to, long count, double expected, double logp) {}

    /** Spike episodes of series x against volume-proportional baseline. */
    static List<Episode> spikes(int[] x, int[] vol, int minCount) {
        int nb = x.length;
        // trimmed baseline fraction: cap each bucket at the 98th percentile of non-empty-volume buckets
        int active = 0;
        for (int b = 0; b < nb; b++) if (vol[b] > 0) active++;
        if (active < 5) return List.of();
        int[] vals = new int[active];
        int j = 0;
        for (int b = 0; b < nb; b++) if (vol[b] > 0) vals[j++] = x[b];
        Arrays.sort(vals);
        int cap = vals[(int) Math.floor((active - 1) * 0.98)];
        double s = 0, v = 0;
        for (int b = 0; b < nb; b++) {
            if (vol[b] == 0) continue;
            s += Math.min(x[b], cap);
            v += vol[b] - x[b];
        }
        if (v <= 0) return List.of();
        double p = Math.max(s, 0.5) / v;
        List<Episode> eps = new ArrayList<>();
        int eFrom = -1, eTo = -1, gap = 0;
        long eCount = 0;
        double eExp = 0, eLogp = 0;
        for (int b = 0; b <= nb; b++) {
            boolean spike = false;
            double lam = 0, lp = 0;
            if (b < nb && x[b] >= minCount) {
                lam = Math.max(p * Math.max(vol[b] - x[b], 1), 1e-4);
                if (x[b] >= 3 * lam + 3) {
                    lp = Stats.poissonLogSf(x[b], lam);
                    spike = lp < -13.8; // p < 1e-6
                }
            }
            if (spike) {
                if (eFrom < 0) { eFrom = b; eCount = 0; eExp = 0; eLogp = 0; }
                eTo = b;
                eCount += x[b];
                eExp += lam;
                eLogp = Math.min(eLogp, lp);
                gap = 0;
            } else if (eFrom >= 0) {
                if (b < nb && ++gap <= 2) {
                    eCount += x[b];
                    eExp += Math.max(p * Math.max(vol[b] - x[b], 1), 1e-4);
                    continue;
                }
                eps.add(new Episode(eFrom, eTo, eCount, eExp, eLogp));
                eFrom = -1;
                gap = 0;
            }
        }
        return eps;
    }

    private void detectSpikes(Model.Analysis a, int[][] ser) {
        List<Model.Anomaly> all = new ArrayList<>();
        for (Model.Cluster c : a.clusters) {
            int[] x = ser[c.id];
            if (x == null || c.count < 5) continue;
            List<Episode> eps = new ArrayList<>(spikes(x, a.volume, 5));
            eps.sort(Comparator.comparingDouble(Episode::logp));
            int n = 0;
            for (Episode e : eps) {
                if (n++ >= 5) break;
                Model.Anomaly an = new Model.Anomaly();
                an.type = "spike";
                an.from = a.start + e.from * a.bucketMs;
                an.to = a.start + (e.to + 1) * a.bucketMs;
                double sig = Math.min(60, -e.logp / Math.log(10));
                an.score = (int) Math.min(100, 15 + sig * (c.level >= Level.ERROR ? 1.1 : 0.8) + c.severity * 0.15);
                an.title = "Häufung: " + label(c);
                an.detail = String.format(Locale.GERMANY, "%,d× in %s (%s – %s), erwartet ≈ %.1f.", e.count,
                        Stats.fmtDuration(an.to - an.from), t(an.from), t(an.to), e.expected);
                an.clusters.add(c.id);
                an.metrics.put("count", e.count);
                an.metrics.put("expected", Math.round(e.expected * 10) / 10.0);
                all.add(an);
            }
            if (!eps.isEmpty()) c.flags.add("SPIKE");
        }
        all.sort((x, y) -> Integer.compare(y.score, x.score));
        a.anomalies.addAll(all.subList(0, Math.min(250, all.size())));
    }

    private void detectErrorRate(Model.Analysis a) {
        int[] err = a.errors;
        for (Episode e : spikes(err, a.volume, 10)) {
            Model.Anomaly an = new Model.Anomaly();
            an.type = "error-rate";
            an.from = a.start + e.from * a.bucketMs;
            an.to = a.start + (e.to + 1) * a.bucketMs;
            double sig = Math.min(60, -e.logp / Math.log(10));
            an.score = (int) Math.min(100, 30 + sig);
            an.title = "Fehlerrate erhöht";
            an.detail = String.format(Locale.GERMANY, "%,d Fehler in %s (%s – %s), erwartet ≈ %.0f (×%.0f).", e.count,
                    Stats.fmtDuration(an.to - an.from), t(an.from), t(an.to), e.expected, e.count / Math.max(1, e.expected));
            an.metrics.put("count", e.count);
            an.metrics.put("expected", Math.round(e.expected));
            topClustersIn(a, an, e.from, e.to);
            a.anomalies.add(an);
        }
    }

    /** Adds the WARN+ clusters with most events between buckets [from,to] (by time-filtered cluster first/last). */
    private void topClustersIn(Model.Analysis a, Model.Anomaly an, int from, int to) {
        // filled lazily by the UI via correlation; here only a cheap approximation using cluster first/last overlap
        long f = a.start + from * a.bucketMs, t = a.start + (to + 1) * a.bucketMs;
        a.clusters.stream().filter(c -> c.level >= Level.WARN && c.first <= t && c.last >= f)
                .sorted((x, y) -> Long.compare(y.count, x.count)).limit(8).forEach(c -> an.clusters.add(c.id));
    }

    // ------------------------------------------------------------------------------------ new error types

    private void detectNew(Model.Analysis a) {
        long span = a.end - a.start;
        long threshold = a.start + Math.max(span / 10, 3_600_000L);
        List<Model.Marker> deploys = a.markers.stream().filter(m -> m.type.equals("deploy") || m.type.equals("started")).toList();
        for (Model.Cluster c : a.clusters) {
            if (c.level < Level.WARN) continue;
            // new = first seen late in the data, or within 2 h after a (re)deployment that itself was not at the very start
            boolean afterDeploy = false;
            for (Model.Marker m : deploys) {
                if (m.ts - a.start >= 3_600_000L && c.first >= m.ts && c.first - m.ts <= 2 * 3_600_000L) { afterDeploy = true; break; }
            }
            if (c.first < threshold && !afterDeploy) continue;
            Model.Anomaly an = new Model.Anomaly();
            an.type = "new";
            an.from = c.first;
            an.to = c.last;
            Model.Marker after = null;
            for (Model.Marker m : deploys) if (m.ts <= c.first && c.first - m.ts <= 2 * 3_600_000L) after = m;
            an.score = (int) Math.min(100, 30 + (c.level >= Level.ERROR ? 15 : 0) + 8 * Math.log10(c.count + 1) + c.severity * 0.2
                    + (after != null ? 15 : 0));
            an.title = "Neue Fehlerart: " + label(c);
            an.detail = String.format(Locale.GERMANY, "Erstmals %s, seitdem %,d×%s.", t(c.first), c.count,
                    after != null ? " – " + Stats.fmtDuration(c.first - after.ts) + " nach „" + after.text + "“" : "");
            an.clusters.add(c.id);
            an.metrics.put("count", c.count);
            c.flags.add("NEW");
            a.anomalies.add(an);
        }
    }

    // ------------------------------------------------------------------------------------ silence / gaps

    private void detectSilence(Model.Analysis a, int[][] ser) {
        int[] v = a.volume;
        int nb = v.length;
        int b = 0;
        while (b < nb) {
            if (v[b] != 0) { b++; continue; }
            int s = b;
            while (b < nb && v[b] == 0) b++;
            int e = b - 1;
            if (s == 0 || b >= nb) continue;
            long dur = (e - s + 1) * a.bucketMs;
            if (dur < 120_000) continue;
            // expected volume from the neighbourhood (median of 30 non-empty buckets on each side)
            List<Integer> nbh = new ArrayList<>();
            for (int k = s - 1; k >= 0 && nbh.size() < 30; k--) if (v[k] > 0) nbh.add(v[k]);
            int right = 0;
            for (int k = e + 1; k < nb && right < 30; k++) if (v[k] > 0) { nbh.add(v[k]); right++; }
            if (nbh.isEmpty()) continue;
            Collections.sort(nbh);
            double expected = nbh.get(nbh.size() / 2) * (double) (e - s + 1);
            if (expected < 50) continue;
            Model.Anomaly an = new Model.Anomaly();
            an.type = "silence";
            an.from = a.start + s * a.bucketMs;
            an.to = a.start + (e + 1) * a.bucketMs;
            an.score = (int) Math.min(95, 40 + 10 * Math.log10(expected) + Math.min(15, dur / 600_000.0 * 5));
            an.title = "Log-Stille: " + Stats.fmtDuration(dur) + " ohne Einträge";
            an.detail = String.format(Locale.GERMANY, "%s – %s keine Log-Einträge, erwartet ≈ %,.0f. Hinweis auf Hänger, GC-Pause, Absturz oder fehlende Logdatei.",
                    t(an.from), t(an.to), expected);
            an.metrics.put("expected", Math.round(expected));
            // WARN+ clusters right after the gap
            int after = e + 1;
            List<int[]> cand = new ArrayList<>();
            for (Model.Cluster c : a.clusters) {
                int[] x = ser[c.id];
                if (x == null) continue;
                int n = 0;
                for (int k = after; k < Math.min(nb, after + 5); k++) n += x[k];
                if (n > 0) cand.add(new int[]{c.id, n});
            }
            cand.sort((p, q) -> Integer.compare(q[1], p[1]));
            for (int i = 0; i < Math.min(8, cand.size()); i++) an.clusters.add(cand.get(i)[0]);
            a.anomalies.add(an);
        }
    }

    /** Regular messages (jobs, heartbeats) that stop long before the end of the data. */
    private void detectSilenced(Model.Analysis a, AtomicLongArray[] presence, int[][] ser) {
        int nb = a.volume.length;
        int lastActive = nb - 1;
        while (lastActive > 0 && a.volume[lastActive] == 0) lastActive--;
        for (Model.Cluster c : a.clusters) {
            // errors that stop are good news; this detector is about regular jobs / heartbeats going quiet
            if (c.count < 20 || c.level > Level.INFO) continue;
            int fb = (int) ((c.first - a.start) / a.bucketMs), lb = (int) ((c.last - a.start) / a.bucketMs);
            if (lb <= fb) continue;
            // must have been active over a long stretch, otherwise it is a burst, not a regular job
            if (c.last - c.first < Math.max(2 * 3_600_000L, (a.end - a.start) * 15 / 100)) continue;
            int present = 0;
            for (int b = fb; b <= lb; b++) {
                boolean on = ser[c.id] != null ? ser[c.id][b] > 0 : presence[c.id] != null && (presence[c.id].get(b >>> 6) & (1L << (b & 63))) != 0;
                if (on) present++;
            }
            int range = lb - fb + 1;
            double interval = (double) (c.last - c.first) / (c.count - 1);
            boolean regular = present >= 0.5 * Math.min(range, c.count);
            if (!regular) continue;
            long silentFor = a.end - c.last;
            if (silentFor < Math.max(20 * interval, Math.max(60 * 60_000L, 5 * a.bucketMs))) continue;
            // data must continue: > 50% of buckets after last occurrence have volume
            int withData = 0;
            for (int b = lb + 1; b <= lastActive; b++) if (a.volume[b] > 0) withData++;
            if (withData < 0.5 * Math.max(1, lastActive - lb)) continue;
            Model.Anomaly an = new Model.Anomaly();
            an.type = "silenced";
            an.from = c.last;
            an.to = a.end;
            an.score = (int) Math.min(90, 40 + 8 * Math.log10(c.count));
            an.title = "Verstummt: " + label(c);
            an.detail = String.format(Locale.GERMANY, "Kam regelmäßig (≈ alle %s, %,d×), zuletzt %s – seitdem %s nicht mehr, obwohl weiter geloggt wird.",
                    Stats.fmtDuration((long) interval), c.count, t(c.last), Stats.fmtDuration(silentFor));
            an.clusters.add(c.id);
            c.flags.add("SILENT");
            a.anomalies.add(an);
        }
    }

    // ------------------------------------------------------------------------------------ restarts

    private void detectCrashes(Model.Analysis a, IndexSearcher s, int[][] ser) throws IOException {
        long prevStart = Long.MIN_VALUE;
        boolean stopped = false;
        for (Model.Marker m : a.markers) {
            switch (m.type) {
                case "stop" -> stopped = true;
                case "started-errors" -> {
                    Model.Anomaly an = new Model.Anomaly();
                    an.type = "start-errors";
                    an.from = m.ts - 60_000;
                    an.to = m.ts;
                    an.score = 70;
                    an.title = "Server mit Fehlern gestartet";
                    an.detail = t(m.ts) + ": " + m.text;
                    a.anomalies.add(an);
                }
                case "start" -> {
                    if (prevStart != Long.MIN_VALUE || m.ts - a.start > 5 * 60_000L) {
                        if (!stopped) {
                            // last event before this start
                            Query q = LongPoint.newRangeQuery(Fields.TS, Long.MIN_VALUE, m.ts - 1);
                            TopDocs td = s.search(q, 1, new Sort(new SortField(Fields.TS, SortField.Type.LONG, true)));
                            long lastBefore = m.ts;
                            if (td.scoreDocs.length > 0) lastBefore = (Long) ((FieldDoc) td.scoreDocs[0]).fields[0];
                            if (lastBefore < m.ts) {
                                Model.Anomaly an = new Model.Anomaly();
                                an.type = "crash";
                                an.from = lastBefore;
                                an.to = m.ts;
                                an.score = 92;
                                an.title = "Ungeplanter Neustart (kein sauberes Herunterfahren)";
                                an.detail = String.format(Locale.GERMANY, "Letzter Eintrag %s, Neustart %s (%s Pause) ohne vorheriges WFLYSRV0050 „stopped“ – Absturz/Kill wahrscheinlich.",
                                        t(lastBefore), t(m.ts), Stats.fmtDuration(m.ts - lastBefore));
                                // WARN+ clusters in the 15 minutes before the last event
                                int lb = (int) ((lastBefore - a.start) / a.bucketMs);
                                int fb = Math.max(0, lb - (int) Math.max(1, 15 * 60_000L / a.bucketMs));
                                List<long[]> cand = new ArrayList<>();
                                for (Model.Cluster c : a.clusters) {
                                    int[] x = ser[c.id];
                                    if (x == null) continue;
                                    long n = 0;
                                    for (int b = fb; b <= Math.min(lb, x.length - 1); b++) n += x[b];
                                    if (n > 0) cand.add(new long[]{c.id, n + c.severity * 1000L});
                                }
                                cand.sort((p, q2) -> Long.compare(q2[1], p[1]));
                                for (int i = 0; i < Math.min(8, cand.size()); i++) an.clusters.add((int) cand.get(i)[0]);
                                a.anomalies.add(an);
                            }
                        }
                    }
                    prevStart = m.ts;
                    stopped = false;
                }
                default -> { }
            }
        }
    }
}
