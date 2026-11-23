package jlogstar.query;

import jlogstar.analyze.Model;
import jlogstar.analyze.Rules;
import jlogstar.analyze.Stats;
import jlogstar.index.Fields;
import jlogstar.ingest.KeyInfo;
import jlogstar.ingest.Level;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.IntPoint;
import org.apache.lucene.document.LongPoint;
import org.apache.lucene.index.*;
import org.apache.lucene.search.*;

import java.io.IOException;
import java.util.*;

/** Answers all UI queries. Results are plain maps/lists serialised to JSON by the web layer. */
public final class SearchService {
    private final Dataset ds;
    private final QueryBuilder qb;

    public SearchService(Dataset ds) {
        this.ds = ds;
        this.qb = new QueryBuilder(ds);
    }

    public QueryBuilder queries() {
        return qb;
    }

    record Range(long start, long end, long bucket, int nb) {}

    private Range range(QueryBuilder.Filter f, int targetBuckets) {
        long from = f.from != null ? f.from : ds.meta.minTs;
        long to = f.to != null ? f.to : ds.meta.maxTs + 1;
        if (to <= from) to = from + 1000;
        long bucket = Stats.niceBucket(to - from, targetBuckets);
        long start = Math.floorDiv(from, bucket) * bucket;
        int nb = (int) Math.max(1, (to - start + bucket - 1) / bucket);
        return new Range(start, to, bucket, nb);
    }

    private AggCollector aggregate(Query q, Range r) throws IOException {
        return ds.searcher.search(q, AggCollector.manager(r.start, r.bucket, r.nb, ds.keys.length));
    }

    // ------------------------------------------------------------------------------------ info

    public Map<String, Object> info() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("events", ds.meta.events);
        m.put("minTs", ds.meta.minTs);
        m.put("maxTs", ds.meta.maxTs);
        m.put("zone", ds.meta.zone);
        m.put("inputBytes", ds.meta.inputBytes);
        m.put("ingestMs", ds.meta.ingestMs);
        m.put("keys", ds.meta.keys);
        m.put("groups", ds.analysis.clusters.size());
        m.put("anomalies", ds.analysis.anomalies.size());
        List<Map<String, Object>> files = new ArrayList<>();
        for (var f : ds.meta.files) {
            Map<String, Object> fm = new LinkedHashMap<>();
            fm.put("id", f.id);
            fm.put("path", f.path);
            fm.put("size", f.size);
            fm.put("layout", f.layout);
            fm.put("events", f.events);
            fm.put("minTs", f.events > 0 ? f.minTs : null);
            fm.put("maxTs", f.events > 0 ? f.maxTs : null);
            fm.put("skipped", f.skipped);
            files.add(fm);
        }
        m.put("files", files);
        List<Map<String, Object>> rules = new ArrayList<>();
        for (Rules.Rule r : Rules.RULES) rules.add(Map.of("id", r.id(), "title", r.title(), "severity", r.severity(),
                "explanation", r.explanation(), "advice", r.advice()));
        m.put("rules", rules);
        return m;
    }

    // ------------------------------------------------------------------------------------ overview

    public Map<String, Object> overview(QueryBuilder.Filter f) throws Exception {
        long t0 = System.nanoTime();
        Range r = range(f, 180);
        Query q = qb.build(f);
        AggCollector agg = aggregate(q, r);

        // roll keys up to clusters
        Map<Integer, long[]> cstat = new HashMap<>(); // count, min, max
        Map<Integer, int[]> cser = new HashMap<>();
        for (int k = 0; k < agg.nk; k++) {
            if (agg.keyCount[k] == 0) continue;
            int c = ds.clusterOfKey(k);
            if (c < 0) continue;
            long[] s = cstat.computeIfAbsent(c, x -> new long[]{0, Long.MAX_VALUE, Long.MIN_VALUE});
            s[0] += agg.keyCount[k];
            s[1] = Math.min(s[1], agg.keyMin[k]);
            s[2] = Math.max(s[2], agg.keyMax[k]);
            int[] ser = cser.get(c);
            if (ser == null) cser.put(c, agg.keySeries[k].clone());
            else for (int b = 0; b < r.nb; b++) ser[b] += agg.keySeries[k][b];
        }
        List<Integer> ids = new ArrayList<>(cstat.keySet());
        ids.sort((a, b) -> {
            Model.Cluster ca = ds.clusters.get(a), cb = ds.clusters.get(b);
            int la = ca.level >= Level.WARN ? 1 : 0, lb = cb.level >= Level.WARN ? 1 : 0;
            if (la != lb) return lb - la;
            return Long.compare(cstat.get(b)[0], cstat.get(a)[0]);
        });
        List<Map<String, Object>> groups = new ArrayList<>();
        int warnPlus = 0, others = 0;
        long newInRange = 0;
        int errGroups = 0;
        for (int id : ids) {
            Model.Cluster c = ds.clusters.get(id);
            boolean wp = c.level >= Level.WARN;
            if (wp) {
                errGroups++;
                if (c.flags.contains("NEW")) newInRange++;
                if (warnPlus++ >= 600) continue;
            } else if (others++ >= 150) continue;
            long[] s = cstat.get(id);
            Map<String, Object> g = clusterJson(c);
            g.put("count", s[0]);
            g.put("first", s[1]);
            g.put("last", s[2]);
            g.put("series", cser.get(id));
            groups.add(g);
        }

        // categories (WARN+): subsystem -> exception category
        Map<String, Map<String, long[]>> cats = new TreeMap<>();
        for (int id : ids) {
            Model.Cluster c = ds.clusters.get(id);
            if (c.level < Level.WARN) continue;
            cats.computeIfAbsent(c.subsystem, x -> new TreeMap<>()).computeIfAbsent(c.category, x -> new long[1])[0] += cstat.get(id)[0];
        }
        List<Map<String, Object>> catJson = new ArrayList<>();
        for (var e : cats.entrySet()) {
            List<Map<String, Object>> ch = new ArrayList<>();
            long sum = 0;
            for (var e2 : e.getValue().entrySet()) {
                ch.add(Map.of("name", e2.getKey(), "value", e2.getValue()[0]));
                sum += e2.getValue()[0];
            }
            catJson.add(Map.of("name", e.getKey(), "value", sum, "children", ch));
        }

        long[] levelTotals = new long[Level.COUNT];
        for (int l = 0; l < Level.COUNT; l++) for (int b = 0; b < r.nb; b++) levelTotals[l] += agg.hist[l][b];

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("start", r.start);
        out.put("end", r.end);
        out.put("bucketMs", r.bucket);
        out.put("total", agg.total);
        out.put("levels", Level.NAMES);
        out.put("levelTotals", levelTotals);
        out.put("hist", agg.hist);
        out.put("groups", groups);
        out.put("groupCount", ids.size());
        out.put("errorGroupCount", errGroups);
        out.put("newGroupCount", newInRange);
        out.put("categories", catJson);
        long from = r.start, to = r.end;
        out.put("markers", ds.analysis.markers.stream().filter(m -> m.ts >= from && m.ts <= to).toList());
        List<Model.Anomaly> an = ds.analysis.anomalies.stream().filter(a -> a.to >= from && a.from <= to).toList();
        out.put("anomalyCount", an.size());
        out.put("anomalies", an.subList(0, Math.min(an.size(), 300)));
        out.put("incidents", incidents(from, to));
        out.put("tookMs", (System.nanoTime() - t0) / 1_000_000);
        return out;
    }

    /** Incidents overlapping [from,to] with their anomalies embedded. */
    public List<Map<String, Object>> incidents(long from, long to) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Model.Incident inc : ds.analysis.incidents) {
            if (inc.to < from || inc.from > to) continue;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", inc.id);
            m.put("score", inc.score);
            m.put("title", inc.title);
            m.put("from", inc.from);
            m.put("to", inc.to);
            m.put("types", inc.types);
            m.put("clusters", inc.clusters);
            m.put("firstSignal", inc.firstSignal);
            m.put("firstSignalTs", inc.firstSignalTs);
            List<Model.Anomaly> list = new ArrayList<>();
            for (int i : inc.anomalies) list.add(ds.analysis.anomalies.get(i));
            list.sort(Comparator.comparingLong(x -> x.from));
            m.put("anomalies", list);
            out.add(m);
        }
        return out;
    }

    public Map<String, Object> clusterJson(Model.Cluster c) {
        Map<String, Object> g = new LinkedHashMap<>();
        g.put("id", c.id);
        g.put("level", Level.name(c.level));
        g.put("template", c.template);
        g.put("logger", c.logger);
        g.put("code", c.code);
        g.put("exOuter", c.exOuter);
        g.put("exRoot", c.exRoot);
        g.put("subsystem", c.subsystem);
        g.put("category", c.category);
        g.put("severity", c.severity);
        g.put("rules", c.rules);
        g.put("flags", c.flags);
        g.put("totalCount", c.count);
        g.put("totalFirst", c.first);
        g.put("totalLast", c.last);
        return g;
    }

    // ------------------------------------------------------------------------------------ events

    public Map<String, Object> events(QueryBuilder.Filter f, boolean asc, String cursor, int limit) throws Exception {
        long t0 = System.nanoTime();
        Query q = qb.build(f);
        Sort sort = new Sort(new SortField(Fields.TS, SortField.Type.LONG, !asc), new SortField(Fields.OFF, SortField.Type.LONG, !asc));
        TopDocs td;
        limit = Math.max(1, Math.min(limit, 500));
        if (cursor != null && !cursor.isBlank()) {
            String[] p = cursor.split(":");
            FieldDoc after = new FieldDoc(Integer.parseInt(p[2]), Float.NaN, new Object[]{Long.parseLong(p[0]), Long.parseLong(p[1])});
            td = ds.searcher.searchAfter(after, q, limit, sort);
        } else td = ds.searcher.search(q, limit, sort);
        List<Map<String, Object>> evs = new ArrayList<>();
        StoredFields sf = ds.searcher.storedFields();
        String next = null;
        for (ScoreDoc sd : td.scoreDocs) {
            evs.add(event(sf, sd.doc));
            FieldDoc fd = (FieldDoc) sd;
            next = fd.fields[0] + ":" + fd.fields[1] + ":" + sd.doc;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("total", td.totalHits.value());
        out.put("totalExact", td.totalHits.relation() == TotalHits.Relation.EQUAL_TO);
        out.put("events", evs);
        out.put("cursor", evs.size() == limit ? next : null);
        out.put("tookMs", (System.nanoTime() - t0) / 1_000_000);
        return out;
    }

    private static final Set<String> STORED = Set.of(Fields.TS, Fields.KEY, Fields.FILE, Fields.OFF, Fields.RAW, Fields.LOGGER, Fields.THREAD);

    Map<String, Object> event(StoredFields sf, int doc) throws IOException {
        Document d = sf.document(doc, STORED);
        Map<String, Object> e = new LinkedHashMap<>();
        int k = d.getField(Fields.KEY).numericValue().intValue();
        KeyInfo ki = k < ds.keys.length ? ds.keys[k] : null;
        e.put("doc", doc);
        e.put("ts", d.getField(Fields.TS).numericValue().longValue());
        e.put("level", ki == null ? "INFO" : Level.name(ki.level));
        e.put("logger", d.get(Fields.LOGGER));
        e.put("thread", d.get(Fields.THREAD));
        e.put("group", ds.clusterOfKey(k));
        e.put("file", d.getField(Fields.FILE).numericValue().intValue());
        e.put("off", d.getField(Fields.OFF).numericValue().longValue());
        e.put("text", d.get(Fields.RAW));
        return e;
    }

    public Map<String, Object> context(int doc, int n) throws Exception {
        StoredFields sf = ds.searcher.storedFields();
        Document d = sf.document(doc, Set.of(Fields.FILE, Fields.OFF));
        int file = d.getField(Fields.FILE).numericValue().intValue();
        long off = d.getField(Fields.OFF).numericValue().longValue();
        n = Math.max(1, Math.min(n, 200));
        Query before = new BooleanQuery.Builder()
                .add(IntPoint.newExactQuery(Fields.FILE, file), BooleanClause.Occur.FILTER)
                .add(LongPoint.newRangeQuery(Fields.OFF, Long.MIN_VALUE, off - 1), BooleanClause.Occur.FILTER).build();
        Query after = new BooleanQuery.Builder()
                .add(IntPoint.newExactQuery(Fields.FILE, file), BooleanClause.Occur.FILTER)
                .add(LongPoint.newRangeQuery(Fields.OFF, off + 1, Long.MAX_VALUE), BooleanClause.Occur.FILTER).build();
        TopDocs tb = ds.searcher.search(before, n, new Sort(new SortField(Fields.OFF, SortField.Type.LONG, true)));
        TopDocs ta = ds.searcher.search(after, n, new Sort(new SortField(Fields.OFF, SortField.Type.LONG)));
        List<Map<String, Object>> evs = new ArrayList<>();
        for (int i = tb.scoreDocs.length - 1; i >= 0; i--) evs.add(event(sf, tb.scoreDocs[i].doc));
        Map<String, Object> self = event(sf, doc);
        self.put("focus", true);
        evs.add(self);
        for (ScoreDoc s : ta.scoreDocs) evs.add(event(sf, s.doc));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("file", ds.meta.files.get(file).path);
        out.put("events", evs);
        return out;
    }

    // ------------------------------------------------------------------------------------ group detail

    public Map<String, Object> group(int id, QueryBuilder.Filter f) throws Exception {
        Model.Cluster c = ds.clusters.get(id);
        if (c == null) throw new NoSuchElementException("Gruppe " + id);
        QueryBuilder.Filter gf = new QueryBuilder.Filter();
        gf.from = f.from;
        gf.to = f.to;
        gf.groups.add(id);
        Query q = qb.build(gf);
        Range r = range(gf, 180);
        AggCollector agg = aggregate(q, r);
        int[] series = new int[r.nb];
        List<Map<String, Object>> variants = new ArrayList<>();
        for (int k : c.keys) {
            if (agg.keySeries[k] != null) for (int b = 0; b < r.nb; b++) series[b] += agg.keySeries[k][b];
            if (agg.keyCount[k] > 0) variants.add(new LinkedHashMap<>(Map.of("key", k, "count", agg.keyCount[k],
                    "sample", ds.keys[k].sample == null ? "" : ds.keys[k].sample, "template", ds.keys[k].template)));
        }
        variants.sort((a, b) -> Long.compare((Long) b.get("count"), (Long) a.get("count")));
        Facets fc = ds.searcher.search(q, Facets.manager());
        Map<String, Object> out = clusterJson(c);
        out.put("sample", c.sample);
        out.put("rootMessage", c.rootMessage);
        out.put("start", r.start);
        out.put("end", r.end);
        out.put("bucketMs", r.bucket);
        out.put("series", series);
        out.put("count", agg.total);
        out.put("threads", fc.top(fc.threads, 15));
        out.put("loggers", fc.top(fc.loggers, 10));
        Map<String, Long> files = new LinkedHashMap<>();
        fc.files.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue(), a.getValue())).limit(10)
                .forEach(e -> files.put(ds.meta.files.get(e.getKey()).path, e.getValue()));
        out.put("files", files);
        out.put("variants", variants.subList(0, Math.min(15, variants.size())));
        List<Map<String, Object>> rules = new ArrayList<>();
        for (Rules.Rule rr : Rules.RULES) if (c.rules.contains(rr.id())) rules.add(Map.of("id", rr.id(), "title", rr.title(),
                "severity", rr.severity(), "explanation", rr.explanation(), "advice", rr.advice()));
        out.put("ruleDetails", rules);
        // only anomalies whose subject is this group (silence/crash/error-rate merely list groups active nearby)
        out.put("anomalies", ds.analysis.anomalies.stream()
                .filter(a -> a.clusters.contains(id) && Set.of("spike", "new", "silenced", "known").contains(a.type)).limit(20).toList());
        // first and most recent occurrence
        StoredFields sf = ds.searcher.storedFields();
        TopDocs first = ds.searcher.search(q, 1, new Sort(new SortField(Fields.TS, SortField.Type.LONG)));
        TopDocs last = ds.searcher.search(q, 1, new Sort(new SortField(Fields.TS, SortField.Type.LONG, true)));
        if (first.scoreDocs.length > 0) out.put("firstEvent", event(sf, first.scoreDocs[0].doc));
        if (last.scoreDocs.length > 0) out.put("lastEvent", event(sf, last.scoreDocs[0].doc));
        return out;
    }

    /** Facet counts for thread, logger and file. */
    static final class Facets implements Collector {
        final Map<String, Long> threads = new HashMap<>(), loggers = new HashMap<>();
        final Map<Integer, Long> files = new HashMap<>();

        @Override
        public LeafCollector getLeafCollector(LeafReaderContext ctx) throws IOException {
            SortedDocValues th = DocValues.getSorted(ctx.reader(), Fields.THREAD);
            SortedDocValues lg = DocValues.getSorted(ctx.reader(), Fields.LOGGER);
            NumericDocValues fi = DocValues.getNumeric(ctx.reader(), Fields.FILE);
            Map<Integer, long[]> thOrd = new HashMap<>(), lgOrd = new HashMap<>();
            return new LeafCollector() {
                @Override public void setScorer(Scorable s) { }

                @Override
                public void collect(int doc) throws IOException {
                    if (th.advanceExact(doc)) thOrd.computeIfAbsent(th.ordValue(), x -> new long[1])[0]++;
                    if (lg.advanceExact(doc)) lgOrd.computeIfAbsent(lg.ordValue(), x -> new long[1])[0]++;
                    if (fi.advanceExact(doc)) files.merge((int) fi.longValue(), 1L, Long::sum);
                }

                @Override
                public void finish() throws IOException {
                    for (var e : thOrd.entrySet()) threads.merge(th.lookupOrd(e.getKey()).utf8ToString(), e.getValue()[0], Long::sum);
                    for (var e : lgOrd.entrySet()) loggers.merge(lg.lookupOrd(e.getKey()).utf8ToString(), e.getValue()[0], Long::sum);
                }
            };
        }

        @Override
        public ScoreMode scoreMode() {
            return ScoreMode.COMPLETE_NO_SCORES;
        }

        Map<String, Long> top(Map<String, Long> m, int n) {
            Map<String, Long> out = new LinkedHashMap<>();
            m.entrySet().stream().sorted((a, b) -> Long.compare(b.getValue(), a.getValue())).limit(n).forEach(e -> out.put(e.getKey(), e.getValue()));
            return out;
        }

        static CollectorManager<Facets, Facets> manager() {
            return new CollectorManager<>() {
                @Override public Facets newCollector() { return new Facets(); }

                @Override
                public Facets reduce(Collection<Facets> cs) {
                    Facets r = new Facets();
                    for (Facets f : cs) {
                        f.threads.forEach((k, v) -> r.threads.merge(k, v, Long::sum));
                        f.loggers.forEach((k, v) -> r.loggers.merge(k, v, Long::sum));
                        f.files.forEach((k, v) -> r.files.merge(k, v, Long::sum));
                    }
                    return r;
                }
            };
        }
    }

    // ------------------------------------------------------------------------------------ correlation

    /**
     * Root-cause candidates for a window: groups over-represented in [from - lead, to] compared to their average rate,
     * ordered by first occurrence inside the window.
     */
    public Map<String, Object> correlate(long from, long to, long lead) throws Exception {
        long wFrom = from - lead;
        QueryBuilder.Filter f = new QueryBuilder.Filter();
        f.from = wFrom;
        f.to = to;
        Range r = range(f, 120);
        AggCollector agg = aggregate(qb.build(f), r);
        Map<Integer, long[]> cs = new HashMap<>(); // count, first
        for (int k = 0; k < agg.nk; k++) {
            if (agg.keyCount[k] == 0) continue;
            int c = ds.clusterOfKey(k);
            if (c < 0) continue;
            long[] s = cs.computeIfAbsent(c, x -> new long[]{0, Long.MAX_VALUE});
            s[0] += agg.keyCount[k];
            s[1] = Math.min(s[1], agg.keyMin[k]);
        }
        double span = Math.max(1, ds.meta.maxTs - ds.meta.minTs);
        double wl = Math.max(1, to - wFrom);
        List<Map<String, Object>> cand = new ArrayList<>();
        for (var e : cs.entrySet()) {
            Model.Cluster c = ds.clusters.get(e.getKey());
            long n = e.getValue()[0];
            double expected = c.count * wl / span;
            double lift = (n + 1) / (expected + 1);
            if (n < 3 || lift < 3) continue;
            Map<String, Object> g = clusterJson(c);
            g.put("count", n);
            g.put("expected", Math.round(expected * 10) / 10.0);
            g.put("lift", Math.round(lift * 10) / 10.0);
            g.put("firstInWindow", e.getValue()[1]);
            g.put("before", e.getValue()[1] < from);
            double score = Math.log10(lift) * 20 + (c.level >= Level.ERROR ? 15 : c.level == Level.WARN ? 8 : 0) + c.severity * 0.2;
            g.put("score", Math.round(score));
            cand.add(g);
        }
        cand.sort((a, b) -> Long.compare((Long) b.get("score"), (Long) a.get("score")));
        List<Map<String, Object>> top = new ArrayList<>(cand.subList(0, Math.min(40, cand.size())));
        top.sort(Comparator.comparingLong(g -> (Long) g.get("firstInWindow")));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("from", from);
        out.put("to", to);
        out.put("windowFrom", wFrom);
        out.put("candidates", top);
        return out;
    }
}
