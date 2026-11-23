package logstar.query;

import logstar.index.Fields;
import logstar.ingest.Level;
import org.apache.lucene.index.DocValues;
import org.apache.lucene.index.LeafReaderContext;
import org.apache.lucene.index.NumericDocValues;
import org.apache.lucene.search.*;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

/**
 * One-pass aggregation over all matching documents, segment-parallel: time histogram per level and per-key
 * count / first / last / time series. Everything shown in the overview is derived from this.
 */
public final class AggCollector implements Collector {
    final long start, bucketMs;
    final int nb, nk;
    final int[][] hist;      // [level][bucket]
    final long[] keyCount, keyMin, keyMax;
    final int[][] keySeries; // lazily per key
    long total;

    AggCollector(long start, long bucketMs, int nb, int nk) {
        this.start = start;
        this.bucketMs = bucketMs;
        this.nb = nb;
        this.nk = nk;
        hist = new int[Level.COUNT][nb];
        keyCount = new long[nk];
        keyMin = new long[nk];
        keyMax = new long[nk];
        keySeries = new int[nk][];
        Arrays.fill(keyMin, Long.MAX_VALUE);
        Arrays.fill(keyMax, Long.MIN_VALUE);
    }

    @Override
    public LeafCollector getLeafCollector(LeafReaderContext ctx) throws IOException {
        NumericDocValues ts = DocValues.getNumeric(ctx.reader(), Fields.TS);
        NumericDocValues kv = DocValues.getNumeric(ctx.reader(), Fields.KEY);
        NumericDocValues lv = DocValues.getNumeric(ctx.reader(), Fields.LVL);
        return new LeafCollector() {
            @Override public void setScorer(Scorable scorer) { }

            @Override
            public void collect(int doc) throws IOException {
                if (!ts.advanceExact(doc)) return;
                long t = ts.longValue();
                int level = lv.advanceExact(doc) ? (int) lv.longValue() : Level.INFO;
                int b = (int) Math.floorDiv(t - start, bucketMs);
                if (b < 0) b = 0; else if (b >= nb) b = nb - 1;
                hist[level][b]++;
                total++;
                if (kv.advanceExact(doc)) {
                    int k = (int) kv.longValue();
                    if (k >= nk) return;
                    keyCount[k]++;
                    if (t < keyMin[k]) keyMin[k] = t;
                    if (t > keyMax[k]) keyMax[k] = t;
                    int[] s = keySeries[k];
                    if (s == null) keySeries[k] = s = new int[nb];
                    s[b]++;
                }
            }
        };
    }

    @Override
    public ScoreMode scoreMode() {
        return ScoreMode.COMPLETE_NO_SCORES;
    }

    void merge(AggCollector o) {
        total += o.total;
        for (int l = 0; l < Level.COUNT; l++) for (int b = 0; b < nb; b++) hist[l][b] += o.hist[l][b];
        for (int k = 0; k < nk; k++) {
            if (o.keyCount[k] == 0) continue;
            keyCount[k] += o.keyCount[k];
            keyMin[k] = Math.min(keyMin[k], o.keyMin[k]);
            keyMax[k] = Math.max(keyMax[k], o.keyMax[k]);
            if (keySeries[k] == null) keySeries[k] = o.keySeries[k];
            else for (int b = 0; b < nb; b++) keySeries[k][b] += o.keySeries[k][b];
        }
    }

    static CollectorManager<AggCollector, AggCollector> manager(long start, long bucketMs, int nb, int nk) {
        return new CollectorManager<>() {
            @Override
            public AggCollector newCollector() {
                return new AggCollector(start, bucketMs, nb, nk);
            }

            @Override
            public AggCollector reduce(Collection<AggCollector> cs) {
                AggCollector r = null;
                for (AggCollector c : cs) {
                    if (r == null) r = c; else r.merge(c);
                }
                return r == null ? new AggCollector(start, bucketMs, nb, nk) : r;
            }
        };
    }
}
