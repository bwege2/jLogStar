package jlogstar.query;

import jlogstar.Json;
import jlogstar.analyze.Model;
import jlogstar.index.IndexMeta;
import jlogstar.ingest.KeyInfo;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.store.FSDirectory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Everything needed to answer queries: Lucene searcher plus meta, key dictionary and analysis. */
public final class Dataset implements AutoCloseable {
    public final IndexMeta meta;
    public final KeyInfo[] keys;
    public final Model.Analysis analysis;
    public final DirectoryReader reader;
    public final IndexSearcher searcher;
    public final ExecutorService pool;
    public final Map<Integer, Model.Cluster> clusters = new HashMap<>();
    /** anomaly flags per cluster for quick lookup */
    public final int[] keyToCluster;

    public Dataset(Path dir, int threads) throws IOException {
        meta = Json.read(dir.resolve("meta.json"), IndexMeta.class);
        keys = Json.read(dir.resolve("keys.json"), KeyInfo[].class);
        analysis = Json.read(dir.resolve("analysis.json"), Model.Analysis.class);
        for (Model.Cluster c : analysis.clusters) clusters.put(c.id, c);
        keyToCluster = analysis.keyToCluster;
        reader = DirectoryReader.open(FSDirectory.open(dir.resolve("lucene")));
        pool = Executors.newFixedThreadPool(threads);
        searcher = new IndexSearcher(reader, pool);
    }

    public int clusterOfKey(int k) {
        return k >= 0 && k < keyToCluster.length ? keyToCluster[k] : -1;
    }

    @Override
    public void close() throws IOException {
        reader.close();
        pool.shutdown();
    }
}
