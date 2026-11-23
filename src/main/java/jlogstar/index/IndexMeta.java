package jlogstar.index;

import jlogstar.ingest.LogFile;

import java.util.List;

/** Persisted description of an index (meta.json). */
public final class IndexMeta {
    public int version = 1;
    public String zone;
    public long created;
    public long ingestMs;
    public long inputBytes;
    public long rawBytes;
    public long events;
    public long minTs = Long.MAX_VALUE;
    public long maxTs = Long.MIN_VALUE;
    public int keys;
    public List<LogFile> files;
}
