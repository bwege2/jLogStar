package jlogstar.ingest;

/** A parsed (possibly multi-line) log event before it is turned into an index document. Reused per worker. */
public final class RawEvent {
    public long ts;
    public int level = Level.INFO;
    public String logger = "";
    public String thread = "";
    /** First line of the message (after the layout prefix). */
    public String message = "";
    /** Complete rendered event text: header line plus continuation lines (stack traces). */
    public final StringBuilder text = new StringBuilder(256);
    /** Index into text where the continuation (body) starts; == text.length() for single-line events. */
    public int bodyStart;
    public int fileId;
    public long offset;
    public int lines;
    public boolean truncated;

    public void reset() {
        ts = 0; level = Level.INFO; logger = ""; thread = ""; message = "";
        text.setLength(0); bodyStart = 0; fileId = 0; offset = 0; lines = 0; truncated = false;
    }
}
