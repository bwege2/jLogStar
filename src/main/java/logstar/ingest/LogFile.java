package logstar.ingest;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipFile;

/** One input log (a plain file, a .gz file, or an entry inside a .zip). */
public final class LogFile {
    public int id;
    public String path;          // display path
    public transient Path file;  // physical file
    public String zipEntry;      // non-null for zip entries
    public boolean gzip;
    public long size;            // physical (compressed) bytes
    public long mtime;
    public String layout;
    public boolean timeOnly;
    public boolean json;
    public long baseDay;         // for time-only formats: epoch day of the first event
    public long events;
    public long minTs = Long.MAX_VALUE, maxTs = Long.MIN_VALUE;
    public String skipped;       // reason when not indexed

    public boolean splittable() {
        return !gzip && zipEntry == null && !timeOnly;
    }

    public InputStream open() throws IOException {
        if (zipEntry != null) {
            ZipFile zf = new ZipFile(file.toFile());
            InputStream in = zf.getInputStream(zf.getEntry(zipEntry));
            return new java.io.FilterInputStream(in) {
                @Override public void close() throws IOException { super.close(); zf.close(); }
            };
        }
        InputStream in = Files.newInputStream(file);
        if (gzip) return new GZIPInputStream(new BufferedInputStream(in, 1 << 16), 1 << 16);
        return in;
    }

    synchronized void addStats(long n, long min, long max) {
        events += n;
        if (n > 0) {
            minTs = Math.min(minTs, min);
            maxTs = Math.max(maxTs, max);
        }
    }
}
