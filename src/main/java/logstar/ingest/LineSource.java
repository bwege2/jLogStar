package logstar.ingest;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Fast byte-oriented line reader that tracks the absolute byte offset of every line. Strips \r and ANSI escapes. */
public final class LineSource implements AutoCloseable {
    private final InputStream in;
    private final byte[] buf;
    private int pos, lim;
    private long base;          // absolute offset of buf[0]
    private boolean eof;
    public long lineOffset;     // offset of the line returned last
    public static final int MAX_LINE = 64 * 1024;

    public LineSource(InputStream in, long startOffset, int bufSize) {
        this.in = in;
        this.buf = new byte[bufSize];
        this.base = startOffset;
    }

    /** Bytes consumed so far (absolute position). */
    public long position() {
        return base + pos;
    }

    private boolean fill() throws IOException {
        if (eof) return false;
        if (pos > 0) {
            System.arraycopy(buf, pos, buf, 0, lim - pos);
            base += pos;
            lim -= pos;
            pos = 0;
        }
        if (lim == buf.length) return true; // full: caller handles long lines
        int r = in.read(buf, lim, buf.length - lim);
        if (r < 0) { eof = true; return false; }
        lim += r;
        return true;
    }

    /** Returns the next line or null at EOF. Lines longer than MAX_LINE are cut (rest skipped). */
    public String next() throws IOException {
        while (true) {
            for (int i = pos; i < lim; i++) {
                if (buf[i] == '\n') {
                    String s = decode(pos, i);
                    lineOffset = base + pos;
                    pos = i + 1;
                    return s;
                }
            }
            if (lim - pos >= MAX_LINE || (lim == buf.length && pos == 0)) {
                // overlong line: return a cut version and skip to the next newline
                lineOffset = base + pos;
                String s = decode(pos, pos + Math.min(MAX_LINE, lim - pos));
                pos = lim;
                skipToNewline();
                return s;
            }
            if (!fill()) {
                if (pos < lim) {
                    String s = decode(pos, lim);
                    lineOffset = base + pos;
                    pos = lim;
                    return s;
                }
                return null;
            }
        }
    }

    private void skipToNewline() throws IOException {
        while (true) {
            for (int i = pos; i < lim; i++) {
                if (buf[i] == '\n') { pos = i + 1; return; }
            }
            pos = lim;
            if (!fill()) return;
        }
    }

    private String decode(int from, int to) {
        if (to > from && buf[to - 1] == '\r') to--;
        boolean esc = false;
        for (int i = from; i < to; i++) if (buf[i] == 0x1b) { esc = true; break; }
        String s = new String(buf, from, to - from, StandardCharsets.UTF_8);
        return esc ? stripAnsi(s) : s;
    }

    static String stripAnsi(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == 0x1b && i + 1 < s.length() && s.charAt(i + 1) == '[') {
                int j = i + 2;
                while (j < s.length() && !(s.charAt(j) >= '@' && s.charAt(j) <= '~')) j++;
                i = j;
            } else sb.append(c);
        }
        return sb.toString();
    }

    @Override
    public void close() throws IOException {
        in.close();
    }
}
