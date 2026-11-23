package jlogstar.ingest;

/**
 * Replaces variable parts of a log message (numbers, ids, uuids, ips, hashes, long tokens, quoted values with digits)
 * by the placeholder <*>, so that messages produced by the same log statement collapse to one template.
 * Message codes like WFLYEJB0034 or IJ000453 and identifier-like tokens (Log4j2, Lucene104Codec) are preserved.
 */
public final class Masker {
    public static final String WILD = "<*>";
    static final int MAX = 400;

    private Masker() {}

    public static String mask(String msg) {
        if (msg == null || msg.isEmpty()) return "";
        String s = msg.length() > MAX ? msg.substring(0, MAX) : msg;
        StringBuilder out = new StringBuilder(s.length() + 8);
        int n = s.length();
        int i = 0;
        while (i < n) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                if (!out.isEmpty() && out.charAt(out.length() - 1) != ' ') out.append(' ');
                i++;
                continue;
            }
            if ((c == '"' || c == '\'') && quoteStart(s, i)) {
                int close = s.indexOf(c, i + 1);
                if (close > i && close - i <= 240) {
                    boolean variable = close - i - 1 > 40;
                    for (int k = i + 1; k < close && !variable; k++) if (Character.isDigit(s.charAt(k))) variable = true;
                    if (variable) {
                        out.append(c).append(WILD).append(c);
                        i = close + 1;
                        continue;
                    }
                }
            }
            int j = i;
            while (j < n && s.charAt(j) != ' ' && s.charAt(j) != '\t' && s.charAt(j) != '\r' && s.charAt(j) != '\n') j++;
            if (keepNext(out)) out.append(s, i, j); // SQLState / vendor error codes identify the error type
            else maskToken(s, i, j, out);
            i = j;
        }
        if (msg.length() > MAX) out.append(" …");
        // collapse "<*> <*>" and "<*><*>"
        String r = out.toString().trim();
        if (r.contains("<*><*>") || r.contains("<*> <*>")) {
            String prev;
            do {
                prev = r;
                r = r.replace("<*><*>", WILD).replace("<*> <*>", WILD);
            } while (!r.equals(prev));
        }
        return r;
    }

    private static final String[] KEEP_AFTER = {"SQLState: ", "SQL Error: ", "ErrorCode: ", "SQLSTATE: ", "errorCode=", "Status: ", "status code "};

    private static boolean keepNext(StringBuilder out) {
        for (String k : KEEP_AFTER) {
            int n = out.length(), m = k.length();
            if (n >= m && out.substring(n - m).equals(k)) return true;
        }
        return false;
    }

    private static boolean quoteStart(String s, int i) {
        if (i == 0) return true;
        char p = s.charAt(i - 1);
        return p == ' ' || p == '=' || p == '(' || p == '[' || p == ':' || p == ',' || p == '{';
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static boolean isPunctLead(char c) {
        return c == '"' || c == '\'' || c == '(' || c == '[' || c == '{' || c == '<' || c == '#';
    }

    private static boolean isPunctTrail(char c) {
        return c == '"' || c == '\'' || c == ')' || c == ']' || c == '}' || c == '>' || c == ',' || c == ';' || c == ':' || c == '.' || c == '!' || c == '?';
    }

    static void maskToken(String s, int from, int to, StringBuilder out) {
        int a = from, b = to;
        while (a < b && isPunctLead(s.charAt(a))) a++;
        while (b > a && isPunctTrail(s.charAt(b - 1))) b--;
        out.append(s, from, a);
        if (a < b) maskCore(s, a, b, out);
        out.append(s, b, to);
    }

    private static void maskCore(String s, int a, int b, StringBuilder out) {
        int len = b - a;
        int digits = 0, letters = 0, seps = 0;
        for (int k = a; k < b; k++) {
            char c = s.charAt(k);
            if (c >= '0' && c <= '9') digits++;
            else if (Character.isLetter(c)) letters++;
            if (isSep(c)) seps++;
        }
        // message codes: WFLYEJB0034, IJ000453, ARJUNA012117, HHH000315, UT005023
        if (digits > 0 && len >= 5 && len <= 20 && Character.isUpperCase(s.charAt(a))) {
            int k = a;
            while (k < b && Character.isUpperCase(s.charAt(k))) k++;
            int l = k;
            while (l < b && Character.isDigit(s.charAt(l))) l++;
            if (l == b && k - a >= 2 && l - k >= 3) { out.append(s, a, b); return; }
        }
        // identifier-like (Log4j2, Lucene104Codec, UTF8): starts uppercase, no separators, mostly letters
        if (digits > 0 && seps == 0 && len <= 20 && Character.isUpperCase(s.charAt(a)) && letters >= 2 * digits && !contains(s, a, b, '-') && !contains(s, a, b, '_')) {
            out.append(s, a, b);
            return;
        }
        // split at separators and mask each segment on its own (key=value, paths, host:port, Class@hash)
        int p = a;
        for (int k = a; k <= b; k++) {
            if (k == b || isSep(s.charAt(k))) {
                if (k > p) maskSegment(s, p, k, out);
                if (k < b) out.append(s.charAt(k));
                p = k + 1;
            }
        }
    }

    private static boolean isSep(char c) {
        return c == '=' || c == '/' || c == '@' || c == ':' || c == ',' || c == ';' || c == '(' || c == ')' || c == '[' || c == ']'
                || c == '<' || c == '>' || c == '"' || c == '\'' || c == '&' || c == '?' || c == '#' || c == '|';
    }

    private static void maskSegment(String s, int a, int b, StringBuilder out) {
        int len = b - a;
        int digits = 0, letters = 0, upper = 0, lower = 0, hex = 0, dots = 0;
        for (int k = a; k < b; k++) {
            char c = s.charAt(k);
            if (c >= '0' && c <= '9') digits++;
            else if (Character.isLetter(c)) { letters++; if (Character.isUpperCase(c)) upper++; else lower++; }
            if (isHex(c) || c == '-') hex++;
            if (c == '.') dots++;
        }
        if (digits == 0) {
            // random-looking tokens without digits (session ids, base64)
            if (len >= 20 && dots == 0 && lower > 1 && upper >= 0.25 * letters && upper <= 0.75 * letters) { appendWild(out); return; }
            out.append(s, a, b);
            return;
        }
        if (hex == len && len >= 6) { appendWild(out); return; }                       // uuid, hashes, hex ids
        if (len > 2 && s.charAt(a) == '0' && (s.charAt(a + 1) == 'x' || s.charAt(a + 1) == 'X')) { appendWild(out); return; }
        if (len >= 10 && letters >= 2 && dots == 0) { appendWild(out); return; }       // session ids, tokens
        // digit-run masking: runs of digits (with . , : between digits) -> <*>
        int k = a;
        while (k < b) {
            char c = s.charAt(k);
            if (Character.isDigit(c)) {
                int e = k;
                while (e < b) {
                    char x = s.charAt(e);
                    if (Character.isDigit(x)) e++;
                    else if ((x == '.' || x == ',') && e + 1 < b && Character.isDigit(s.charAt(e + 1))) e++;
                    else break;
                }
                appendWild(out);
                k = e;
            } else {
                out.append(c);
                k++;
            }
        }
    }

    private static boolean contains(String s, int a, int b, char c) {
        for (int k = a; k < b; k++) if (s.charAt(k) == c) return true;
        return false;
    }

    private static void appendWild(StringBuilder out) {
        int n = out.length();
        if (n >= 3 && out.charAt(n - 1) == '>' && out.charAt(n - 2) == '*' && out.charAt(n - 3) == '<') return;
        out.append(WILD);
    }
}
