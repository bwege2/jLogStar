package jlogstar.ingest;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.zone.ZoneRules;
import java.util.HashMap;

/**
 * Hand-written timestamp parser for the formats Java logging frameworks typically print at the start of a line.
 * Much faster than DateTimeFormatter. Not thread-safe (keeps a per-instance offset cache).
 *
 * Supported (optionally wrapped in [ ]):
 *   yyyy-MM-dd HH:mm:ss[,.]SSS  (also 'T' separator, '/' date separators, optional fraction, Z / +hh:mm / +hhmm)
 *   dd.MM.yyyy HH:mm:ss[,.]SSS
 *   dd MMM yyyy HH:mm:ss,SSS    (log4j DATE)
 *   dd-MMM-yyyy HH:mm:ss.SSS    (Tomcat)
 *   HH:mm:ss[,.]SSS             (time only, e.g. WildFly console; date supplied by caller)
 */
public final class TsParser {
    public static final long DAY_MS = 86_400_000L;

    /** Result of a parse. epochMs is only valid when !timeOnly; for timeOnly see msOfDay. */
    public static final class Result {
        public long epochMs;
        public long msOfDay;
        public boolean timeOnly;
        public int end;
    }

    private final ZoneRules rules;
    private final boolean fixed;
    private final int fixedOffsetSec;
    private final HashMap<Long, Integer> offsetCache = new HashMap<>();

    public TsParser(ZoneId zone) {
        this.rules = zone.getRules();
        this.fixed = rules.isFixedOffset();
        this.fixedOffsetSec = fixed ? rules.getOffset(java.time.Instant.EPOCH).getTotalSeconds() : 0;
    }

    private static final String[] MONTHS = {"JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"};

    private static int d(CharSequence s, int i) {
        char c = s.charAt(i);
        return c >= '0' && c <= '9' ? c - '0' : -1;
    }

    private static int num(CharSequence s, int i, int n) {
        if (i + n > s.length()) return -1;
        int v = 0;
        for (int k = 0; k < n; k++) {
            int x = d(s, i + k);
            if (x < 0) return -1;
            v = v * 10 + x;
        }
        return v;
    }

    private static int month(CharSequence s, int i) {
        if (i + 3 > s.length()) return -1;
        for (int m = 0; m < 12; m++) {
            String mm = MONTHS[m];
            if (Character.toUpperCase(s.charAt(i)) == mm.charAt(0) && Character.toUpperCase(s.charAt(i + 1)) == mm.charAt(1)
                    && Character.toUpperCase(s.charAt(i + 2)) == mm.charAt(2)) return m + 1;
        }
        return -1;
    }

    /** Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm). */
    public static long epochDay(int y, int m, int dd) {
        y -= m <= 2 ? 1 : 0;
        long era = (y >= 0 ? y : y - 399) / 400;
        long yoe = y - era * 400;
        long doy = (153L * (m + (m > 2 ? -3 : 9)) + 2) / 5 + dd - 1;
        long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * 146097 + doe - 719468;
    }

    /** Converts local date/time to epoch millis using the configured zone. */
    public long toEpoch(long epochDay, long msOfDay) {
        long localSec = epochDay * 86400 + msOfDay / 1000;
        int off;
        if (fixed) off = fixedOffsetSec;
        else {
            long hourKey = localSec / 3600;
            Integer c = offsetCache.get(hourKey);
            if (c == null) {
                c = rules.getOffset(LocalDateTime.ofEpochSecond(localSec, 0, ZoneOffset.UTC)).getTotalSeconds();
                if (offsetCache.size() > 100_000) offsetCache.clear();
                offsetCache.put(hourKey, c);
            }
            off = c;
        }
        return (localSec - off) * 1000 + msOfDay % 1000;
    }

    /** Parses a timestamp at position 'from'. Returns false if none found. */
    public boolean parse(CharSequence s, int from, Result r) {
        int n = s.length();
        int i = from;
        boolean bracket = false;
        if (i < n && s.charAt(i) == '[') { bracket = true; i++; }
        if (i + 8 > n) return false;
        int y = -1, mo = -1, da = -1;
        int c0 = d(s, i);
        if (c0 < 0) {
            return false;
        }
        // yyyy-MM-dd / yyyy/MM/dd
        if (i + 10 <= n && (s.charAt(i + 4) == '-' || s.charAt(i + 4) == '/') && s.charAt(i + 7) == s.charAt(i + 4)) {
            y = num(s, i, 4); mo = num(s, i + 5, 2); da = num(s, i + 8, 2);
            if (y < 0 || mo < 0 || da < 0) return false;
            i += 10;
            if (i >= n || (s.charAt(i) != ' ' && s.charAt(i) != 'T')) return false;
            i++;
        } else if (i + 10 <= n && s.charAt(i + 2) == '.' && s.charAt(i + 5) == '.') { // dd.MM.yyyy
            da = num(s, i, 2); mo = num(s, i + 3, 2); y = num(s, i + 6, 4);
            if (y < 0 || mo < 0 || da < 0) return false;
            i += 10;
            if (i >= n || s.charAt(i) != ' ') return false;
            i++;
        } else if (i + 11 <= n && (s.charAt(i + 2) == ' ' || s.charAt(i + 2) == '-') && Character.isLetter(s.charAt(i + 3))) { // dd MMM yyyy
            da = num(s, i, 2); mo = month(s, i + 3); 
            if (da < 0 || mo < 0 || s.charAt(i + 6) != s.charAt(i + 2)) return false;
            y = num(s, i + 7, 4);
            if (y < 0) return false;
            i += 11;
            if (i >= n || s.charAt(i) != ' ') return false;
            i++;
        }
        // time HH:mm:ss
        if (i + 8 > n || s.charAt(i + 2) != ':' || s.charAt(i + 5) != ':') return false;
        int hh = num(s, i, 2), mi = num(s, i + 3, 2), ss = num(s, i + 6, 2);
        if (hh < 0 || mi < 0 || ss < 0 || hh > 23 || mi > 59 || ss > 60) return false;
        i += 8;
        int ms = 0;
        if (i < n && (s.charAt(i) == ',' || s.charAt(i) == '.')) {
            int k = i + 1, digits = 0;
            while (k < n && d(s, k) >= 0) {
                if (digits < 3) ms = ms * 10 + d(s, k);
                digits++; k++;
            }
            if (digits == 0) return false;
            for (int p = digits; p < 3; p++) ms *= 10;
            i = k;
        }
        int offSec = Integer.MIN_VALUE;
        if (i < n && s.charAt(i) == 'Z') { offSec = 0; i++; }
        else if (i + 3 <= n && (s.charAt(i) == '+' || s.charAt(i) == '-') && d(s, i + 1) >= 0 && y >= 0) {
            int sign = s.charAt(i) == '-' ? -1 : 1;
            int oh = num(s, i + 1, 2);
            int k = i + 3, om = 0;
            if (k < n && s.charAt(k) == ':') k++;
            int x = num(s, k, 2);
            if (x >= 0) { om = x; k += 2; }
            if (oh >= 0) { offSec = sign * (oh * 3600 + om * 60); i = k; }
        }
        if (bracket) {
            while (i < n && s.charAt(i) == ' ') i++;
            if (i < n && s.charAt(i) == ']') i++; else return false;
        }
        if (i < n) {
            char c = s.charAt(i);
            if (!(c == ' ' || c == '\t' || c == '|' || c == ']' || c == '[' || c == '-')) return false;
        }
        long msOfDay = ((hh * 60L + mi) * 60 + Math.min(ss, 59)) * 1000 + ms;
        r.end = i;
        r.msOfDay = msOfDay;
        if (y < 0) {
            r.timeOnly = true;
            r.epochMs = 0;
        } else {
            if (mo < 1 || mo > 12 || da < 1 || da > 31) return false;
            r.timeOnly = false;
            long ed = epochDay(y, mo, da);
            r.epochMs = offSec != Integer.MIN_VALUE ? (ed * 86400 + msOfDay / 1000 - offSec) * 1000 + ms : toEpoch(ed, msOfDay);
        }
        return true;
    }
}
