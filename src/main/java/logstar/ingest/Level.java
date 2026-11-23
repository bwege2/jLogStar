package logstar.ingest;

/** Normalised log levels, stored as small ints so they fit cheaply into doc values. */
public final class Level {
    public static final int TRACE = 0, DEBUG = 1, INFO = 2, WARN = 3, ERROR = 4, FATAL = 5;
    public static final String[] NAMES = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
    public static final int COUNT = NAMES.length;

    private Level() {}

    /** Parses a level word in s[from,to); returns -1 if it is not a known level. Case-insensitive. */
    public static int parse(CharSequence s, int from, int to) {
        int len = to - from;
        if (len < 3 || len > 9) return -1;
        char[] b = new char[len];
        for (int i = 0; i < len; i++) b[i] = Character.toUpperCase(s.charAt(from + i));
        return switch (new String(b)) {
            case "TRACE", "FINEST", "FINER", "ALL" -> TRACE;
            case "DEBUG", "FINE", "DBG" -> DEBUG;
            case "INFO", "CONFIG", "NOTICE", "INF" -> INFO;
            case "WARN", "WARNING", "WRN" -> WARN;
            case "ERROR", "SEVERE", "ERR" -> ERROR;
            case "FATAL", "CRITICAL", "CRIT", "ALERT", "EMERG", "EMERGENCY" -> FATAL;
            default -> -1;
        };
    }

    public static int parse(String s) {
        return s == null ? -1 : parse(s.trim(), 0, s.trim().length());
    }

    public static String name(int level) {
        return level >= 0 && level < COUNT ? NAMES[level] : "INFO";
    }
}
