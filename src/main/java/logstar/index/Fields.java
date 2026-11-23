package logstar.index;

/** Field names in the Lucene index. */
public final class Fields {
    public static final String TS = "ts";          // LongPoint + NumericDocValues + stored
    public static final String LVL = "lvl";        // IntPoint + NumericDocValues + stored
    public static final String LEVEL = "level";    // keyword (TRACE..FATAL)
    public static final String LOGGER = "logger";  // keyword + SortedDocValues + stored
    public static final String THREAD = "thread";  // keyword + SortedDocValues + stored
    public static final String CODE = "code";      // keyword multi (message codes); SortedDocValues = primary code
    public static final String EX = "ex";          // keyword multi: FQCN and simple names of all exceptions
    public static final String KEY = "k";          // IntPoint + NumericDocValues + stored: template key id
    public static final String FILE = "file";      // IntPoint + NumericDocValues + stored
    public static final String OFF = "off";        // LongPoint + NumericDocValues + stored: byte offset in file
    public static final String TEXT = "text";      // analysed full text
    public static final String RAW = "raw";        // stored full text
    private Fields() {}
}
