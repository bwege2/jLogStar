package jlogstar.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Describes how the part of a header line after the timestamp is structured.
 * Text layouts are regexes with named groups level / logger / thread / msg.
 */
public abstract class Layout {
    public final String name;

    protected Layout(String name) { this.name = name; }

    /** Parses the remainder of a header line starting at 'from' into ev (level/logger/thread/message). */
    public abstract boolean parse(String line, int from, RawEvent ev, Matcher[] cache, int slot);

    public static final class RegexLayout extends Layout {
        final Pattern p;
        final boolean hasLogger, hasThread;

        RegexLayout(String name, String regex) {
            super(name);
            this.p = Pattern.compile(regex);
            this.hasLogger = regex.contains("?<logger>");
            this.hasThread = regex.contains("?<thread>");
        }

        @Override
        public boolean parse(String line, int from, RawEvent ev, Matcher[] cache, int slot) {
            Matcher m = cache[slot];
            if (m == null) cache[slot] = m = p.matcher(line);
            else m.reset(line);
            m.region(from, line.length());
            if (!m.lookingAt()) return false;
            int lv = Level.parse(line, m.start("level"), m.end("level"));
            if (lv < 0) return false;
            ev.level = lv;
            ev.logger = hasLogger ? m.group("logger").trim() : "";
            ev.thread = hasThread ? m.group("thread").trim() : "";
            ev.message = m.group("msg");
            return true;
        }
    }

    /** Fallback: find a level word among the first tokens, message = rest. */
    public static final class GenericLayout extends Layout {
        GenericLayout() { super("generic"); }

        @Override
        public boolean parse(String line, int from, RawEvent ev, Matcher[] cache, int slot) {
            int n = line.length();
            int i = from;
            for (int tok = 0; tok < 6 && i < n; tok++) {
                while (i < n && (line.charAt(i) == ' ' || line.charAt(i) == '\t' || line.charAt(i) == '[' || line.charAt(i) == '|')) i++;
                int s = i;
                while (i < n && Character.isLetter(line.charAt(i))) i++;
                if (i > s && Level.parse(line, s, i) >= 0 && (i >= n || !Character.isLetterOrDigit(line.charAt(i)))) {
                    ev.level = Level.parse(line, s, i);
                    while (i < n && (line.charAt(i) == ']' || line.charAt(i) == ' ' || line.charAt(i) == ':' || line.charAt(i) == '|' || line.charAt(i) == '-')) i++;
                    ev.message = line.substring(i);
                    return true;
                }
                while (i < n && line.charAt(i) != ' ' && line.charAt(i) != '\t') i++;
            }
            ev.level = Level.INFO;
            ev.message = line.substring(Math.min(from, n)).trim();
            return true;
        }
    }

    private static final String LVL = "(?<level>[A-Za-z]{3,9})";

    /** Candidate text layouts, tried in order during format detection. */
    public static final List<Layout> TEXT_LAYOUTS = List.of(
            // WildFly / JBoss: %d %-5p [%c] (%t) %s%e%n
            new RegexLayout("jboss", "\\s*" + LVL + "\\s+\\[(?<logger>[^\\]]*)\\]\\s+\\((?<thread>.*?)\\)\\s(?<msg>.*)"),
            // Log4j2 / Logback default: %d [%t] %-5level %logger{36} - %msg
            new RegexLayout("thread-level-logger", "\\s*\\[(?<thread>[^\\]]*)\\]\\s+" + LVL + "\\s+(?<logger>[\\w.$\\-]+)\\s*(?:-|:)\\s?(?<msg>.*)"),
            // Log4j 1: %d %-5p [%t] %c - %m
            new RegexLayout("level-thread-logger", "\\s*" + LVL + "\\s+\\[(?<thread>[^\\]]*)\\]\\s+(?<logger>[\\w.$\\-]+)\\s*(?:-|:)\\s?(?<msg>.*)"),
            // %d %-5p [%c] [%t] %m / %d %-5p %c [%t] - %m
            new RegexLayout("level-logger-thread", "\\s*" + LVL + "\\s+\\[?(?<logger>[\\w.$\\-]+)\\]?\\s+\\[(?<thread>[^\\]]*)\\]\\s*(?:-|:)?\\s?(?<msg>.*)"),
            // Spring Boot: %d %5p 1234 --- [app] [thread] logger : msg
            new RegexLayout("spring", "\\s*" + LVL + "\\s+\\d+\\s+---\\s+(?:\\[[^\\]]*\\]\\s+)?\\[\\s*(?<thread>[^\\]]*)\\]\\s+(?<logger>[\\w.$\\-]+)\\s*:\\s?(?<msg>.*)"),
            // %d [%t] %c %-5p - %m  (thread, logger, level)
            new RegexLayout("thread-logger-level", "\\s*\\[(?<thread>[^\\]]*)\\]\\s+(?<logger>[\\w.$\\-]+)\\s+" + LVL + "\\s*(?:-|:)\\s?(?<msg>.*)"),
            // %d %-5p %c - %m (no thread)
            new RegexLayout("level-logger", "\\s*" + LVL + "\\s+\\[?(?<logger>[\\w.$\\-]+)\\]?\\s*(?:-|:)\\s?(?<msg>.*)"),
            // %d %-5p (%t) [%c] %m
            new RegexLayout("level-pthread-logger", "\\s*" + LVL + "\\s+\\((?<thread>.*?)\\)\\s+\\[(?<logger>[^\\]]*)\\]\\s?(?<msg>.*)")
    );

    public static final Layout GENERIC = new GenericLayout();

    // ---------------------------------------------------------------- JSON lines

    /** JSON-lines layouts: log4j2 JsonLayout/JsonTemplateLayout/EcsLayout, logstash, WildFly json-formatter. */
    public static final class JsonLayout extends Layout {
        private static final ObjectMapper M = new ObjectMapper();

        public JsonLayout() { super("json"); }

        @Override
        public boolean parse(String line, int from, RawEvent ev, Matcher[] cache, int slot) {
            throw new UnsupportedOperationException();
        }

        private static JsonNode first(JsonNode n, String... paths) {
            for (String p : paths) {
                JsonNode cur = n;
                for (String part : p.split("/")) {
                    if (cur == null) break;
                    cur = cur.get(part);
                }
                if (cur != null && !cur.isNull() && !cur.isMissingNode()) return cur;
            }
            return null;
        }

        /** Parses a JSON line. Returns false if it is not a JSON object. */
        public boolean parseJson(String line, RawEvent ev, TsParser tsp, TsParser.Result r) {
            JsonNode n;
            try {
                n = M.readTree(line);
            } catch (Exception e) {
                return false;
            }
            if (n == null || !n.isObject()) return false;
            long ts = Long.MIN_VALUE;
            JsonNode t = first(n, "@timestamp", "timestamp", "time", "date", "ts", "instant", "timeMillis", "datetime");
            if (t != null) {
                if (t.isNumber()) {
                    long v = t.asLong();
                    ts = v < 100_000_000_000L ? v * 1000 : v;
                } else if (t.isObject() && t.has("epochSecond")) {
                    ts = t.get("epochSecond").asLong() * 1000 + t.path("nanoOfSecond").asLong() / 1_000_000;
                } else if (tsp.parse(t.asText(), 0, r) && !r.timeOnly) {
                    ts = r.epochMs;
                }
            }
            if (ts == Long.MIN_VALUE) return false;
            ev.ts = ts;
            JsonNode lv = first(n, "level", "log.level", "log/level", "severity", "levelname");
            ev.level = lv == null ? Level.INFO : Math.max(0, Level.parse(lv.asText()));
            JsonNode lg = first(n, "loggerName", "logger_name", "logger", "log.logger", "log/logger", "category");
            ev.logger = lg == null ? "" : lg.asText();
            JsonNode th = first(n, "thread", "threadName", "thread_name", "process.thread.name", "process/thread/name");
            ev.thread = th == null ? "" : th.asText();
            JsonNode msg = first(n, "message", "msg", "@message", "formattedMessage");
            String message = msg == null ? "" : (msg.isTextual() ? msg.asText() : msg.toString());
            int nl = message.indexOf('\n');
            ev.message = nl >= 0 ? message.substring(0, nl) : message;

            StringBuilder sb = ev.text;
            sb.setLength(0);
            sb.append(isoLike(ts)).append(' ').append(Level.name(ev.level)).append(" [").append(ev.logger).append("] (")
                    .append(ev.thread).append(") ").append(ev.message);
            ev.bodyStart = sb.length();
            if (nl >= 0) sb.append(message, nl, message.length());
            String stack = stackText(n);
            if (stack != null && !stack.isEmpty()) sb.append('\n').append(stack.stripTrailing());
            // MDC context helps a lot in practice (request ids, users) - append compactly
            JsonNode mdc = first(n, "mdc", "contextMap", "context");
            if (mdc != null && mdc.isObject() && !mdc.isEmpty()) {
                sb.append("\n  MDC: ");
                Iterator<Map.Entry<String, JsonNode>> it = mdc.properties().iterator();
                while (it.hasNext()) {
                    var e = it.next();
                    sb.append(e.getKey()).append('=').append(e.getValue().asText());
                    if (it.hasNext()) sb.append(", ");
                }
            }
            return true;
        }

        private static String stackText(JsonNode n) {
            JsonNode s = first(n, "stack_trace", "stackTrace", "error.stack_trace", "error/stack_trace", "exception/stacktrace", "stacktrace");
            if (s != null && s.isTextual()) return s.asText();
            JsonNode thrown = first(n, "thrown", "exception", "error");
            if (thrown == null) return null;
            if (thrown.isTextual()) return thrown.asText();
            if (thrown.has("extendedStackTrace") && thrown.get("extendedStackTrace").isTextual()) return thrown.get("extendedStackTrace").asText();
            StringBuilder sb = new StringBuilder();
            renderThrowable(thrown, sb, false, 0);
            return sb.toString();
        }

        /** Renders log4j2 'thrown' or WildFly 'exception' objects as a classic Java stack trace. */
        private static void renderThrowable(JsonNode t, StringBuilder sb, boolean cause, int depth) {
            if (t == null || !t.isObject() || depth > 20) return;
            JsonNode name = first(t, "name", "exceptionType", "type", "class");
            JsonNode msg = first(t, "message", "localizedMessage");
            if (sb.length() > 0) sb.append('\n');
            if (cause) sb.append("Caused by: ");
            sb.append(name == null ? "java.lang.Throwable" : name.asText());
            if (msg != null) sb.append(": ").append(msg.asText());
            JsonNode frames = first(t, "extendedStackTrace", "stackTrace", "frames");
            if (frames != null && frames.isArray()) {
                for (JsonNode f : frames) {
                    JsonNode cls = first(f, "class", "className", "declaringClass");
                    JsonNode m = first(f, "method", "methodName");
                    JsonNode file = first(f, "file", "fileName");
                    JsonNode ln = first(f, "line", "lineNumber");
                    sb.append("\n\tat ").append(cls == null ? "?" : cls.asText()).append('.').append(m == null ? "?" : m.asText())
                            .append('(').append(file == null ? "Unknown Source" : file.asText());
                    if (ln != null) sb.append(':').append(ln.asText());
                    sb.append(')');
                }
            }
            renderThrowable(first(t, "cause", "causedBy"), sb, true, depth + 1);
        }

        private static String isoLike(long ts) {
            return java.time.Instant.ofEpochMilli(ts).atZone(java.time.ZoneId.systemDefault()).toLocalDateTime().toString().replace('T', ' ');
        }
    }
}
