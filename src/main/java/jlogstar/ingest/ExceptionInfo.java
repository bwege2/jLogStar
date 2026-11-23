package jlogstar.ingest;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Exception chain extracted from a (multi-line) Java log event. */
public final class ExceptionInfo {
    /** All exception classes in order of appearance (outermost first, then causes). */
    public final List<String> classes = new ArrayList<>(4);
    public String outer;
    public String root;
    public String rootMessage;
    /** Normalised signature: outer|root|appFrame;appFrame */
    public String signature = "";
    /** Message codes (WFLYxxx, IJ, ARJUNA ...) found in exception lines. */
    public final List<String> codes = new ArrayList<>(2);

    static final String[] FRAMEWORK = {
            "java.", "javax.", "jakarta.", "jdk.", "sun.", "com.sun.", "org.jboss.", "org.wildfly.", "io.undertow.",
            "org.hibernate.", "org.apache.", "org.springframework.", "com.arjuna.", "org.infinispan.", "org.eclipse.",
            "io.netty.", "org.glassfish.", "com.fasterxml.", "org.slf4j.", "org.junit.", "kotlin.", "scala.", "groovy.",
            "org.postgresql.", "oracle.", "com.mysql.", "com.microsoft.sqlserver.", "org.h2.", "net.bytebuddy.",
            "io.smallrye.", "io.quarkus.", "org.keycloak.", "org.mariadb.", "com.zaxxer.", "org.aspectj.", "reactor.",
            "io.opentelemetry.", "org.xnio.", "org.picketbox.", "org.omg.", "com.google.", "org.codehaus.", "jdk.proxy",
            "$Proxy", "com.ibm.", "weblogic.", "org.mockito.", "io.micrometer.", "org.jgroups."
    };

    public static boolean isFramework(String cls) {
        for (String p : FRAMEWORK) if (cls.startsWith(p)) return true;
        return false;
    }

    private static final Pattern INLINE_EX = Pattern.compile("\\b((?:[a-z_$][\\w$]*\\.)+[A-Z][\\w$]*(?:Exception|Error|Throwable|Fault))\\b");
    public static final Pattern CODE = Pattern.compile("\\b([A-Z]{2,12}\\d{3,7})\\b:?");

    /** True if the token s[from,to) looks like a fully qualified exception class name. */
    public static boolean isExceptionClass(CharSequence s, int from, int to) {
        if (to - from < 5) return false;
        int lastDot = -1, dots = 0;
        for (int i = from; i < to; i++) {
            char c = s.charAt(i);
            if (c == '.') { lastDot = i; dots++; }
            else if (!(Character.isLetterOrDigit(c) || c == '_' || c == '$')) return false;
        }
        if (dots < 1 || lastDot == to - 1 || !Character.isUpperCase(s.charAt(lastDot + 1))) return false;
        if (!Character.isLowerCase(s.charAt(from))) return false;
        String simple = s.subSequence(lastDot + 1, to).toString();
        return simple.endsWith("Exception") || simple.endsWith("Error") || simple.endsWith("Throwable") || simple.contains("Exception")
                || simple.endsWith("Fault") || simple.endsWith("Failure") || simple.endsWith("Problem");
    }

    /** Normalises generated class names in frames: lambdas, proxies, accessors, CGLIB/ByteBuddy enhancers, line-less. */
    static String normalizeFrame(String frame) {
        int dd = frame.indexOf("$$");
        if (dd > 0) {
            int lastDot = frame.lastIndexOf('.');
            frame = frame.substring(0, dd) + "$$*" + (lastDot > dd ? frame.substring(lastDot) : "");
        }
        StringBuilder sb = null;
        for (int i = 0; i < frame.length(); i++) {
            char c = frame.charAt(i);
            if (Character.isDigit(c) && i > 0 && (frame.charAt(i - 1) == '$' || frame.startsWith("GeneratedMethodAccessor", Math.max(0, i - 23))
                    || Character.isDigit(frame.charAt(i - 1)))) {
                if (sb == null) sb = new StringBuilder(frame.substring(0, i));
                if (sb.isEmpty() || sb.charAt(sb.length() - 1) != '#') sb.append('#');
            } else if (sb != null) sb.append(c);
        }
        return sb == null ? frame : sb.toString();
    }

    public static ExceptionInfo parse(CharSequence text, int bodyStart, String headerMessage) {
        ExceptionInfo info = new ExceptionInfo();
        int n = text.length();
        int i = bodyStart;
        List<List<String>> frames = new ArrayList<>(4);
        List<String> current = null;
        boolean inSuppressed = false;
        int lines = 0;
        while (i < n && lines < 4000) {
            int e = i;
            while (e < n && text.charAt(e) != '\n') e++;
            int s = i;
            while (s < e && (text.charAt(s) == ' ' || text.charAt(s) == '\t')) s++;
            lines++;
            if (s + 3 < e && text.charAt(s) == 'a' && text.charAt(s + 1) == 't' && text.charAt(s + 2) == ' ') {
                if (current != null && !inSuppressed && current.size() < 12) {
                    int p = s + 3;
                    int paren = p;
                    while (paren < e && text.charAt(paren) != '(') paren++;
                    String fr = text.subSequence(p, paren).toString().trim();
                    // strip module prefix "app//" or "java.base@17/"
                    int slash = fr.lastIndexOf('/');
                    if (slash >= 0) fr = fr.substring(slash + 1);
                    current.add(fr);
                }
            } else if (startsWith(text, s, e, "Caused by: ")) {
                int cs = s + 11;
                int ce = tokenEnd(text, cs, e);
                if (isExceptionClass(text, cs, ce)) {
                    String cls = text.subSequence(cs, ce).toString();
                    info.classes.add(cls);
                    info.root = cls;
                    info.rootMessage = ce + 1 < e ? text.subSequence(Math.min(e, ce + 2), e).toString() : "";
                    current = new ArrayList<>();
                    frames.add(current);
                    inSuppressed = false;
                    codes(text, ce, e, info);
                }
            } else if (startsWith(text, s, e, "Suppressed: ")) {
                inSuppressed = true;
            } else if (!startsWith(text, s, e, "...") && frames.isEmpty()) {
                int ce = tokenEnd(text, s, e);
                if (isExceptionClass(text, s, ce)) {
                    String cls = text.subSequence(s, ce).toString();
                    info.classes.add(cls);
                    info.outer = cls;
                    info.root = cls;
                    info.rootMessage = ce + 1 < e ? text.subSequence(Math.min(e, ce + 2), e).toString() : "";
                    current = new ArrayList<>();
                    frames.add(current);
                    codes(text, ce, e, info);
                }
            }
            i = e + 1;
        }
        if (info.classes.isEmpty() && headerMessage != null
                && (headerMessage.contains("Exception") || headerMessage.contains("Error"))) {
            Matcher m = INLINE_EX.matcher(headerMessage);
            while (m.find() && info.classes.size() < 4) {
                info.classes.add(m.group(1));
                if (info.outer == null) info.outer = m.group(1);
                info.root = m.group(1);
                int after = m.end();
                info.rootMessage = after + 2 <= headerMessage.length() ? headerMessage.substring(Math.min(headerMessage.length(), after + 2)) : "";
            }
        }
        if (info.outer == null) return info;
        // signature: outer | root | first two application frames of the root cause (fallback: outer block)
        List<String> sig = new ArrayList<>(2);
        for (int b = frames.size() - 1; b >= 0 && sig.isEmpty(); b--) {
            for (String f : frames.get(b)) {
                if (!isFramework(f)) {
                    sig.add(normalizeFrame(f));
                    if (sig.size() == 2) break;
                }
            }
        }
        if (sig.isEmpty() && !frames.isEmpty() && !frames.getLast().isEmpty()) sig.add(normalizeFrame(frames.getLast().getFirst()));
        info.signature = info.outer + "|" + info.root + "|" + String.join(";", sig);
        if (info.rootMessage != null && info.rootMessage.length() > 300) info.rootMessage = info.rootMessage.substring(0, 300);
        return info;
    }

    private static void codes(CharSequence text, int from, int to, ExceptionInfo info) {
        if (info.codes.size() >= 4 || to - from < 6) return;
        Matcher m = CODE.matcher(text.subSequence(from, Math.min(to, from + 200)));
        if (m.find()) info.codes.add(m.group(1));
    }

    private static int tokenEnd(CharSequence s, int from, int to) {
        int i = from;
        while (i < to && s.charAt(i) != ':' && s.charAt(i) != ' ' && s.charAt(i) != '\t') i++;
        return i;
    }

    private static boolean startsWith(CharSequence s, int from, int to, String p) {
        if (to - from < p.length()) return false;
        for (int k = 0; k < p.length(); k++) if (s.charAt(from + k) != p.charAt(k)) return false;
        return true;
    }
}
