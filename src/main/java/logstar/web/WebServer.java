package logstar.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import logstar.Json;
import logstar.query.QueryBuilder;
import logstar.query.SearchService;
import org.apache.lucene.queryparser.classic.ParseException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.zip.GZIPOutputStream;

/** Embedded HTTP server: JSON API under /api, static single-page UI from classpath /web. */
public final class WebServer {
    private final SearchService svc;
    private HttpServer server;

    public WebServer(SearchService svc) {
        this.svc = svc;
    }

    public void start(String host, int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress(host, port), 64);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.createContext("/api/", this::api);
        server.createContext("/", this::stat);
        server.start();
    }

    private static Map<String, String> params(HttpExchange ex) {
        Map<String, String> m = new HashMap<>();
        String q = ex.getRequestURI().getRawQuery();
        if (q == null) return m;
        for (String p : q.split("&")) {
            int i = p.indexOf('=');
            if (i < 0) m.put(URLDecoder.decode(p, StandardCharsets.UTF_8), "");
            else m.put(URLDecoder.decode(p.substring(0, i), StandardCharsets.UTF_8), URLDecoder.decode(p.substring(i + 1), StandardCharsets.UTF_8));
        }
        return m;
    }

    private static Long lng(Map<String, String> p, String k) {
        String v = p.get(k);
        return v == null || v.isBlank() ? null : Long.parseLong(v);
    }

    private static List<Integer> ints(String v) {
        List<Integer> out = new ArrayList<>();
        if (v == null || v.isBlank()) return out;
        for (String s : v.split(",")) if (!s.isBlank()) out.add(Integer.parseInt(s.trim()));
        return out;
    }

    static QueryBuilder.Filter filter(Map<String, String> p) {
        QueryBuilder.Filter f = new QueryBuilder.Filter();
        f.q = p.get("q");
        f.from = lng(p, "from");
        f.to = lng(p, "to");
        String ml = p.get("minLevel");
        if (ml != null && !ml.isBlank()) f.minLevel = Integer.parseInt(ml);
        f.groups = ints(p.get("groups"));
        f.excludeGroups = ints(p.get("exclude"));
        String file = p.get("file");
        if (file != null && !file.isBlank()) f.file = Integer.parseInt(file);
        return f;
    }

    private void api(HttpExchange ex) throws IOException {
        try (ex) {
            Map<String, String> p = params(ex);
            String path = ex.getRequestURI().getPath();
            Object result;
            int status = 200;
            try {
                result = switch (path) {
                    case "/api/info" -> svc.info();
                    case "/api/overview" -> svc.overview(filter(p));
                    case "/api/events" -> svc.events(filter(p), "asc".equals(p.get("order")), p.get("cursor"),
                            Integer.parseInt(p.getOrDefault("limit", "100")));
                    case "/api/context" -> svc.context(Integer.parseInt(p.get("doc")), Integer.parseInt(p.getOrDefault("n", "25")));
                    case "/api/group" -> svc.group(Integer.parseInt(p.get("id")), filter(p));
                    case "/api/correlate" -> svc.correlate(Long.parseLong(p.get("from")), Long.parseLong(p.get("to")),
                            Long.parseLong(p.getOrDefault("lead", "1800000")));
                    default -> {
                        status = 404;
                        yield Map.of("error", "unknown endpoint " + path);
                    }
                };
            } catch (ParseException | NumberFormatException | NoSuchElementException e) {
                status = 400;
                result = Map.of("error", "Ungültige Anfrage: " + firstLine(e.getMessage()));
            } catch (Exception e) {
                e.printStackTrace();
                status = 500;
                result = Map.of("error", e.getClass().getSimpleName() + ": " + firstLine(e.getMessage()));
            }
            byte[] body = Json.M.writeValueAsBytes(result);
            send(ex, status, "application/json; charset=utf-8", body);
        }
    }

    private static String firstLine(String s) {
        if (s == null) return "";
        int i = s.indexOf('\n');
        return i > 0 ? s.substring(0, i) : s;
    }

    private static void send(HttpExchange ex, int status, String type, byte[] body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", type);
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        String ae = ex.getRequestHeaders().getFirst("Accept-Encoding");
        if (body.length > 2048 && ae != null && ae.contains("gzip")) {
            ex.getResponseHeaders().set("Content-Encoding", "gzip");
            ex.sendResponseHeaders(status, 0);
            try (OutputStream os = new GZIPOutputStream(ex.getResponseBody(), 1 << 16)) {
                os.write(body);
            }
        } else {
            ex.sendResponseHeaders(status, body.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(body);
            }
        }
    }

    private static final Map<String, String> TYPES = Map.of("html", "text/html; charset=utf-8", "js", "text/javascript; charset=utf-8",
            "css", "text/css; charset=utf-8", "svg", "image/svg+xml", "png", "image/png", "ico", "image/x-icon");

    private void stat(HttpExchange ex) throws IOException {
        try (ex) {
            String path = ex.getRequestURI().getPath();
            if (path.equals("/") || path.isEmpty()) path = "/index.html";
            if (path.contains("..")) {
                send(ex, 400, "text/plain", "bad path".getBytes());
                return;
            }
            try (InputStream in = WebServer.class.getResourceAsStream("/web" + path)) {
                if (in == null) {
                    send(ex, 404, "text/plain", "not found".getBytes());
                    return;
                }
                String ext = path.substring(path.lastIndexOf('.') + 1);
                send(ex, 200, TYPES.getOrDefault(ext, "application/octet-stream"), in.readAllBytes());
            }
        }
    }
}
