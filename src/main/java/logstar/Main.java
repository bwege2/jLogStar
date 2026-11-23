package logstar;

import logstar.analyze.Analyzer;
import logstar.ingest.Ingestor;
import logstar.query.Dataset;
import logstar.query.SearchService;
import logstar.web.WebServer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;

public final class Main {
    private static void usage() {
        System.out.println("""
                logStar – Java/WildFly log analyzer

                  logstar index  --index DIR [--tz ZONE] [--threads N] <files|dirs…>   index logs (and analyse)
                  logstar analyze --index DIR                                          re-run analysis only
                  logstar serve  --index DIR [--port 7070] [--host 127.0.0.1]          start web UI
                  logstar open   [--index DIR] [--port 7070] [--reindex] <files|dirs…> index if needed, then serve

                Supported: WildFly/JBoss server.log & console.log, Log4j2/Log4j/Logback/Spring Boot patterns,
                JSON lines (log4j2 JsonLayout/JsonTemplateLayout/ECS, WildFly json-formatter); .gz and .zip.
                Default time zone for logs without offset: system zone (--tz Europe/Berlin to override).
                """);
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) { usage(); return; }
        String cmd = args[0];
        Path index = null;
        ZoneId zone = ZoneId.systemDefault();
        int threads = Runtime.getRuntime().availableProcessors();
        int port = 7070;
        String host = "127.0.0.1";
        boolean reindex = false;
        List<Path> inputs = new ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--index", "-i" -> index = Path.of(args[++i]);
                case "--tz" -> zone = ZoneId.of(args[++i]);
                case "--threads" -> threads = Integer.parseInt(args[++i]);
                case "--port", "-p" -> port = Integer.parseInt(args[++i]);
                case "--host" -> host = args[++i];
                case "--reindex" -> reindex = true;
                default -> inputs.add(Path.of(args[i]));
            }
        }
        switch (cmd) {
            case "index" -> {
                require(index != null && !inputs.isEmpty(), "index needs --index DIR and inputs");
                doIndex(index, zone, threads, inputs);
            }
            case "analyze" -> {
                require(index != null, "analyze needs --index DIR");
                new Analyzer(index, threads).run();
            }
            case "serve" -> {
                require(index != null, "serve needs --index DIR");
                serve(index, threads, host, port);
            }
            case "open" -> {
                require(!inputs.isEmpty(), "open needs inputs");
                if (index == null) index = defaultIndexFor(inputs.getFirst());
                if (reindex || !Files.exists(index.resolve("analysis.json"))) doIndex(index, zone, threads, inputs);
                else System.out.println("Using existing index " + index + " (--reindex to rebuild)");
                serve(index, threads, host, port);
            }
            default -> usage();
        }
    }

    private static Path defaultIndexFor(Path input) {
        Path abs = input.toAbsolutePath().normalize();
        Path dir = Files.isDirectory(abs) ? abs : abs.getParent();
        return dir.resolve(".logstar-index");
    }

    private static void require(boolean ok, String msg) {
        if (!ok) {
            System.err.println(msg);
            usage();
            System.exit(2);
        }
    }

    private static void doIndex(Path index, ZoneId zone, int threads, List<Path> inputs) throws Exception {
        System.out.println("Indexing into " + index + " with " + threads + " threads (zone " + zone + ")");
        new Ingestor(index, zone, threads).run(inputs);
        new Analyzer(index, threads).run();
    }

    private static void serve(Path index, int threads, String host, int port) throws Exception {
        Dataset ds = new Dataset(index, threads);
        WebServer ws = new WebServer(new SearchService(ds));
        ws.start(host, port);
        System.out.printf("logStar: %,d events – http://%s:%d/%n", ds.meta.events, host.equals("0.0.0.0") ? "localhost" : host, port);
        Thread.currentThread().join();
    }
}
