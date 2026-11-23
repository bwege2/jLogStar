package logstar.analyze;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Persisted analysis results (analysis.json). */
public final class Model {
    private Model() {}

    public static final class Cluster {
        public int id;
        public int[] keys;
        public int level;
        public String logger;
        public String template;
        public String code;
        public String exOuter;
        public String exRoot;
        public String exClasses;
        public String subsystem;
        public String category;
        public String sample;
        public String rootMessage;
        public long count;
        public long first;
        public long last;
        public int severity;            // 0..100 from rules
        public List<String> rules = new ArrayList<>();
        public List<String> flags = new ArrayList<>(); // NEW, SPIKE, CRIT, SILENT
    }

    public static final class Anomaly {
        public String type;      // spike, error-rate, new, silence, silenced, crash, start-errors, known
        public int score;        // 0..100
        public String title;
        public String detail;
        public long from;
        public long to;
        public List<Integer> clusters = new ArrayList<>();
        public Map<String, Object> metrics = new LinkedHashMap<>();
        public Integer incident;
    }

    /** Anomalies that overlap in time, presented as one event ("what happened at 09:44"). */
    public static final class Incident {
        public int id;
        public int score;
        public String title;
        public long from;
        public long to;
        public List<String> types = new ArrayList<>();
        public List<Integer> anomalies = new ArrayList<>(); // indices into Analysis.anomalies
        public List<Integer> clusters = new ArrayList<>();
        public String firstSignal;
        public long firstSignalTs;
    }

    public static final class Marker {
        public String type;      // start, started, stop, deploy, undeploy
        public long ts;
        public String text;

        public Marker() {}

        public Marker(String type, long ts, String text) {
            this.type = type; this.ts = ts; this.text = text;
        }
    }

    public static final class Analysis {
        public long bucketMs;
        public long start;
        public long end;
        public int[] volume;
        public int[] errors;
        public int[] warnings;
        public int[] keyToCluster;
        public List<Cluster> clusters = new ArrayList<>();
        public List<Anomaly> anomalies = new ArrayList<>();
        public List<Marker> markers = new ArrayList<>();
        public List<Incident> incidents = new ArrayList<>();
        public long analyzeMs;
    }
}
