package jlogstar.analyze;

import jlogstar.ingest.ExceptionInfo;
import jlogstar.ingest.KeyInfo;
import jlogstar.ingest.Masker;

import java.util.*;

/**
 * Drain-style merge of template keys: keys with same level, logger, exception signature and token count are merged
 * when at least SIM of their tokens are equal; differing positions become <*>.
 * Works on distinct keys (not events), so it is cheap even for huge logs.
 */
public final class Clusterer {
    static final double SIM = 0.7;
    static final int MAX_CLUSTERS_PER_GROUP = 300;

    static final class Proto {
        String[] tokens;
        List<Integer> keys = new ArrayList<>();
    }

    /** Returns keyToCluster mapping; fills clusters (id, keys, template). */
    public static int[] cluster(List<KeyInfo> keys, long[] keyCount, List<Model.Cluster> out) {
        Map<String, List<Integer>> groups = new HashMap<>();
        for (KeyInfo k : keys) {
            if (keyCount[k.id] == 0) continue;
            String[] toks = k.template.split(" ");
            String g = k.level + "\u0001" + k.logger + "\u0001" + k.exSig + "\u0001" + toks.length;
            groups.computeIfAbsent(g, x -> new ArrayList<>()).add(k.id);
        }
        int[] k2c = new int[keys.size()];
        Arrays.fill(k2c, -1);
        for (List<Integer> ids : groups.values()) {
            ids.sort((a, b) -> Long.compare(keyCount[b], keyCount[a]));
            List<Proto> protos = new ArrayList<>();
            for (int id : ids) {
                String[] toks = keys.get(id).template.split(" ");
                Proto best = null;
                double bestSim = -1;
                if (toks.length > 1) {
                    for (Proto p : protos) {
                        double s = sim(p.tokens, toks);
                        if (s > bestSim) { bestSim = s; best = p; }
                    }
                }
                if (best != null && bestSim >= SIM) {
                    for (int i = 0; i < toks.length; i++) if (!best.tokens[i].equals(toks[i])) best.tokens[i] = Masker.WILD;
                    best.keys.add(id);
                } else if (protos.size() < MAX_CLUSTERS_PER_GROUP || toks.length <= 1) {
                    Proto p = new Proto();
                    p.tokens = toks.clone();
                    p.keys.add(id);
                    protos.add(p);
                } else {
                    // too many distinct shapes: attach to closest
                    if (best == null) best = protos.getFirst();
                    for (int i = 0; i < toks.length; i++) if (!best.tokens[i].equals(toks[i])) best.tokens[i] = Masker.WILD;
                    best.keys.add(id);
                }
            }
            for (Proto p : protos) {
                Model.Cluster c = new Model.Cluster();
                c.id = out.size();
                c.keys = p.keys.stream().mapToInt(Integer::intValue).toArray();
                c.template = String.join(" ", p.tokens);
                out.add(c);
                for (int k : c.keys) k2c[k] = c.id;
            }
        }
        return k2c;
    }

    private static double sim(String[] a, String[] b) {
        if (!a[0].equals(b[0]) && !a[0].equals(Masker.WILD) && !b[0].equals(Masker.WILD)) return 0;
        int eq = 0;
        for (int i = 0; i < a.length; i++) {
            if (a[i].equals(b[i]) || a[i].equals(Masker.WILD)) eq++;
            else if (isCode(a[i]) || isCode(b[i]) || hasDigit(a[i]) || hasDigit(b[i])) return 0; // codes never merge
        }
        return (double) eq / a.length;
    }

    /** Digits that survived masking are deliberate (SQLState, HTTP status, identifiers). */
    private static boolean hasDigit(String t) {
        if (t.contains(Masker.WILD) || t.length() > 12) return false;
        for (int i = 0; i < t.length(); i++) if (Character.isDigit(t.charAt(i))) return true;
        return false;
    }

    private static boolean isCode(String t) {
        return t.length() >= 5 && ExceptionInfo.CODE.matcher(t).matches();
    }
}
