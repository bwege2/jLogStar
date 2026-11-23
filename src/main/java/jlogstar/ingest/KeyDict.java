package jlogstar.ingest;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/** Thread-safe dictionary assigning dense ids to template keys. */
public final class KeyDict {
    public static final int MAX_KEYS = 400_000;
    private final ConcurrentHashMap<String, KeyInfo> map = new ConcurrentHashMap<>();
    private final List<KeyInfo> byId = new ArrayList<>();

    public KeyInfo get(String key) {
        return map.get(key);
    }

    public KeyInfo add(String key, KeyInfo proto) {
        return map.computeIfAbsent(key, k -> {
            synchronized (byId) {
                proto.id = byId.size();
                byId.add(proto);
            }
            return proto;
        });
    }

    public int size() {
        return map.size();
    }

    public List<KeyInfo> all() {
        synchronized (byId) {
            return new ArrayList<>(byId);
        }
    }
}
