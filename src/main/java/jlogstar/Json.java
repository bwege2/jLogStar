package jlogstar;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class Json {
    public static final ObjectMapper M = new ObjectMapper()
            .setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.NONE)
            .setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.PUBLIC_ONLY)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);

    private Json() {}

    public static void write(Path p, Object o) throws IOException {
        Path tmp = p.resolveSibling(p.getFileName() + ".tmp");
        try (var out = new java.io.BufferedOutputStream(Files.newOutputStream(tmp), 1 << 16)) {
            M.writeValue(out, o);
        }
        Files.move(tmp, p, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    public static <T> T read(Path p, Class<T> c) throws IOException {
        try (var in = new java.io.BufferedInputStream(Files.newInputStream(p), 1 << 16)) {
            return M.readValue(in, c);
        }
    }

    public static <T> T read(Path p, com.fasterxml.jackson.core.type.TypeReference<T> t) throws IOException {
        try (var in = new java.io.BufferedInputStream(Files.newInputStream(p), 1 << 16)) {
            return M.readValue(in, t);
        }
    }
}
