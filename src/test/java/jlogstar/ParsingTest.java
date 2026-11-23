package jlogstar;

import jlogstar.ingest.*;
import org.junit.jupiter.api.Test;

import java.time.*;
import java.util.regex.Matcher;

import static org.junit.jupiter.api.Assertions.*;

class ParsingTest {
    final ZoneId berlin = ZoneId.of("Europe/Berlin");

    long ts(String s) {
        TsParser p = new TsParser(berlin);
        TsParser.Result r = new TsParser.Result();
        assertTrue(p.parse(s, 0, r), s);
        return r.epochMs;
    }

    @Test
    void timestamps() {
        long expect = LocalDateTime.of(2026, 11, 20, 10, 23, 45, 123_000_000).atZone(berlin).toInstant().toEpochMilli();
        assertEquals(expect, ts("2026-11-20 10:23:45,123 ERROR [x] (y) z"));
        assertEquals(expect, ts("2026-11-20T10:23:45.123 [main] INFO a - b"));
        assertEquals(expect, ts("[2026-11-20 10:23:45.123] INFO"));
        assertEquals(expect, ts("20.11.2026 10:23:45,123 INFO"));
        assertEquals(expect, ts("20 Nov 2026 10:23:45,123 INFO"));
        assertEquals(expect, ts("20-Nov-2026 10:23:45.123 INFO"));
        assertEquals(Instant.parse("2026-11-20T10:23:45.123Z").toEpochMilli(), ts("2026-11-20T10:23:45.123Z INFO"));
        assertEquals(Instant.parse("2026-11-20T09:23:45.123Z").toEpochMilli(), ts("2026-11-20T10:23:45.123+01:00 INFO"));
        TsParser p = new TsParser(berlin);
        TsParser.Result r = new TsParser.Result();
        assertTrue(p.parse("10:23:45,123 INFO  [org.jboss] (main) x", 0, r));
        assertTrue(r.timeOnly);
        assertEquals((10 * 3600 + 23 * 60 + 45) * 1000L + 123, r.msOfDay);
        assertFalse(p.parse("\tat com.acme.Foo.bar(Foo.java:12)", 0, r));
        assertFalse(p.parse("12345 something", 0, r));
        assertFalse(p.parse("2026-11-20 is a date", 0, r));
    }

    @Test
    void masking() {
        assertEquals("Order <*> placed by user u<*> in <*>ms", Masker.mask("Order 4711 placed by user u123 in 87ms"));
        assertEquals("WFLYEJB0034: Invocation failed on component OrderService", Masker.mask("WFLYEJB0034: Invocation failed on component OrderService"));
        assertEquals("IJ000453: Unable to get managed connection for java:jboss/datasources/ShopDS",
                Masker.mask("IJ000453: Unable to get managed connection for java:jboss/datasources/ShopDS"));
        assertEquals("session <*> from <*>:<*>", Masker.mask("session 550e8400-e29b-41d4-a716-446655440000 from 192.168.10.12:8080"));
        assertEquals("GET /api/orders/<*> took <*> ms", Masker.mask("GET /api/orders/123456 took 12.5 ms"));
        assertEquals("Deployed \"shop.war\" (runtime-name : \"shop.war\")", Masker.mask("Deployed \"shop.war\" (runtime-name : \"shop.war\")"));
        assertEquals("User <*> logged in (session <*>)", Masker.mask("User x logged in (session ROfbikww754EF0tWIVWwKcre_SxAsdd3zazxkuq6)").replaceFirst("User x", "User <*>"));
        assertEquals("SQL Error: 0, SQLState: 23505", Masker.mask("SQL Error: 0, SQLState: 23505"));
        assertEquals("Using Log4j2 with Lucene104Codec", Masker.mask("Using Log4j2 with Lucene104Codec"));
        assertEquals("[default task-<*>] value=<*>", Masker.mask("[default task-12] value=42"));
        assertEquals("POST /shop/api/orders -> <*> (<*> ms) user=miamey<*> ip=<*> session=<*>",
                Masker.mask("POST /shop/api/orders -> 201 (87 ms) user=miamey12 ip=10.1.2.3 session=kpvBAaVvubsYCJA_Z3XTIg9_AA1p2UhXgUnkA_"));
        assertEquals("GET /shop/api/cart/<*> -> <*>", Masker.mask("GET /shop/api/cart/5f0c2a1e-9b7d-4c1a-ac3e-b1d2e3f40a5c -> 200"));
        assertEquals("ShopDS: getConnection(null, WrappedConnectionRequestInfo@<*>[userName=shop]) [<*>/<*>]",
                Masker.mask("ShopDS: getConnection(null, WrappedConnectionRequestInfo@c3c4be12[userName=shop]) [12/20]"));
    }

    @Test
    void exceptions() {
        String text = """
                2026-11-20 10:23:45,123 ERROR [org.jboss.as.ejb3.invocation] (default task-12) WFLYEJB0034: Invocation failed
                jakarta.ejb.EJBException: boom
                \tat org.jboss.as.ejb3.tx.CMTTxInterceptor.handleExceptionInOurTx(CMTTxInterceptor.java:139)
                \tat com.acme.shop.OrderService$$Lambda/0x000071.place(OrderService.java:42)
                \tat java.base/java.lang.Thread.run(Thread.java:1583)
                Caused by: java.lang.NullPointerException: Cannot invoke "Customer.getAddress()" because "customer" is null
                \tat com.acme.shop.checkout.ShippingCalculator.calc(ShippingCalculator.java:77)
                \tat com.acme.shop.checkout.CheckoutBean.checkout(CheckoutBean.java:31)
                \tat org.jboss.weld.Foo.bar(Foo.java:1)
                \t... 42 more
                """;
        int body = text.indexOf('\n');
        ExceptionInfo ex = ExceptionInfo.parse(text, body, "WFLYEJB0034: Invocation failed");
        assertEquals("jakarta.ejb.EJBException", ex.outer);
        assertEquals("java.lang.NullPointerException", ex.root);
        assertEquals("jakarta.ejb.EJBException|java.lang.NullPointerException|com.acme.shop.checkout.ShippingCalculator.calc;com.acme.shop.checkout.CheckoutBean.checkout", ex.signature);
        assertTrue(ex.rootMessage.startsWith("Cannot invoke"));

        ExceptionInfo inline = ExceptionInfo.parse("x", 1, "Call failed: java.net.SocketTimeoutException: Read timed out");
        assertEquals("java.net.SocketTimeoutException", inline.root);
    }

    RawEvent parse(String layoutName, String line) {
        TsParser p = new TsParser(berlin);
        TsParser.Result r = new TsParser.Result();
        assertTrue(p.parse(line, 0, r));
        RawEvent ev = new RawEvent();
        Layout l = FormatDetector.layoutByName(layoutName);
        assertTrue(l.parse(line, r.end, ev, new Matcher[1], 0), layoutName + ": " + line);
        return ev;
    }

    @Test
    void layouts() {
        RawEvent e = parse("jboss", "2026-11-20 10:23:45,123 ERROR [org.jboss.as.ejb3.invocation] (default task-12) WFLYEJB0034: x (y)");
        assertEquals(Level.ERROR, e.level);
        assertEquals("org.jboss.as.ejb3.invocation", e.logger);
        assertEquals("default task-12", e.thread);
        assertEquals("WFLYEJB0034: x (y)", e.message);
        e = parse("jboss", "2026-11-20 10:23:45,123 INFO  [org.jboss.as] (ServerService Thread Pool -- 75) WFLYSRV0049: start");
        assertEquals("ServerService Thread Pool -- 75", e.thread);
        e = parse("thread-level-logger", "2026-11-20 10:23:45.123 [pool-3-thread-1] WARN  com.acme.shop.Foo - slow query 1234 ms");
        assertEquals(Level.WARN, e.level);
        assertEquals("com.acme.shop.Foo", e.logger);
        assertEquals("pool-3-thread-1", e.thread);
        assertEquals("slow query 1234 ms", e.message);
        e = parse("level-thread-logger", "2026-11-20 10:23:45,123 ERROR [main] com.acme.App - failed");
        assertEquals("main", e.thread);
        assertEquals("com.acme.App", e.logger);
        e = parse("spring", "2026-11-20T10:23:45.123+01:00  INFO 4711 --- [demo] [           main] com.acme.DemoApp                       : Started DemoApp in 2.1 seconds");
        assertEquals("main", e.thread);
        assertEquals("com.acme.DemoApp", e.logger);
    }
}
