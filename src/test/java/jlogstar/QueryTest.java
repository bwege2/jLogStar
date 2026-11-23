package jlogstar;

import jlogstar.query.QueryBuilder;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class QueryTest {
    final QueryBuilder qb = new QueryBuilder(null);

    String q(String s) throws Exception {
        QueryBuilder.Filter f = new QueryBuilder.Filter();
        f.q = s;
        return qb.build(f).toString();
    }

    @Test
    void textIsTokenisedLikeLogs() throws Exception {
        assertEquals("+text:\"java lang nullpointerexception\"", q("java.lang.NullPointerException"));
        assertEquals("+text:\"read timed out\"", q("\"Read timed out\""));
        assertEquals("+text:ij000453", q("IJ000453"));
    }

    @Test
    void pathsAndColonsAreText() throws Exception {
        assertEquals("+text:\"shop api orders\"", q("/shop/api/orders"));
        assertEquals("+text:\"sqlstate 23505\"", q("SQLState: 23505"));
        assertEquals("+text:\"java jboss datasources shopds\"", q("java:jboss/datasources/ShopDS"));
        assertTrue(q("/time[dr]?out/").contains("/time[dr]?out/"), "real regex stays a regex");
    }

    @Test
    void fields() throws Exception {
        assertEquals("+code:IJ000453", q("code:ij000453"));
        assertEquals("+logger:com.acme*", q("logger:com.acme*"));
        assertEquals("+ex:NullPointerException", q("ex:NullPointerException"));
        assertEquals("+thread:default task-12", q("thread:\"default task-12\""));
        assertEquals("+level:ERROR", q("level:error"));
        assertEquals("#lvl:[3 TO 5]", q("level:>=WARN"));
    }

    @Test
    void negativeOnlyMeansEverythingExcept() throws Exception {
        assertEquals("+(+*:* -text:heartbeat)", q("-heartbeat"));
        assertEquals("+(+text:timeout -text:socket)", q("timeout -socket"));
    }
}
