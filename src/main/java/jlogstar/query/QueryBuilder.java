package jlogstar.query;

import jlogstar.analyze.Model;
import jlogstar.index.Fields;
import jlogstar.index.LogAnalyzer;
import jlogstar.ingest.Level;
import org.apache.lucene.document.IntPoint;
import org.apache.lucene.document.LongPoint;
import org.apache.lucene.index.Term;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.*;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Builds Lucene queries from the UI filter: free text in Lucene syntax (default field = full text, AND semantics),
 * plus the pseudo fields group:N, level:WARN (and level:>=WARN), and time range / minimum level / group filters.
 */
public final class QueryBuilder {
    private final Dataset ds;

    public QueryBuilder(Dataset ds) {
        this.ds = ds;
    }

    public static final class Filter {
        public String q;
        public Long from, to;
        public Integer minLevel;
        public List<Integer> groups = new ArrayList<>();
        public List<Integer> excludeGroups = new ArrayList<>();
        public Integer file;
    }

    private static final Pattern LEVEL_GE = Pattern.compile("level:>=?([A-Za-z]+)");
    private static final Pattern LEVEL_EQ = Pattern.compile("level:([A-Za-z]+)");
    private static final Pattern CODE = Pattern.compile("code:(\\S+)");

    public Query build(Filter f) throws ParseException {
        BooleanQuery.Builder b = new BooleanQuery.Builder();
        boolean any = false;
        if (f.q != null && !f.q.isBlank()) {
            String q = f.q.trim();
            // level:>=WARN -> lvl range
            Matcher m = LEVEL_GE.matcher(q);
            StringBuilder sb = new StringBuilder();
            while (m.find()) {
                int lv = Level.parse(m.group(1));
                if (lv >= 0) b.add(IntPoint.newRangeQuery(Fields.LVL, lv, Level.FATAL), BooleanClause.Occur.FILTER);
                m.appendReplacement(sb, "");
                any = true;
            }
            m.appendTail(sb);
            q = sb.toString();
            Matcher m2 = LEVEL_EQ.matcher(q);
            sb = new StringBuilder();
            while (m2.find()) m2.appendReplacement(sb, "level:" + Level.name(Math.max(0, Level.parse(m2.group(1)))));
            m2.appendTail(sb);
            q = sb.toString().trim();
            // message codes are always upper case (WFLYEJB0034, IJ000453)
            Matcher m3 = CODE.matcher(q);
            sb = new StringBuilder();
            while (m3.find()) m3.appendReplacement(sb, Matcher.quoteReplacement("code:" + m3.group(1).toUpperCase(java.util.Locale.ROOT)));
            m3.appendTail(sb);
            q = sb.toString();
            if (!q.isEmpty() && !q.equals("*")) {
                b.add(withPositiveClause(parseLenient(q)), BooleanClause.Occur.MUST);
                any = true;
            }
        }
        if (f.from != null || f.to != null) {
            b.add(LongPoint.newRangeQuery(Fields.TS, f.from == null ? Long.MIN_VALUE : f.from, f.to == null ? Long.MAX_VALUE : f.to - 1),
                    BooleanClause.Occur.FILTER);
            any = true;
        }
        if (f.minLevel != null && f.minLevel > 0) {
            b.add(IntPoint.newRangeQuery(Fields.LVL, f.minLevel, Level.FATAL), BooleanClause.Occur.FILTER);
            any = true;
        }
        if (!f.groups.isEmpty()) {
            b.add(groupQuery(f.groups), BooleanClause.Occur.FILTER);
            any = true;
        }
        if (f.file != null) {
            b.add(IntPoint.newExactQuery(Fields.FILE, f.file), BooleanClause.Occur.FILTER);
            any = true;
        }
        if (!f.excludeGroups.isEmpty()) {
            b.add(groupQuery(f.excludeGroups), BooleanClause.Occur.MUST_NOT);
            if (!any) b.add(new MatchAllDocsQuery(), BooleanClause.Occur.MUST);
            any = true;
        }
        return any ? b.build() : new MatchAllDocsQuery();
    }

    /**
     * Parses Lucene syntax. Log searches often contain paths ("/shop/api/orders") that Lucene would read as a
     * regular expression: if parsing fails, slashes are escaped and parsing is retried.
     */
    Query parseLenient(String q) throws ParseException {
        return new Parser().parse(escapeSlashes(q));
    }

    private static final Pattern REGEX_TERM = Pattern.compile("[+-]?(\\w+:)?/.+/");

    /** Escapes '/' except in whole terms of the form /regex/ (optionally with field: and +/- prefix). */
    static String escapeSlashes(String q) {
        if (q.indexOf('/') < 0) return q;
        StringBuilder sb = new StringBuilder(q.length() + 8);
        for (String part : q.split("(?<=\\s)|(?=\\s)")) {
            if (part.isBlank() || REGEX_TERM.matcher(part).matches()) sb.append(part);
            else sb.append(part.replace("\\/", "/").replace("/", "\\/"));
        }
        return sb.toString();
    }

    private static final Set<String> FIELDS = Set.of(Fields.TEXT, Fields.LOGGER, Fields.THREAD, Fields.CODE, Fields.EX, Fields.LEVEL,
            "group", "g", "file");

    /** "-heartbeat" alone would match nothing in Lucene: purely negative queries mean "everything except". */
    static Query withPositiveClause(Query q) {
        if (q instanceof BooleanQuery bq && !bq.clauses().isEmpty()
                && bq.clauses().stream().allMatch(c -> c.occur() == BooleanClause.Occur.MUST_NOT)) {
            BooleanQuery.Builder b = new BooleanQuery.Builder();
            b.add(new MatchAllDocsQuery(), BooleanClause.Occur.MUST);
            for (BooleanClause c : bq.clauses()) b.add(c);
            return b.build();
        }
        return q;
    }

    public Query groupQuery(Collection<Integer> groups) {
        List<Integer> keys = new ArrayList<>();
        for (int g : groups) {
            Model.Cluster c = ds.clusters.get(g);
            if (c != null) for (int k : c.keys) keys.add(k);
        }
        if (keys.isEmpty()) return new MatchNoDocsQuery();
        return IntPoint.newSetQuery(Fields.KEY, keys.stream().mapToInt(Integer::intValue).toArray());
    }

    private final class Parser extends QueryParser {
        Parser() {
            super(Fields.TEXT, LogAnalyzer.perField());
            setDefaultOperator(Operator.AND);
            setAllowLeadingWildcard(true);
            setSplitOnWhitespace(true);
            setAutoGeneratePhraseQueries(true);
        }

        @Override
        protected Query getFieldQuery(String field, String queryText, boolean quoted) throws ParseException {
            if ("group".equals(field) || "g".equals(field)) {
                try {
                    return groupQuery(List.of(Integer.parseInt(queryText.trim())));
                } catch (NumberFormatException e) {
                    throw new ParseException("group: erwartet eine Gruppennummer");
                }
            }
            if ("file".equals(field)) {
                try {
                    return IntPoint.newExactQuery(Fields.FILE, Integer.parseInt(queryText.trim()));
                } catch (NumberFormatException e) {
                    throw new ParseException("file: erwartet eine Datei-Nummer");
                }
            }
            if (!FIELDS.contains(field)) {
                // "SQLState: 23505" or "java:jboss/datasources/ShopDS" is text, not a field query
                return super.getFieldQuery(Fields.TEXT, field + " " + queryText, true);
            }
            if (Fields.LOGGER.equals(field) || Fields.THREAD.equals(field) || Fields.CODE.equals(field) || Fields.EX.equals(field)
                    || Fields.LEVEL.equals(field)) {
                return new TermQuery(new Term(field, queryText));
            }
            return super.getFieldQuery(field, queryText, quoted);
        }

        @Override
        protected Query getWildcardQuery(String field, String termStr) throws ParseException {
            return FIELDS.contains(field) ? super.getWildcardQuery(field, termStr) : super.getWildcardQuery(Fields.TEXT, termStr);
        }

        @Override
        protected Query getPrefixQuery(String field, String termStr) throws ParseException {
            return FIELDS.contains(field) ? super.getPrefixQuery(field, termStr) : super.getPrefixQuery(Fields.TEXT, termStr);
        }
    }
}
