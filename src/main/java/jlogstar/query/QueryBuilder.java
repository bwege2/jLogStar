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
            if (!q.isEmpty() && !q.equals("*")) {
                Parser p = new Parser();
                b.add(p.parse(q), BooleanClause.Occur.MUST);
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
            if (Fields.LOGGER.equals(field) || Fields.THREAD.equals(field) || Fields.CODE.equals(field) || Fields.EX.equals(field)
                    || Fields.LEVEL.equals(field)) {
                return new TermQuery(new Term(field, queryText));
            }
            return super.getFieldQuery(field, queryText, quoted);
        }
    }
}
