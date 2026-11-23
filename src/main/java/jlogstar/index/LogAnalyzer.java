package jlogstar.index;

import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.LowerCaseFilter;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.Tokenizer;
import org.apache.lucene.analysis.core.KeywordAnalyzer;
import org.apache.lucene.analysis.miscellaneous.PerFieldAnalyzerWrapper;
import org.apache.lucene.analysis.util.CharTokenizer;

import java.util.Map;

/**
 * Tokenises log text on everything that is not a letter or digit, so that java.lang.NullPointerException is
 * findable as "NullPointerException", as the phrase "java.lang.NullPointerException" and IJ000453 stays one token.
 */
public final class LogAnalyzer extends Analyzer {
    @Override
    protected TokenStreamComponents createComponents(String fieldName) {
        Tokenizer t = new CharTokenizer() {
            @Override
            protected boolean isTokenChar(int c) {
                return Character.isLetterOrDigit(c) || c == '_';
            }
        };
        TokenStream ts = new LowerCaseFilter(t);
        return new TokenStreamComponents(t, ts);
    }

    @Override
    protected TokenStream normalize(String fieldName, TokenStream in) {
        return new LowerCaseFilter(in);
    }

    public static Analyzer perField() {
        KeywordAnalyzer kw = new KeywordAnalyzer();
        return new PerFieldAnalyzerWrapper(new LogAnalyzer(), Map.of(
                Fields.LEVEL, kw, Fields.LOGGER, kw, Fields.THREAD, kw, Fields.CODE, kw, Fields.EX, kw));
    }
}
