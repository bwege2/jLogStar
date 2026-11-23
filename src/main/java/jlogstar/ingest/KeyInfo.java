package jlogstar.ingest;

/** One distinct template key: level + logger + masked message + exception signature. */
public final class KeyInfo {
    public int id;
    public int level;
    public String logger;
    public String template;
    public String code;
    public String exOuter;
    public String exRoot;
    public String exSig;
    public String exClasses;
    public String sample;
    public String rootMessage;

    public KeyInfo() {}
}
