package logstar.analyze;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/** Built-in knowledge about typical Java EE / WildFly failure patterns. */
public final class Rules {
    public record Rule(String id, int severity, String title, Pattern match, String explanation, String advice) {}

    private static Pattern p(String regex) {
        return Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    }

    public static final List<Rule> RULES = List.of(
            new Rule("oom", 95, "Speicher erschöpft (OutOfMemoryError)", p("OutOfMemoryError|GC overhead limit exceeded|Java heap space|Metaspace|unable to create (new )?native thread"),
                    "Die JVM hat keinen Speicher mehr. Danach ist der Zustand des Servers unzuverlässig, häufig folgt ein Absturz/Neustart.",
                    "Heap-Dump (-XX:+HeapDumpOnOutOfMemoryError) analysieren, Speicherverlauf/GC-Logs prüfen, Leaks (Caches, Sessions) suchen."),
            new Rule("files", 90, "Zu viele offene Dateien", p("Too many open files"),
                    "Das Betriebssystem-Limit für Datei-/Socket-Handles ist erreicht.", "ulimit -n prüfen, Socket-/Stream-Leaks suchen."),
            new Rule("pool", 85, "Datenbank-Connection-Pool erschöpft", p("IJ000453|IJ000655|Unable to get managed connection|No managed connections available|Connection is not available, request timed out|Unable to acquire JDBC Connection"),
                    "Alle Verbindungen des Datasource-Pools sind belegt; neue Anfragen warten bis zum Timeout und schlagen fehl.",
                    "Langsame Queries / lange Transaktionen davor suchen, Connection-Leaks prüfen (IJ000100 / cached-connection-manager debug), max-pool-size."),
            new Rule("db", 75, "Datenbankverbindung gestört", p("JDBCConnectionException|SQLTransientConnectionException|SQLRecoverableException|Communications link failure|Connection refused.*(5432|3306|1521|1433)|I/O error.*(database|connection)|PSQLException: An I/O error|IJ000609|IJ031041"),
                    "Die Verbindung zur Datenbank ist abgebrochen oder nicht herstellbar.", "DB-Verfügbarkeit, Netzwerk, Failover und Validierung (validate-on-match / background-validation) prüfen."),
            new Rule("txtimeout", 75, "Transaktions-Timeout", p("ARJUNA012117|ARJUNA012121|ARJUNA012095|ARJUNA012108|TransactionReaper|Transaction timeout|transaction is not active|ARJUNA016063"),
                    "Transaktionen laufen länger als das Timeout und werden vom Transaction Reaper abgebrochen.",
                    "Langlaufende Methoden/Queries finden (Thread des Reapers nennt den Thread), Timeout nicht einfach nur erhöhen."),
            new Rule("deadlock", 80, "Deadlock / Sperrkonflikt", p("deadlock|LockAcquisitionException|CannotAcquireLockException|PessimisticLockException|lock wait timeout|ORA-00060|could not obtain lock"),
                    "Parallele Transaktionen sperren sich gegenseitig.", "Zugriffsreihenfolge vereinheitlichen, Transaktionen verkürzen, Indizes prüfen."),
            new Rule("stackoverflow", 80, "StackOverflowError (Endlosrekursion)", p("StackOverflowError"),
                    "Eine Rekursion terminiert nicht (oft zyklische Objektgraphen beim Serialisieren / toString / equals).", "Stacktrace auf wiederholende Frames prüfen."),
            new Rule("ejbpool", 75, "EJB-/Thread-Pool erschöpft", p("Failed to acquire a permit|WFLYEJB0378|RejectedExecutionException|Thread pool is exhausted|Task .* rejected|UT005019|WFLYEJB0241|max-threads"),
                    "Es stehen keine Worker-/Bean-Instanzen mehr zur Verfügung, Anfragen werden abgelehnt.", "Blockierende Aufrufe (DB, extern) als Ursache suchen; Pool-Größen erst danach anpassen."),
            new Rule("deploy", 80, "Deployment / Service-Start fehlgeschlagen", p("WFLYCTL0013|WFLYCTL0186|WFLYCTL0448|WFLYSRV0026|WFLYCTL0180|WFLYCTL0412|Deployment .* failed|MSC000001|Services with missing/unavailable dependencies"),
                    "Ein Deployment oder ein Server-Dienst konnte nicht starten.", "Erste Fehlermeldung des Starts lesen (fehlende Abhängigkeit, Konfiguration, Klassen)."),
            new Rule("classload", 70, "Klassenlade-Problem", p("ClassNotFoundException|NoClassDefFoundError|NoSuchMethodError|NoSuchFieldError|IncompatibleClassChangeError|LinkageError|ClassCastException.*cannot be cast.*(loaded by|ModuleClassLoader)"),
                    "Bibliotheken fehlen, sind doppelt vorhanden oder in falscher Version.", "jboss-deployment-structure.xml, Module und WEB-INF/lib auf Duplikate prüfen."),
            new Rule("tls", 70, "TLS / Zertifikat", p("SSLHandshakeException|CertificateExpiredException|PKIX path building failed|unable to find valid certification path|SSLException"),
                    "TLS-Handshake fehlgeschlagen: Zertifikat abgelaufen, unbekannte CA oder Protokoll-Mismatch.", "Truststore, Zertifikatslaufzeiten und Cipher/Protokolle prüfen."),
            new Rule("cluster", 60, "Cluster / Infinispan", p("ISPN000136|ISPN000476|SuspectException|ISPN000094|JGRP|split brain|ClusterTopology|TimeoutException.*(Infinispan|ISPN)"),
                    "Probleme in Cluster-Kommunikation oder verteiltem Cache.", "Netzwerk zwischen Knoten, JGroups-Konfiguration, Lock-Timeouts prüfen."),
            new Rule("refused", 60, "Verbindung abgelehnt", p("ConnectException|Connection refused|No route to host|UnknownHostException|HttpHostConnectException"),
                    "Ein Zielsystem ist nicht erreichbar.", "Erreichbarkeit/DNS/Firewall des Zielsystems prüfen."),
            new Rule("timeout", 55, "Timeout bei externem Aufruf", p("SocketTimeoutException|Read timed out|connect timed out|ConnectTimeoutException|ProcessingException.*timeout|TimeoutException|UT000128"),
                    "Ein externer Aufruf (REST, SOAP, DB, Cache) hat nicht rechtzeitig geantwortet.", "Antwortzeiten des Zielsystems prüfen, Timeouts und Circuit-Breaker konfigurieren."),
            new Rule("npe", 50, "NullPointerException", p("NullPointerException"),
                    "Programmierfehler: Zugriff auf null. Neu auftretende NPEs deuten oft auf eine Regression oder unerwartete Daten hin.", "App-Frame im Stacktrace ansehen; Datenzustand prüfen."),
            new Rule("rollback", 50, "Transaktion zurückgerollt", p("RollbackException|EJBTransactionRolledbackException|TransactionRolledbackLocalException|ARJUNA016053|marked for rollback"),
                    "Die Transaktion wurde (meist wegen einer vorherigen Exception) zurückgerollt.", "Die ursprüngliche Exception im selben Thread kurz davor suchen."),
            new Rule("optimistic", 45, "Optimistische Sperre", p("OptimisticLockException|StaleObjectStateException|StaleStateException|Row was updated or deleted by another transaction"),
                    "Gleichzeitige Änderung desselben Datensatzes.", "Meist fachlich zu behandeln (Retry / Hinweis an Benutzer)."),
            new Rule("lazy", 45, "LazyInitializationException", p("LazyInitializationException|could not initialize proxy"),
                    "Zugriff auf nicht geladene JPA-Beziehung außerhalb der Session/Transaktion.", "Fetch-Strategie / Entity-Graph oder DTO-Projektion verwenden."),
            new Rule("constraint", 35, "Constraint-Verletzung", p("ConstraintViolationException|SQLState: 23|duplicate key|unique constraint|integrity constraint|ORA-00001"),
                    "Daten verletzen eine DB-Bedingung (Unique, FK, Not-Null).", "Fachliche Validierung vor dem Speichern, Idempotenz von Requests prüfen."),
            new Rule("clientabort", 15, "Client hat Verbindung abgebrochen", p("Broken pipe|Connection reset by peer|ClientAbortException|UT010029|An established connection was aborted|EofException"),
                    "Der Client hat die Verbindung geschlossen, bevor die Antwort fertig war. Meist harmlos, in Massen ein Hinweis auf langsame Antworten.", "Nur relevant, wenn gehäuft: dann Antwortzeiten prüfen.")
    );

    public static String haystack(Model.Cluster c) {
        StringBuilder sb = new StringBuilder(256);
        sb.append(c.template).append(' ');
        if (c.code != null) sb.append(c.code).append(' ');
        if (c.exClasses != null) sb.append(c.exClasses).append(' ');
        if (c.rootMessage != null) sb.append(c.rootMessage).append(' ');
        if (c.sample != null) sb.append(c.sample);
        return sb.toString();
    }

    // ----------------------------------------------------------------------------------- subsystems

    private static final String[][] CODE_SUBSYSTEM = {
            {"WFLYSRV", "Server"}, {"WFLYCTL", "Server"}, {"WFLYDS", "Server"}, {"WFLYDR", "Server"}, {"WFLYEE", "Server"},
            {"WFLYEJB", "EJB"}, {"WFLYJCA", "Datasource/JCA"}, {"IJ", "Datasource/JCA"}, {"ARJUNA", "Transaktionen"}, {"WFLYTX", "Transaktionen"},
            {"HHH", "Hibernate/JPA"}, {"WFLYJPA", "Hibernate/JPA"}, {"WFLYUT", "Undertow/Web"}, {"UT", "Undertow/Web"},
            {"RESTEASY", "REST"}, {"ISPN", "Infinispan/Cluster"}, {"WFLYCLINF", "Infinispan/Cluster"}, {"JGRP", "Infinispan/Cluster"},
            {"WFLYCLSV", "Infinispan/Cluster"}, {"WFLYWELD", "CDI/Weld"}, {"WELD", "CDI/Weld"}, {"WFLYSEC", "Security"}, {"ELY", "Security"},
            {"WFLYELY", "Security"}, {"WFLYMSG", "Messaging"}, {"WFLYMSGAMQ", "Messaging"}, {"AMQ", "Messaging"}, {"WFLYNAM", "JNDI"},
            {"WFLYIO", "Remoting/IO"}, {"XNIO", "Remoting/IO"}, {"JBREM", "Remoting/IO"}, {"WFLYRMT", "Remoting/IO"}, {"WFLYMAIL", "Mail"},
            {"WFLYLOG", "Logging"}, {"WFLYJSF", "JSF"}, {"WFLYWS", "Webservices"}, {"JBWS", "Webservices"}, {"WFLYBATCH", "Batch"}, {"JBERET", "Batch"}
    };

    private static final String[][] LOGGER_SUBSYSTEM = {
            {"org.jboss.as.ejb3", "EJB"}, {"org.jboss.ejb", "EJB"}, {"org.jboss.jca", "Datasource/JCA"}, {"org.jboss.as.connector", "Datasource/JCA"},
            {"com.arjuna", "Transaktionen"}, {"org.hibernate", "Hibernate/JPA"}, {"io.undertow", "Undertow/Web"}, {"org.jboss.as.server", "Server"},
            {"org.jboss.as.controller", "Server"}, {"org.jboss.as", "Server"}, {"org.wildfly.extension.undertow", "Undertow/Web"},
            {"org.jboss.resteasy", "REST"}, {"org.infinispan", "Infinispan/Cluster"}, {"org.jgroups", "Infinispan/Cluster"},
            {"org.jboss.weld", "CDI/Weld"}, {"org.wildfly.security", "Security"}, {"org.apache.activemq", "Messaging"},
            {"org.springframework", "Spring"}, {"org.apache.catalina", "Tomcat"}, {"org.apache.kafka", "Kafka"}, {"org.jboss.remoting", "Remoting/IO"},
            {"org.xnio", "Remoting/IO"}, {"org.apache.http", "HTTP-Client"}, {"org.apache.cxf", "Webservices"}, {"stderr", "stderr"}, {"stdout", "stdout"}
    };

    public static String subsystem(String code, String logger) {
        if (code != null) {
            int k = 0;
            while (k < code.length() && Character.isLetter(code.charAt(k))) k++;
            String prefix = code.substring(0, k);
            for (String[] cs : CODE_SUBSYSTEM) if (cs[0].equals(prefix)) return cs[1];
        }
        if (logger != null && !logger.isEmpty()) {
            for (String[] ls : LOGGER_SUBSYSTEM) if (logger.startsWith(ls[0])) return ls[1];
            String[] parts = logger.split("\\.");
            if (parts.length >= 3) return parts[0] + "." + parts[1] + "." + parts[2];
            return logger;
        }
        return "(unbekannt)";
    }

    public static String simpleName(String cls) {
        if (cls == null) return null;
        int d = cls.lastIndexOf('.');
        return d >= 0 ? cls.substring(d + 1) : cls;
    }

    public static String lower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }
}
