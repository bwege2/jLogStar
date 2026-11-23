# logStar – Konzept

Ziel: Gigabytes an Java-Logs (WildFly/JBoss, Log4j2, Logback, Log4j 1, JSON-Layouts) in Minuten einlesen,
in Millisekunden durchsuchen und so darstellen, dass man **Fehler, Fehlerarten und untypische Situationen**
sofort sieht – ohne vorher zu wissen, wonach man sucht.

## 1. Was ist an Java-Logs besonders?

| Eigenschaft | Konsequenz |
|---|---|
| Ereignisse sind **mehrzeilig** (Stacktraces, `Caused by:`, `... 42 more`) | Parser muss Ereignisgrenzen erkennen (Zeile beginnt mit Zeitstempel), nicht Zeilen zählen. |
| Nachrichten sind **Schablonen mit variablen Teilen** (IDs, Dauer, SQL-Bindwerte, UUIDs) | Volltextsuche allein reicht nicht – man braucht **Template-Mining**, damit 400 000 Zeilen zu „1 Fehlerart“ werden. |
| WildFly-Meldungen tragen **Message-Codes** (`WFLYEJB0034`, `IJ000453`, `ARJUNA012117`, `HHH000315`) | Präfix = Subsystem (EJB, JCA-Pool, Transaktionen, Hibernate, Undertow …): perfekte Kategorie für „Fehlerarten“. |
| Exceptions haben **Ursachenketten** | Eine Fehlergruppe wird durch Meldung **und** Exception-Signatur (Typ + Root-Cause + erste Anwendungs-Frames) bestimmt. |
| WildFly `console.log` / Default-Konsolen-Pattern hat **nur Uhrzeit** | Datum aus Dateinamen (`server.log.2026-11-20`) oder Dateidatum ableiten, Tageswechsel erkennen. |
| Logs werden **rotiert und gezippt** | Mehrere Dateien, `.gz`, `.zip`, Verzeichnisse rekursiv. |

## 2. Durchsuchbarkeit bei Gigabytes

**Entscheidung: Apache Lucene als eingebetteter Index + Spalten-Werte (DocValues) für Aggregationen.**

- Einlesen parallel: große Dateien werden in Byte-Blöcke zerlegt, jeder Block beginnt am nächsten
  Ereignisanfang; alle Kerne parsen gleichzeitig, `IndexWriter` ist thread-safe.
- Pro Ereignis indexiert: Zeit, Level, Logger, Thread, Message-Code, Exception-Klassen, Template-ID,
  Datei + Byte-Offset, Volltext (Nachricht + Stacktrace). Rohtext wird komprimiert gespeichert
  (Logs komprimieren ~8–10×) → der Index ist eigenständig, die Originaldateien werden nicht mehr gebraucht.
- Abfragen: Volltext (`"Read timed out"`, `IJ000453`, Wildcards, Phrasen, boolesch) kombiniert mit Feldern
  (`level:ERROR logger:com.acme* ex:java.lang.NullPointerException code:WFLYEJB*`) und Zeitraum.
- **Jede Ansicht ist eine Aggregation über das aktuelle Suchergebnis**: Zeithistogramm, Fehlergruppen,
  Kategorien werden aus DocValues spaltenweise gezählt (segment-parallel) – typischerweise < 1 s auch
  bei zweistelligen Millionen Ereignissen. Dadurch filtert ein Klick/Brush alles gleichzeitig.
- Kontextansicht: Nachbar-Ereignisse über (Datei, Offset) – „was stand im Log davor/danach?“.

Alternativen bewertet: grep/ripgrep (keine Aggregation, jede Suche ein Voll-Scan), ELK/OpenSearch
(Infrastruktur-Aufwand, für ein Analyse-Werkzeug am Arbeitsplatz zu schwer), DuckDB/Parquet (sehr gute
Aggregation, aber Volltextsuche schwach). Lucene liefert beides in einem einzigen JAR.

## 3. Fehlergruppen (Template-Mining)

1. **Maskieren** (parallel, beim Einlesen): Zahlen, Hex, UUIDs, IPs, URLs-Parameter, Zeit/Dauer,
   Strings in Anführungszeichen, Session-/Order-IDs → `<*>`.
2. **Exception-Signatur**: äußerste Exception-Klasse + Root-Cause-Klasse + die ersten Frames,
   die *nicht* aus Framework-Paketen stammen (org.jboss, io.undertow, jakarta, java., sun., org.hibernate …).
3. Schlüssel = Logger + maskierte Nachricht + Signatur → dichte Template-ID.
4. **Drain-artiges Clustering** nach dem Einlesen über die *verschiedenen* Schlüssel (nicht über Ereignisse,
   daher schnell): gleiche Tokenzahl, gleicher Logger, ≥ 70 % gleiche Tokens → gemeinsame Gruppe.

## 4. Erkennung untypischer Situationen

| Detektor | Idee | Warum relevant |
|---|---|---|
| **Neue Fehlerart** | Gruppe (≥ WARN) erscheint erstmals spät im Zeitraum bzw. nach einem Deployment | Regressionen nach Releases |
| **Spike** | Zählung pro Zeitfenster gegen robuste Grundrate (getrimmter Mittelwert), Poisson-Tail-Test, benachbarte Fenster zu Episoden verschmolzen | Fehlerstürme, Lastprobleme |
| **Stille / Lücke** | Gesamtvolumen fällt dort auf 0, wo normalerweise viel geloggt wird | Hänger, GC-Pausen, Abstürze |
| **Verstummt** | Regelmäßige Meldung (Job/Heartbeat) hört vor Ende auf | stille Job-Abbrüche |
| **Neustart / Absturz** | WildFly-Start (`WFLYSRV0049`) ohne vorheriges `WFLYSRV0050` = ungeplanter Neustart | Crash-Erkennung |
| **Bekannte kritische Muster** | Regelbibliothek: OOM, StackOverflow, `IJ000453` Pool erschöpft, `ARJUNA012117` Tx-Timeout, Deadlocks, „Too many open files“, Thread-Pool erschöpft … mit Erklärung | Wissen über WildFly eingebaut |
| **Korrelation / Ursachenkandidaten** | Für ein Zeitfenster: welche Gruppen sind überproportional häufig (Lift), sortiert nach *erstem Auftreten* | „Was kam zuerst?“ – Root-Cause-Suche |

## 5. Visualisierung – was ist sinnvoll?

Leitfrage: *Wann ist was schiefgegangen, welche Art von Fehler war es, was ist neu, was hängt zusammen?*

1. **Zeitachse (gestapelte Balken nach Level)** mit Markern für Neustarts, Deployments, Anomalien;
   Brush = Zeitfilter für alles. Volumen und Fehler auf getrennten Achsen (Fehler gehen sonst im
   INFO-Rauschen unter).
2. **Fehlergruppen-Tabelle** mit Sparkline, Anzahl, erstem/letztem Auftreten, Exception, Code,
   Badges *NEU* / *SPIKE* / *KRITISCH*. Das ist die zentrale Arbeitsliste.
3. **Heatmap Fehlergruppen × Zeit**: zeigt auf einen Blick Episoden und welche Fehler *gemeinsam*
   auftreten (vertikale Bänder = Kaskaden).
4. **Fehlerarten-Treemap**: Subsystem (Message-Code-Präfix / Logger-Paket) → Exception-Typ.
5. **Anomalie-Liste** mit Begründung („73× in 5 min, erwartet 0,4“) – Klick zoomt die Zeitachse.
6. **Ereignisliste** (Suche) mit Treffer-Hervorhebung, aufklappbarem Stacktrace und Kontext ±N.
7. **Gruppendetail**: Verlauf, Verteilung nach Thread/Logger/Datei, Beispiel-Stacktrace, Ursachenkette.
8. **Ursachen-Ansicht** für ein Zeitfenster: Gruppen mit höchstem Lift, chronologisch nach Erstauftreten.

## 6. Architektur

```
logstar.jar (Java 25, ein Fat-JAR)
├─ ingest   Formaterkennung → paralleles Parsen → Maskierung/Signatur → Lucene IndexWriter
├─ analyze  Clustering der Templates, Zeitreihen, Detektoren, Regelbibliothek → analysis.json
├─ query    Lucene-Suche + DocValues-Aggregationen (segment-parallel)
└─ web      eingebetteter HTTP-Server (JDK), JSON-API, Single-Page-UI (ECharts, ohne Build-Schritt)
```

Aufruf: `logstar index <dateien|verzeichnisse…> --index <dir>` und `logstar serve --index <dir>`,
oder in einem Schritt `logstar open <logs…>`.
