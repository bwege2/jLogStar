# ✶ jLogStar

Log-Analyzer für Java-Logs (WildFly/JBoss, Log4j2, Log4j, Logback, Spring Boot, JSON-Layouts) mit Fokus auf
**Fehler, Fehlerarten und untypische Situationen** – für Gigabytes an Logs, lokal, ohne Infrastruktur.
Hintergrund und Designentscheidungen: [docs/KONZEPT.md](docs/KONZEPT.md).

**Download:** [Releases](https://github.com/bwege2/jLogStar/releases) · **Anleitung:** [Wiki](https://github.com/bwege2/jLogStar/wiki)

## Schnellstart

Aus dem Release-Zip (nur Java 21+ nötig): entpacken, dann `./jlogstar open /pfad/zu/logs/` (Windows: `jlogstar.bat open C:\logs`).

Aus den Quellen:

```bash
mvn package                                   # baut target/jlogstar.jar (Java 21+)
./jlogstar open /pfad/zu/logs/                 # indexiert (falls nötig) und startet die UI
# → http://127.0.0.1:7070/
```

Einzelschritte:

```bash
./jlogstar index --index /data/idx --tz Europe/Berlin /var/log/wildfly/ app.log archive.zip
./jlogstar serve --index /data/idx --port 7070            # --host 0.0.0.0 für Zugriff von außen
./jlogstar analyze --index /data/idx                      # nur Analyse neu rechnen
```

Eingaben: Dateien, Verzeichnisse (rekursiv), `.gz`, `.zip`. Das Format wird pro Datei automatisch erkannt.
Logs ohne Zeitzone werden in `--tz` interpretiert (Standard: Systemzeitzone). `JLOGSTAR_HEAP=8g` setzt den Heap.

Demo mit synthetischen WildFly-Logs inkl. eingebauter Vorfälle (siehe [tools/README-genlogs.md](tools/README-genlogs.md)):

```bash
python3 tools/genlogs.py --out /tmp/demo-logs --size 1G --days 5 --gzip-rotated
./jlogstar open /tmp/demo-logs
```

## Was die UI zeigt

| Ansicht | Inhalt |
|---|---|
| **Übersicht** | Kennzahlen; Zeitverlauf nach Level und separat Fehler/Warnungen mit Neustart-/Deployment-Linien und Vorfall-Bändern (Bereich ziehen = Zeitfilter); Heatmap Fehlergruppen × Zeit (pro Zeile normiert, auffällige Gruppen zuerst); Treemap Subsystem → Exception; Top-Vorfälle |
| **Fehlergruppen** | alle Templates mit Badges NEU / SPIKE / KRITISCH / VERSTUMMT, Sparkline, erstes/letztes Auftreten. Detail: Verlauf, Threads, Dateien, Varianten, erklärte Regel, erstes/letztes Ereignis |
| **Anomalien** | Vorfälle (zeitlich zusammenhängende Signale) und alle Einzel-Auffälligkeiten mit Begründung |
| **Ursachen-Analyse** | für ein Zeitfenster inkl. Vorlauf: überproportional häufige Gruppen, chronologisch – „was kam zuerst?“ |
| **Ereignisse** | Volltext-Treffer mit Hervorhebung, formatierte Stacktraces (App-Frames hervorgehoben), Kontext ±25 in der Datei, „gleicher Thread ±2 min“ |

Alle Ansichten zeigen immer das aktuelle Suchergebnis; der Filterzustand steht in der URL (teilbar).

### Suche

`"Read timed out"` · `timeout AND pool` · `-heartbeat` · `ex:NullPointerException` · `code:IJ000453` · `code:WFLYEJB*` ·
`logger:com.acme*` · `thread:"default task-12"` · `level:>=WARN` · `group:42` / `-group:7` · `file:3`

## Erkennung

- **Fehlergruppen**: Maskierung variabler Teile (IDs, UUIDs, Zahlen, Session-Tokens, IPs …; Message-Codes und SQLStates bleiben
  erhalten) + Exception-Signatur (äußere Exception, Root Cause, erste Anwendungs-Frames) + Drain-artiges Clustering.
- **Detektoren**: Häufung (Poisson-Test gegen volumenproportionale Grundrate), erhöhte Fehlerrate, neue Fehlerart (spät oder
  nach Deployment), Log-Stille, verstummte Jobs/Heartbeats, ungeplanter Neustart (WFLYSRV0049 ohne WFLYSRV0050), Start mit Fehlern,
  20 Regeln für bekannte Muster (OOM, Pool erschöpft, Tx-Timeout, Deadlock, Klassenladen, TLS …) mit Erklärung und Tipp.
- **Vorfälle**: überlappende Signale werden zusammengefasst, das früheste Signal ist der erste Ursachen-Kandidat.
- WildFly-Spezialitäten: `console.log` ohne Datum wird über identische Zeilen im `server.log` datiert;
  zeilenweise nach `[stderr]` geschriebene Stacktraces (`e.printStackTrace()`) werden wieder zu einem Ereignis zusammengesetzt;
  doppelte Start-Meldungen aus mehreren Dateien werden entdoppelt.

## Leistung (gemessen, 16 Kerne, NVMe)

| Daten | Indexieren | Index | Übersicht (alle Ereignisse) | gefilterte Suche |
|---|---|---|---|---|
| 1,07 GB Text (gz), 5,5 Mio. Ereignisse | 29 s | 0,7 GB | 0,2–0,3 s | 10–90 ms |
| 5,37 GB Text, 29,3 Mio. Ereignisse | 2:05 min (44 MB/s) | 3,5 GB | 0,36–0,49 s | 7–115 ms |

Der Index enthält den komprimierten Originaltext; die Logdateien werden danach nicht mehr gebraucht.

Release bauen: `tools/release.sh` → `dist/jlogstar-<version>.zip`. Veröffentlichen: Version in `pom.xml` und
`CHANGELOG.md` setzen, Tag `v<version>` pushen – GitHub Actions baut das Zip und legt das Release an.

## Architektur

```
src/main/java/jlogstar/
  ingest/   Formaterkennung, Zeitstempel-Parser, Layouts (Text + JSON), Exception-Parser, Masker, paralleles Indexieren
  index/    Lucene-Felder und Analyzer (Tokenisierung für Klassennamen/Codes)
  analyze/  Clustering, Zeitreihen, Detektoren, Regelbibliothek → analysis.json
  query/    Suche + segment-parallele DocValues-Aggregationen, Kontext, Gruppendetail, Korrelation
  web/      eingebetteter HTTP-Server + JSON-API
src/main/resources/web/   UI (Vanilla JS + ECharts, kein Build-Schritt)
tools/genlogs.py          Generator für realistische Testlogs mit Ground Truth
```

## Grenzen / nächste Schritte

- Kein inkrementelles Nachladen (tail -f); ein Index wird jeweils komplett neu aufgebaut.
- Mehrzeilige JSON-Logs (pretty printed) werden nicht unterstützt, nur JSON-Lines.
- Mehrere Server/Hosts werden nicht getrennt (z. B. Absturzerkennung geht von einem Server aus).
- Ab sehr vielen Segmenten (> ~50 GB Logs) wäre ein abschließendes Merge sinnvoll.

## Lizenz

jLogStar steht unter der [GNU General Public License v3.0](LICENSE).
Enthaltene Bibliotheken (Apache Lucene, Jackson, Apache ECharts) stehen unter der Apache License 2.0.
