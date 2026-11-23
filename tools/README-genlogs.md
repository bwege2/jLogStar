# genlogs.py – synthetische WildFly-/log4j2-Testlogs

Erzeugt große, realistische Java/WildFly-Logs mit **bekannten, eingebauten Vorfällen**, um
Fehler-Gruppierung und Anomalie-Erkennung des Log-Analyzers zu testen.
Nur Python-3-Standardbibliothek (ab 3.8), keine Abhängigkeiten.

## Aufruf

```bash
python3 tools/genlogs.py --out DIR --size 500M --days 3 --seed 42 [--gzip-rotated]
```

| Option | Bedeutung |
|---|---|
| `--out DIR` | Zielverzeichnis (alte `server.log*`, `app.log`, `console.log`, `ground_truth.json` dort werden ersetzt) |
| `--size` | Gesamtgröße unkomprimiert, Suffixe `K`/`M`/`G` (Standard `500M`) |
| `--days` | Anzahl Tage (Standard 3) |
| `--seed` | Zufalls-Seed; gleicher Seed + gleiches `--start` ergibt identische Dateien |
| `--start YYYY-MM-DD` | erster Tag (Standard: heute minus `--days`) |
| `--gzip-rotated` | rotierte Dateien als `server.log.<datum>.gz` |
| `--gzip-level` | gzip-Level (Standard 1, schnell) |
| `--quiet` | keine Fortschrittsausgabe |

Durchsatz (gemessen): ca. 110–140 MB/s unkomprimiert, mit `--gzip-rotated` ca. 90 MB/s.

## Ausgabe

| Datei | Inhalt | Pattern |
|---|---|---|
| `server.log.YYYY-MM-DD` (je Tag), `server.log` (letzter Tag) | WildFly-Serverlog, täglich rotiert wie der periodic-rotating-file-handler, ca. 78 % | `%d{yyyy-MM-dd HH:mm:ss,SSS} %-5p [%c] (%t) %s%e%n` |
| `app.log` | Anwendungslog (log4j2), ca. 20 %, ganzer Zeitraum | `%d{yyyy-MM-dd HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n` |
| `console.log` | Konsole, nur erster Tag, nur INFO+, Stichprobe (max. 4 MB) | `%d{HH:mm:ss,SSS} %-5p [%c] (%t) %s%e%n` |
| `ground_truth.json` | alle Vorfälle mit Zeitraum, Datei(en), Logger, Codes, Exceptions, Anzahl; dazu Dateistatistik, periodische Jobs und Anteile der Hintergrund-Templates | – |

Hintergrund: Lastkurve nach Tageszeit, schwächer am Wochenende; viele INFO/DEBUG/TRACE-Zeilen
(Undertow, RESTEasy, Hibernate SQL mit Bind-Parametern, IronJacamar, Arjuna, Infinispan, `com.acme.shop.*`)
mit variablen Teilen (IDs, UUIDs, IPs, Benutzer, Session-IDs, Bestellnummern, Dauern). Dazu seltenes, gleichmäßiges
WARN/ERROR-Rauschen mit echten Stacktraces: Duplicate Key (23505), `NotFoundException`, `RequestTooBigException`,
Broken pipe, ISPN-Lock-Timeout, einzelne ARJUNA012117. Herzschlag-Job `InventorySync` alle 60 s.

## Eingebaute Vorfälle (siehe `ground_truth.json`)

1. **Server-Lifecycle**: Start am Anfang (WFLYSRV0049 / 0027 / 0010 / 0025); in der Mitte ein sauberer Neustart
   (WFLYSRV0050 → Start); ein **Absturz** nach `OutOfMemoryError: Java heap space` – Neustart ohne vorheriges WFLYSRV0050.
2. **DB-Pool erschöpft** (~15 min): `IJ000453` → `JDBCConnectionException` → WFLYEJB0034; einige Minuten vorher
   Slow-Query-Warnungen von `ReportRepository` (Ursache), kurz vorher ARJUNA012117/012121.
3. **Neuer Fehlertyp** nach Redeployment an Tag 2: `NullPointerException` in `ShippingCalculator`, danach in niedriger Rate.
4. **Stille**: ~20 min gar keine Zeilen (Hänger) zur Hauptlastzeit, danach Burst aus ARJUNA012117, Rollbacks,
   WFLYEJB0378 und `RejectedExecutionException`.
5. **Herzschlag stirbt**: `InventorySync` loggt die letzten ~6 h nicht mehr.
6. **Fehlersturm**: ~3 min tausende `SocketTimeoutException: Read timed out` vom `PaymentGatewayClient`.
7. **Einzelfälle**: 2–3× `StackOverflowError` (1024-Frame-Trace), 2× PostgreSQL-Deadlock (40P01, `LockAcquisitionException`).

Die Stärke der Vorfälle skaliert mit `--size` (Bezug 500M). Zeitstempel sind lokale Zeit ohne Zone.
