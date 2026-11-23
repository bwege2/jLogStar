# Changelog

## 0.1.0

Erste Version von jLogStar – Log-Analyzer für Java/WildFly-Logs mit Fokus auf Fehler, Fehlerarten und Anomalien.

**Download:** `jlogstar-0.1.0.zip` entpacken, dann `./jlogstar open /pfad/zu/logs/` (Windows: `jlogstar.bat open C:\logs`)
und http://127.0.0.1:7070 öffnen. Benötigt Java 21 oder neuer.

### Funktionen
- Einlesen von WildFly/JBoss (`server.log`, `console.log`), Log4j2, Log4j, Logback, Spring Boot und JSON-Lines;
  `.gz`, `.zip` und ganze Verzeichnisse; Format wird pro Datei automatisch erkannt
- Volltextsuche mit Phrasen, Wildcards, boolescher Logik und Feldern (`ex:`, `code:`, `logger:`, `thread:`, `level:>=`, `group:`)
- Fehlergruppen durch Template-Mining (variable Teile maskiert, Exception-Signatur, Drain-artiges Clustering)
- Anomalie-Erkennung: Häufungen, erhöhte Fehlerrate, neue Fehlerarten (auch nach Deployments), Log-Stille,
  verstummte Jobs, ungeplante Neustarts, 20 Regeln für bekannte Muster (OOM, Pool erschöpft, Tx-Timeout, Deadlock …)
- Vorfälle aus zeitlich zusammenhängenden Signalen und Ursachen-Analyse („was kam zuerst?“)
- Web-UI: Zeitverlauf, Heatmap Fehlergruppen × Zeit, Treemap der Fehlerarten, Gruppendetails, Ereignisliste
  mit formatierten Stacktraces, Kontext in der Datei, hell/dunkel
- WildFly-Spezialitäten: Datierung von `console.log` über `server.log`, zeilenweise `[stderr]`-Stacktraces werden
  zusammengesetzt, doppelte Start-Meldungen entdoppelt

### Leistung (16 Kerne)
- 5,4 GB / 29 Mio. Ereignisse in ca. 2 min indexiert; Übersicht über alles in ca. 0,4 s, gefilterte Suchen 7–115 ms

### Bekannte Grenzen
- Kein inkrementelles Nachladen; mehrzeilige (pretty-printed) JSON-Logs nicht unterstützt; mehrere Server in einem Index
  werden nicht getrennt ausgewertet
