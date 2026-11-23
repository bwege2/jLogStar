@echo off
rem logStar launcher for Windows: needs Java 21+ (JAVA_HOME or java on PATH). Heap: set LOGSTAR_HEAP=8g
setlocal
set "DIR=%~dp0"
set "JAR=%DIR%logstar.jar"
if not exist "%JAR%" set "JAR=%DIR%target\logstar.jar"
if not exist "%JAR%" (
  echo logstar.jar nicht gefunden - im Quellverzeichnis zuerst bauen: mvn package
  exit /b 1
)
set "JAVA=java"
if defined JAVA_HOME set "JAVA=%JAVA_HOME%\bin\java"
if not defined LOGSTAR_HEAP set "LOGSTAR_HEAP=4g"
"%JAVA%" -Xmx%LOGSTAR_HEAP% -XX:+UseParallelGC --add-modules jdk.incubator.vector --enable-native-access=ALL-UNNAMED -Djava.util.logging.config.file=NUL -jar "%JAR%" %*
