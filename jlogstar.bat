@echo off
rem jLogStar launcher for Windows: needs Java 21+ (JAVA_HOME or java on PATH). Heap: set JLOGSTAR_HEAP=8g
setlocal
set "DIR=%~dp0"
set "JAR=%DIR%jlogstar.jar"
if not exist "%JAR%" set "JAR=%DIR%target\jlogstar.jar"
if not exist "%JAR%" (
  echo jlogstar.jar nicht gefunden - im Quellverzeichnis zuerst bauen: mvn package
  exit /b 1
)
set "JAVA=java"
if defined JAVA_HOME set "JAVA=%JAVA_HOME%\bin\java"
if not defined JLOGSTAR_HEAP set "JLOGSTAR_HEAP=4g"
"%JAVA%" -Xmx%JLOGSTAR_HEAP% -XX:+UseParallelGC --add-modules jdk.incubator.vector --enable-native-access=ALL-UNNAMED -Djava.util.logging.config.file=NUL -jar "%JAR%" %*
