#!/usr/bin/env bash
# Builds dist/logstar-<version>.zip: jar, launchers, docs and the test-log generator.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=$(sed -n 's:.*<version>\(.*\)</version>.*:\1:p' pom.xml | head -1)
NAME="logstar-$VERSION"
mvn -q clean package
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/$NAME/docs" "$STAGE/$NAME/tools"
cp target/logstar.jar logstar logstar.bat README.md "$STAGE/$NAME/"
cp docs/KONZEPT.md "$STAGE/$NAME/docs/"
cp tools/genlogs.py tools/README-genlogs.md "$STAGE/$NAME/tools/"
cp src/main/resources/web/vendor/echarts-LICENSE.txt "$STAGE/$NAME/docs/THIRD-PARTY-echarts-LICENSE.txt"
cat > "$STAGE/$NAME/VERSION.txt" <<INFO
logStar $VERSION
built $(date -u +%Y-%m-%dT%H:%M:%SZ) with $(java -version 2>&1 | head -1)
requires Java 21+
INFO
chmod +x "$STAGE/$NAME/logstar"
mkdir -p dist
rm -f "dist/$NAME.zip"
(cd "$STAGE" && zip -qr9 - "$NAME") > "dist/$NAME.zip"
echo "dist/$NAME.zip ($(du -h "dist/$NAME.zip" | cut -f1))"
