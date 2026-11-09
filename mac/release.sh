#!/bin/sh
# 사용법: mac/release.sh 0.3.0 [출력폴더]
# DMG와 업데이트 정보를 만든다. 올린 뒤 npx wrangler deploy 하면 앱들이 새 버전을 받는다.
set -e
cd "$(dirname "$0")"
[ -n "$1" ] && echo "$1" > VERSION
V=$(cat VERSION)
OUT=${2:-../public/mac}
./build.sh
STAGE=$(mktemp -d)
cp -R dist/Clauduo.app "$STAGE/"
ln -s /Applications "$STAGE/Applications"
mkdir -p "$OUT"
hdiutil create -quiet -volname "Clauduo" -srcfolder "$STAGE" -ov -format UDZO "$OUT/Clauduo.dmg"
rm -rf "$STAGE"
SHA=$(shasum -a 256 "$OUT/Clauduo.dmg" | cut -d' ' -f1)
printf '{"version":"%s","url":"/mac/Clauduo.dmg?v=%s","sha256":"%s"}\n' "$V" "$V" "$SHA" > "$OUT/latest.json"
ls -la "$OUT/Clauduo.dmg" | awk '{print "DMG bytes:", $5}'
echo "Clauduo $V 준비 완료"
