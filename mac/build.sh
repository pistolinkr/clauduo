#!/bin/sh
# dist/Clauduo.app 을 만든다. 임시(ad-hoc) 서명이라 이 Mac에서 쓰는 용도다.
set -e
cd "$(dirname "$0")"
swift build -c release
APP=dist/Clauduo.app
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS"
cp .build/release/Clauduo "$APP/Contents/MacOS/Clauduo"
cat > "$APP/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.clauduo.mac</string>
<key>CFBundleName</key><string>Clauduo</string>
<key>CFBundleExecutable</key><string>Clauduo</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>26.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
EOF
codesign --force --deep -s - "$APP"
echo "$PWD/$APP"
