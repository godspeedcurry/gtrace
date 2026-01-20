#!/bin/bash
set -e

ICONSET="utils/gtrace.iconset"
mkdir -p "$ICONSET"
SRC="build/appicon.png"

# Check if source exists
if [ ! -f "$SRC" ]; then
    echo "Source icon $SRC not found!"
    exit 1
fi

echo "Generating iconset from $SRC..."

# Standard sizes
sips -z 16 16     "$SRC" --out "$ICONSET/icon_16x16.png"
sips -z 32 32     "$SRC" --out "$ICONSET/icon_16x16@2x.png"
sips -z 32 32     "$SRC" --out "$ICONSET/icon_32x32.png"
sips -z 64 64     "$SRC" --out "$ICONSET/icon_32x32@2x.png"
sips -z 128 128   "$SRC" --out "$ICONSET/icon_128x128.png"
sips -z 256 256   "$SRC" --out "$ICONSET/icon_128x128@2x.png"
sips -z 256 256   "$SRC" --out "$ICONSET/icon_256x256.png"
sips -z 512 512   "$SRC" --out "$ICONSET/icon_256x256@2x.png"
sips -z 512 512   "$SRC" --out "$ICONSET/icon_512x512.png"
sips -z 1024 1024 "$SRC" --out "$ICONSET/icon_512x512@2x.png"

echo "Packing icns..."
iconutil -c icns "$ICONSET" -o build/darwin/icon.icns

echo "Done! generated build/darwin/icon.icns"
rm -rf "$ICONSET"
