#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# SDK path from Theos environment, or default
SDK="${SDK:-$THEOS/sdks/iPhoneOS17.0.2.sdk}"
if [ ! -d "$SDK" ]; then
    echo "SDK not found at $SDK; set SDK env var or ensure THEOS is configured"
    exit 1
fi

APP_NAME="apphide-recovery"
APP_DIR="$SCRIPT_DIR/$APP_NAME.app"
IPA_DIR="$SCRIPT_DIR/build"
IPA_PATH="$IPA_DIR/AppHideRecovery.ipa"

# Clean
rm -rf "$APP_DIR" "$IPA_DIR"
mkdir -p "$APP_DIR" "$IPA_DIR"

# Compile
clang -arch arm64 \
    -isysroot "$SDK" \
    -miphoneos-version-min=15.0 \
    -framework UIKit -framework Foundation -framework CoreGraphics \
    -o "$APP_DIR/$APP_NAME" \
    "$SCRIPT_DIR/main.m"

# Copy Info.plist
cp "$SCRIPT_DIR/Info.plist" "$APP_DIR/"

# Sign with ldid (using entitlements)
ldid -S"$SCRIPT_DIR/Entitlements.plist" "$APP_DIR/$APP_NAME"
ldid -S"$SCRIPT_DIR/Entitlements.plist" "$APP_DIR"

# Create .ipa (Payload directory inside zip)
mkdir -p "$IPA_DIR/Payload"
cp -R "$APP_DIR" "$IPA_DIR/Payload/"
cd "$IPA_DIR"
zip -r "$IPA_PATH" Payload/ -x "*.DS_Store"
cd "$SCRIPT_DIR"
rm -rf "$IPA_DIR/Payload"

echo "IPA built: $IPA_PATH"
ls -lh "$IPA_PATH"