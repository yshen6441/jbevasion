# Builds the link-time stub for libjailbreak.dylib.
# The stub only contains symbol bodies so the linker can resolve them;
# the install name below is what the jbevasion binary records, and at runtime
# dyld resolves /var/jb/usr/lib/libjailbreak.dylib (via -rpath) for the REAL
# library. The stub is never loaded on device.

# On macOS CI there is no xcrun-visible iPhoneOS SDK; theos vendors one under
# THEOS/sdks and exports SYSROOT. Fall back to xcrun only for local happy path.
ifndef SYSROOT
SYSROOT := $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null)
endif

CC := clang

TARGET := libjailbreak.dylib

all: $(TARGET)

$(TARGET): stub.c
	$(CC) -arch arm64 -arch arm64e \
		-isysroot $(SYSROOT) \
		-miphoneos-version-min=15.0 \
		-dynamiclib \
		-install_name @rpath/libjailbreak.dylib \
		-o $@ $<
	ldid -Cadhoc -S $@

clean:
	rm -f $(TARGET)

.PHONY: all clean