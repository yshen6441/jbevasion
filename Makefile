# jbevasion - jailbreak environment hiding controller (Dopamine)
# Links against Dopamine's libjailbreak.dylib via a build-time stub.
# At runtime dyld binds the real /var/jb/usr/lib/libjailbreak.dylib.

GO_EASY_ON_ME = 1
DEBUG = 0
FINALPACKAGE = 1

TARGET := iphone:clang:latest:15.0
ARCHS = arm64 arm64e
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TOOL_NAME = jbevasion

jbevasion_FILES = src/main.m src/krw.c src/hide.c src/fd_rdir.c src/apphide.c src/vhide.c
jbevasion_CFLAGS = -Iinclude -fobjc-arc
jbevasion_LDFLAGS = -Lstub -ljailbreak -framework CoreFoundation -Wl,-rpath,/var/jb/usr/lib
jbevasion_CODESIGN_FLAGS = -Sent.plist
jbevasion_INSTALL_PATH = /usr/bin

# Build the link-time stub before the tool.
internal-tool-all::
	$(MAKE) -C stub SYSROOT="$(SYSROOT)"

include $(THEOS_MAKE_PATH)/tool.mk

TWEAK_NAME = jbevasionCC
jbevasionCC_FILES = Tweak/Tweak.xm
jbevasionCC_CFLAGS = -fobjc-arc -Iinclude
jbevasionCC_FRAMEWORKS = UIKit

include $(THEOS_MAKE_PATH)/tweak.mk

include $(THEOS_MAKE_PATH)/aggregate.mk