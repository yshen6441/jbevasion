#import <Foundation/Foundation.h>
#include <objc/runtime.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>
#include "krw.h"
#include "apphide.h"

#define kNotificationName CFSTR("com.xsf1re.jbevasion/toggle")
#define kBundleID CFSTR("com.xsf1re.jbevasion")

static BOOL get_pref_enabled(void) {
    CFBooleanRef val = (CFBooleanRef)CFPreferencesCopyAppValue(CFSTR("enabled"), kBundleID);
    BOOL on = (val && CFBooleanGetValue(val));
    if (val) CFRelease(val);
    return on;
}

static void trigger_hide(BOOL on) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int ret = krw_init();
        if (ret != 0) {
            NSLog(@"jbevasion: krw_init failed (%d)", ret);
            return;
        }
        if (on) {
            apphide_hide_all();
            NSLog(@"jbevasion: hidden all apps");
        } else {
            apphide_unhide_all();
            NSLog(@"jbevasion: restored all apps");
        }
    });
}

static void notification_handler(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    BOOL on = get_pref_enabled();
    NSLog(@"jbevasion: notification received, enabled=%d", on);
    trigger_hide(on);
}

__attribute__((constructor))
static void initialize(void) {
    CFNotificationCenterAddObserver(
        CFNotificationCenterGetDarwinNotifyCenter(),
        NULL,
        notification_handler,
        kNotificationName,
        NULL,
        CFNotificationSuspensionBehaviorDeliverImmediately
    );
    NSLog(@"jbevasion: tweak loaded, registered for notification");
    BOOL on = get_pref_enabled();
    if (on) {
        NSLog(@"jbevasion: auto-hide on startup");
        trigger_hide(on);
    }
}