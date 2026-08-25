#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#define CCSupportModulesPath @"/Library/ControlCenter/Bundles"

%hook CCSModuleRepository

+ (NSArray<NSURL *> *)_defaultModuleDirectories {
    NSArray<NSURL *> *dirs = %orig;
    if (dirs) {
        NSURL *thirdParty = [NSURL fileURLWithPath:CCSupportModulesPath isDirectory:YES];
        return [dirs arrayByAddingObject:thirdParty];
    }
    return dirs;
}

- (void)_queue_updateAllModuleMetadata {
    Ivar ivar = class_getInstanceVariable(%c(CCSModuleRepository), "_ignoreAllowedList");
    if (ivar) {
        object_setIvar(self, ivar, (id)YES);
    }
    %orig;
}

%end

%ctor {
    %init();
}