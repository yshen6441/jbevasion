#import "JBRootListController.h"

#define kNotificationName "com.xsf1re.jbevasion/toggle"

@implementation JBRootListController

- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
    }
    return _specifiers;
}

- (void)setEnabled:(id)value specifier:(PSSpecifier *)specifier {
    [self setPreferenceValue:value specifier:specifier];
    notify_post(kNotificationName);
}

@end