#import <UIKit/UIKit.h>

#define VHIDE_PLIST "/var/jb/Library/Preferences/com.jbevasion.vhide.plist"

static NSArray *s_blockedSchemes = nil;
static dispatch_once_t s_onceToken;

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
	NSString *scheme = [[url scheme] lowercaseString];
	if (!scheme) return %orig;

	dispatch_once(&s_onceToken, ^{
		NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:@VHIDE_PLIST];
		s_blockedSchemes = plist[@"BlockedURLSchemes"] ?: @[];
	});
	if ([s_blockedSchemes containsObject:scheme]) {
		return NO;
	}
	return %orig;
}
%end