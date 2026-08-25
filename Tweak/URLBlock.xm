#import <UIKit/UIKit.h>

#define VHIDE_PLIST "/var/jb/Library/Preferences/com.jbevasion.vhide.plist"

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
	NSString *scheme = [[url scheme] lowercaseString];
	if (!scheme) return %orig;

	NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:@VHIDE_PLIST];
	NSArray *blocked = plist[@"BlockedURLSchemes"];
	if ([blocked containsObject:scheme]) {
		return NO;
	}
	return %orig;
}
%end