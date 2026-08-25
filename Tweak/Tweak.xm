#import <UIKit/UIKit.h>
#import <spawn.h>
#import <sys/wait.h>

#define JBE_TOOL_PATH "/var/jb/usr/bin/jbevasion"
#define JBE_STASH_DIR "/var/jb/.apphide-stash"

@interface CCUIModularControlCenterOverlayViewController : UIViewController
- (void)setPresentationState:(NSInteger)state;
@end

/* Spawn the CLI and, when waitForExit is YES, block until it exits so the
 * debounce window really covers the whole hide/show operation (uicache can
 * take seconds) instead of a fixed sleep. */
static void jbev_run(const char *cmd, BOOL waitForExit) {
	pid_t pid;
	const char *argv[] = { JBE_TOOL_PATH, cmd, NULL };
	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_init(&actions);
	posix_spawn(&pid, JBE_TOOL_PATH, &actions, NULL, (char *const *)argv, NULL);
	posix_spawn_file_actions_destroy(&actions);
	if (waitForExit && pid > 0) {
		int status = 0;
		waitpid(pid, &status, 0);
	}
}

static BOOL jbev_is_hidden(void) {
	NSFileManager *fm = [NSFileManager defaultManager];
	BOOL isDir = NO;
	if (![fm fileExistsAtPath:@JBE_STASH_DIR isDirectory:&isDir] || !isDir) return NO;

	NSArray *items = [fm contentsOfDirectoryAtPath:@JBE_STASH_DIR error:nil];
	for (NSString *item in items) {
		if ([item hasSuffix:@".app"]) return YES;
	}
	return NO;
}

%hook CCUIModularControlCenterOverlayViewController

#define JBE_TOGGLE_TAG 0x4a42

/* Debounce guard: the CLI is slow (uicache + respring can take several
 * seconds), so rapid taps on the toggle would stack up parallel
 * apphide-all / apphide-showall processes that race each other and leave
 * the stash in an inconsistent mixed state. spawn is gated behind this flag
 * and only re-armed after the previous command has finished. */
static BOOL g_jbev_busy = NO;

/* Refresh the eye icon + tint to match the on-disk stash state. Safe to call
 * from the main thread at any time (no animations, no layout side effects). */
static void jbev_style_button(UIButton *button) {
	BOOL hidden = jbev_is_hidden();
	UIColor *tint = hidden ? [UIColor systemOrangeColor] : [UIColor systemGreenColor];
	UIImageSymbolConfiguration *cfg = [UIImageSymbolConfiguration configurationWithPointSize:18 weight:UIImageSymbolWeightBold];
	NSString *symbol = hidden ? @"eye.slash.fill" : @"eye.fill";
	UIImage *img = [UIImage systemImageNamed:symbol withConfiguration:cfg];
	[button setImage:img forState:UIControlStateNormal];
	button.tintColor = tint;
}

- (void)setPresentationState:(NSInteger)state {
	%orig;

	UIButton *jbevToggleButton = [self.view viewWithTag:JBE_TOGGLE_TAG];
	if (jbevToggleButton == nil) {
		jbevToggleButton = [UIButton buttonWithType:UIButtonTypeSystem];
		jbevToggleButton.tag = JBE_TOGGLE_TAG;
		[jbevToggleButton addAction:[UIAction actionWithHandler:^(__kindof UIAction *handler) {
			if (g_jbev_busy) return;

			BOOL hidden = jbev_is_hidden();
			const char *cmd = hidden ? "apphide-showall" : "apphide-all";

			g_jbev_busy = YES;
			dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
				jbev_run(cmd, YES);
				dispatch_async(dispatch_get_main_queue(), ^{
					g_jbev_busy = NO;
					jbev_style_button(jbevToggleButton);
				});
			});
		}] forControlEvents:UIControlEventTouchUpInside];
		[self.view addSubview:jbevToggleButton];
	}

	jbev_style_button(jbevToggleButton);

	CGFloat size = 36;
	UIWindow *win = self.view.window;
	CGFloat safeLeft = win.safeAreaInsets.left ?: 20;
	CGFloat yOffset = 18;
	jbevToggleButton.frame = CGRectMake(safeLeft, yOffset, size, size);

	if (state == 1) {
		jbevToggleButton.alpha = 0;
		jbevToggleButton.transform = CGAffineTransformMakeScale(0.6, 0.6);
		[UIView animateWithDuration:0.35 delay:0.0 usingSpringWithDamping:0.7
			initialSpringVelocity:0.5 options:UIViewAnimationOptionCurveEaseOut animations:^{
				jbevToggleButton.alpha = 1.0;
				jbevToggleButton.transform = CGAffineTransformIdentity;
			} completion:nil];
	} else {
		[UIView animateWithDuration:0.2 animations:^{
			jbevToggleButton.alpha = 0;
			jbevToggleButton.transform = CGAffineTransformMakeScale(0.6, 0.6);
		}];
	}
}

%end

/* ── URL scheme blocking ──────────────────────────────────────────────── */

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