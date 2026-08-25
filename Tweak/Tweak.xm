#import <UIKit/UIKit.h>
#import <spawn.h>

#define JBE_TOOL_PATH "/var/jb/usr/bin/jbevasion"
#define JBE_STASH_DIR "/var/jb/.apphide-stash"

@interface CCUIModularControlCenterOverlayViewController : UIViewController
- (void)setPresentationState:(NSInteger)state;
@end

static void jbev_run(const char *cmd) {
	pid_t pid;
	const char *argv[] = { JBE_TOOL_PATH, cmd, NULL };
	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_init(&actions);
	posix_spawn(&pid, JBE_TOOL_PATH, &actions, NULL, (char *const *)argv, NULL);
	posix_spawn_file_actions_destroy(&actions);
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

- (void)setPresentationState:(NSInteger)state {
	%orig;

	UIButton *jbevToggleButton = [self.view viewWithTag:JBE_TOGGLE_TAG];
	if (jbevToggleButton == nil) {
		jbevToggleButton = [UIButton buttonWithType:UIButtonTypeSystem];
		jbevToggleButton.tag = JBE_TOGGLE_TAG;
		[jbevToggleButton addAction:[UIAction actionWithHandler:^(__kindof UIAction *handler) {
			BOOL hidden = jbev_is_hidden();
			jbev_run(hidden ? "apphide-showall" : "apphide-all");
		}] forControlEvents:UIControlEventTouchUpInside];
		[self.view addSubview:jbevToggleButton];
	}

	UIColor *tint = jbev_is_hidden() ? [UIColor systemOrangeColor] : [UIColor systemGreenColor];
	UIFont *font = [UIFont systemFontOfSize:20];
	UIImageSymbolConfiguration *cfg = [UIImageSymbolConfiguration configurationWithPointSize:18 weight:UIImageSymbolWeightBold];
	NSString *symbol = jbev_is_hidden() ? @"eye.slash.fill" : @"eye.fill";
	UIImage *img = [UIImage systemImageNamed:symbol withConfiguration:cfg];
	[jbevToggleButton setImage:img forState:UIControlStateNormal];
	jbevToggleButton.tintColor = tint;

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