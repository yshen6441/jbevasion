#import <UIKit/UIKit.h>
#import <spawn.h>
#import <sys/wait.h>
#import <dlfcn.h>
#import <string.h>
#import <unistd.h>

extern char **environ;

static int (*my_persona_set)(const posix_spawnattr_t * __restrict, int, uid_t) = NULL;
static int (*my_persona_uid)(const posix_spawnattr_t * __restrict, uid_t) = NULL;
static int (*my_persona_gid)(const posix_spawnattr_t * __restrict, gid_t) = NULL;

__attribute__((constructor))
static void load_persona_api(void) {
    void *h = dlopen(NULL, RTLD_LAZY);
    if (h) {
        my_persona_set = dlsym(h, "posix_spawnattr_set_persona_np");
        my_persona_uid = dlsym(h, "posix_spawnattr_set_persona_uid_np");
        my_persona_gid = dlsym(h, "posix_spawnattr_set_persona_gid_np");
    }
}

static int run_as_root(const char *path, char *const argv[]) {
    pid_t pid = 0;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    if (my_persona_set) my_persona_set(&attr, 1, 0);
    if (my_persona_uid) my_persona_uid(&attr, 0);
    if (my_persona_gid) my_persona_gid(&attr, 0);
    int r = posix_spawn(&pid, path, NULL, &attr, argv, environ);
    posix_spawnattr_destroy(&attr);
    if (r != 0) return r;
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];

    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = UIColor.systemBackgroundColor;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 120, self.window.frame.size.width - 40, 40)];
    title.text = @"越狱环境app隐藏";
    title.textAlignment = NSTextAlignmentCenter;
    title.font = [UIFont boldSystemFontOfSize:24];
    [vc.view addSubview:title];

    UILabel *desc = [[UILabel alloc] initWithFrame:CGRectMake(20, 170, self.window.frame.size.width - 40, 40)];
    desc.text = @"打开开关隐藏所有越狱应用，关闭恢复";
    desc.numberOfLines = 0;
    desc.textAlignment = NSTextAlignmentCenter;
    desc.font = [UIFont systemFontOfSize:15];
    desc.textColor = UIColor.secondaryLabelColor;
    [vc.view addSubview:desc];

    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(0, 0, 0, 0)];
    sw.center = CGPointMake(self.window.frame.size.width / 2, 270);
    sw.onTintColor = UIColor.systemRedColor;
    sw.transform = CGAffineTransformMakeScale(1.5, 1.5);
    [vc.view addSubview:sw];

    UILabel *statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 310, self.window.frame.size.width - 40, 30)];
    statusLabel.textAlignment = NSTextAlignmentCenter;
    statusLabel.font = [UIFont systemFontOfSize:14];
    [vc.view addSubview:statusLabel];

    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleLarge];
    spinner.center = CGPointMake(self.window.frame.size.width / 2, 380);
    spinner.hidesWhenStopped = YES;
    [vc.view addSubview:spinner];

    /* Check initial state */
    const char *jbpath = "/var/jb/usr/bin/jbevasion";
    if (access(jbpath, X_OK) != 0) jbpath = "/usr/bin/jbevasion";

    NSString *stash = @"/var/jb/.apphide-stash";
    BOOL hasHidden = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:stash error:nil].count > 0;
    sw.on = hasHidden;
    statusLabel.text = hasHidden ? @"已隐藏，关闭可恢复" : @"未隐藏，打开可隐藏";

    [sw addTarget:self action:@selector(switchChanged:) forControlEvents:UIControlEventValueChanged];
    objc_setAssociatedObject(sw, "statusLabel", statusLabel, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(sw, "spinner", spinner, OBJC_ASSOCIATION_RETAIN);
    objc_setAssociatedObject(sw, "jbpath", [NSString stringWithUTF8String:jbpath], OBJC_ASSOCIATION_RETAIN);

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    return YES;
}

- (void)switchChanged:(UISwitch *)sender {
    UILabel *statusLabel = (UILabel *)objc_getAssociatedObject(sender, "statusLabel");
    UIActivityIndicatorView *spinner = (UIActivityIndicatorView *)objc_getAssociatedObject(sender, "spinner");
    NSString *jbpath = (NSString *)objc_getAssociatedObject(sender, "jbpath");

    sender.enabled = NO;
    [spinner startAnimating];
    statusLabel.text = sender.on ? @"正在隐藏…" : @"正在恢复…";

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        const char *cmd = sender.on ? "apphide-all" : "apphide-showall";
        char *args[] = { (char *)[jbpath UTF8String], (char *)cmd, NULL };
        int r = run_as_root([jbpath UTF8String], args);

        dispatch_async(dispatch_get_main_queue(), ^{
            [spinner stopAnimating];
            sender.enabled = YES;
            if (r == 0) {
                statusLabel.text = sender.on ? @"已隐藏" : @"已恢复";
            } else {
                statusLabel.text = [NSString stringWithFormat:@"操作失败: %d", r];
                sender.on = !sender.on;
            }
        });
    });
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}