#import <UIKit/UIKit.h>
#import <spawn.h>
#import <sys/wait.h>
#import <string.h>
#import <unistd.h>

extern char **environ;

static int run_cmd(const char *path, char *const argv[]) {
    pid_t pid = 0;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    int r = posix_spawn(&pid, path, NULL, &attr, argv, environ);
    posix_spawnattr_destroy(&attr);
    if (r != 0) return r;
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

@interface ViewController : UIViewController
@property (strong, nonatomic) UILabel *statusLabel;
@property (strong, nonatomic) UIActivityIndicatorView *spinner;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 120, self.view.frame.size.width - 40, 40)];
    title.text = @"越狱环境app隐藏";
    title.textAlignment = NSTextAlignmentCenter;
    title.font = [UIFont boldSystemFontOfSize:24];
    [self.view addSubview:title];

    UILabel *desc = [[UILabel alloc] initWithFrame:CGRectMake(20, 170, self.view.frame.size.width - 40, 40)];
    desc.text = @"打开开关隐藏所有越狱应用，关闭恢复";
    desc.numberOfLines = 0;
    desc.textAlignment = NSTextAlignmentCenter;
    desc.font = [UIFont systemFontOfSize:15];
    desc.textColor = UIColor.secondaryLabelColor;
    [self.view addSubview:desc];

    UISwitch *sw = [[UISwitch alloc] initWithFrame:CGRectMake(0, 0, 0, 0)];
    sw.center = CGPointMake(self.view.frame.size.width / 2, 270);
    sw.onTintColor = UIColor.systemRedColor;
    sw.transform = CGAffineTransformMakeScale(1.5, 1.5);
    [sw addTarget:self action:@selector(switchChanged:) forControlEvents:UIControlEventValueChanged];
    [self.view addSubview:sw];

    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 310, self.view.frame.size.width - 40, 30)];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.font = [UIFont systemFontOfSize:14];
    [self.view addSubview:self.statusLabel];

    self.spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleLarge];
    self.spinner.center = CGPointMake(self.view.frame.size.width / 2, 380);
    self.spinner.hidesWhenStopped = YES;
    [self.view addSubview:self.spinner];

    NSString *stash = @"/var/jb/.apphide-stash";
    NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:stash error:nil];
    BOOL hasHidden = contents.count > 0;
    sw.on = hasHidden;
    self.statusLabel.text = hasHidden ? @"已隐藏，关闭可恢复" : @"未隐藏，打开可隐藏";
}

- (void)switchChanged:(UISwitch *)sender {
    sender.enabled = NO;
    [self.spinner startAnimating];
    self.statusLabel.text = sender.on ? @"正在隐藏…" : @"正在恢复…";

    const char *jbpath = "/var/jb/usr/bin/jbevasion";
    if (access(jbpath, X_OK) != 0) jbpath = "/usr/bin/jbevasion";
    const char *cmd = sender.on ? "apphide-all" : "apphide-showall";
    char *const args[] = { (char *)jbpath, (char *)cmd, NULL };

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int r = run_cmd(jbpath, args);

        dispatch_async(dispatch_get_main_queue(), ^{
            [self.spinner stopAnimating];
            sender.enabled = YES;
            if (r == 0) {
                self.statusLabel.text = sender.on ? @"已隐藏" : @"已恢复";
            } else {
                self.statusLabel.text = [NSString stringWithFormat:@"操作失败: %d", r];
                sender.on = !sender.on;
            }
        });
    });
}

@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [[ViewController alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}