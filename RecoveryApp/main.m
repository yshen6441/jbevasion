#import <UIKit/UIKit.h>
#import <spawn.h>
#import <sys/wait.h>
#import <string.h>
#import <unistd.h>
#import <fcntl.h>
extern char **environ;

@interface ViewController : UIViewController
@property (strong, nonatomic) UILabel *statusLabel;
@property (strong, nonatomic) UIActivityIndicatorView *spinner;
@property (strong, nonatomic) UITextView *logView;
- (void)appendLog:(NSString *)msg;
@end

@implementation ViewController

- (void)appendLog:(NSString *)msg {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.logView.text = [self.logView.text stringByAppendingFormat:@"%@\n", msg];
        [self.logView scrollRangeToVisible:NSMakeRange(self.logView.text.length, 0)];
    });
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;
    CGFloat w = self.view.frame.size.width;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 60, w - 40, 36)];
    title.text = @"越狱环境app隐藏";
    title.textAlignment = NSTextAlignmentCenter;
    title.font = [UIFont boldSystemFontOfSize:22];
    [self.view addSubview:title];

    UISwitch *sw = [[UISwitch alloc] init];
    sw.center = CGPointMake(w / 2, 120);
    sw.onTintColor = UIColor.systemRedColor;
    sw.transform = CGAffineTransformMakeScale(1.3, 1.3);
    [sw addTarget:self action:@selector(switchChanged:) forControlEvents:UIControlEventValueChanged];
    [self.view addSubview:sw];

    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 145, w - 40, 24)];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.font = [UIFont systemFontOfSize:13];
    [self.view addSubview:self.statusLabel];

    self.spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    self.spinner.center = CGPointMake(w / 2, 185);
    self.spinner.hidesWhenStopped = YES;
    [self.view addSubview:self.spinner];

    self.logView = [[UITextView alloc] initWithFrame:CGRectMake(10, 200, w - 20, self.view.frame.size.height - 210)];
    self.logView.editable = NO;
    self.logView.font = [UIFont fontWithName:@"Menlo" size:10];
    self.logView.backgroundColor = UIColor.blackColor;
    self.logView.textColor = UIColor.greenColor;
    self.logView.layer.cornerRadius = 8;
    self.logView.contentInset = UIEdgeInsetsMake(4, 4, 4, 4);
    [self.view addSubview:self.logView];

    [self appendLog:@"=== AppHide Recovery ==="];

    const char *jbpath = "/var/jb/usr/bin/jbevasion";
    int acc = access(jbpath, X_OK);
    [self appendLog:[NSString stringWithFormat:@"jbevasion at %s: %s", jbpath, acc == 0 ? "YES" : "NO"]];

    if (acc != 0) {
        jbpath = "/usr/bin/jbevasion";
        acc = access(jbpath, X_OK);
        [self appendLog:[NSString stringWithFormat:@"jbevasion at %s: %s", jbpath, acc == 0 ? "YES" : "NO"]];
    }

    [self appendLog:[NSString stringWithFormat:@"uid=%d gid=%d", getuid(), getgid()]];

    NSString *stash = @"/var/jb/.apphide-stash";
    NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:stash error:nil];
    BOOL hasHidden = contents.count > 0;
    [self appendLog:[NSString stringWithFormat:@"stash dir %@: %ld entries", stash, (long)contents.count]];

    sw.on = hasHidden;
    self.statusLabel.text = hasHidden ? @"已隐藏，关闭可恢复" : @"未隐藏，打开可隐藏";
}

- (void)switchChanged:(UISwitch *)sender {
    sender.enabled = NO;
    [self.spinner startAnimating];
    self.statusLabel.text = sender.on ? @"正在隐藏…" : @"正在恢复…";
    [self appendLog:[NSString stringWithFormat:@"\n>>> %@", sender.on ? @"隐藏所有" : @"恢复所有"]];

    const char *jbpath = "/var/jb/usr/bin/jbevasion";
    if (access(jbpath, X_OK) != 0) jbpath = "/usr/bin/jbevasion";
    const char *cmd = sender.on ? "apphide-all" : "apphide-showall";
    [self appendLog:[NSString stringWithFormat:@"cmd: %s %s", jbpath, cmd]];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [self appendLog:@"persona: skipped (causes ESRCH), relying on setuid bit"];

        int out_pipe[2], err_pipe[2];
        pipe(out_pipe);
        pipe(err_pipe);

        posix_spawn_file_actions_t actions;
        posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_adddup2(&actions, out_pipe[1], STDOUT_FILENO);
        posix_spawn_file_actions_adddup2(&actions, err_pipe[1], STDERR_FILENO);
        posix_spawn_file_actions_addclose(&actions, out_pipe[0]);
        posix_spawn_file_actions_addclose(&actions, err_pipe[0]);

        pid_t pid = 0;
        posix_spawnattr_t attr;
        posix_spawnattr_init(&attr);
        char *const args[] = { (char *)jbpath, (char *)cmd, NULL };
        int spawn_rc = posix_spawn(&pid, jbpath, &actions, &attr, args, environ);
        posix_spawnattr_destroy(&attr);
        posix_spawn_file_actions_destroy(&actions);

        close(out_pipe[1]);
        close(err_pipe[1]);

        if (spawn_rc != 0) {
            [self appendLog:[NSString stringWithFormat:@"posix_spawn failed: %s", strerror(spawn_rc)]];
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.spinner stopAnimating];
                sender.enabled = YES;
                self.statusLabel.text = [NSString stringWithFormat:@"spawn失败: %d", spawn_rc];
                sender.on = !sender.on;
            });
            close(out_pipe[0]);
            close(err_pipe[0]);
            return;
        }

        [self appendLog:[NSString stringWithFormat:@"pid=%d", pid]];

        char buf[4096];
        ssize_t n;
        while ((n = read(out_pipe[0], buf, sizeof(buf) - 1)) > 0) {
            buf[n] = '\0';
            [self appendLog:[NSString stringWithUTF8String:buf]];
        }
        while ((n = read(err_pipe[0], buf, sizeof(buf) - 1)) > 0) {
            buf[n] = '\0';
            [self appendLog:[NSString stringWithFormat:@"stderr: %s", buf]];
        }
        close(out_pipe[0]);
        close(err_pipe[0]);

        int status = 0;
        waitpid(pid, &status, 0);
        int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        [self appendLog:[NSString stringWithFormat:@"exit code: %d", exit_code]];

        dispatch_async(dispatch_get_main_queue(), ^{
            [self.spinner stopAnimating];
            sender.enabled = YES;
            if (exit_code == 0) {
                self.statusLabel.text = sender.on ? @"已隐藏" : @"已恢复";
                [self appendLog:@"OK"];
            } else {
                self.statusLabel.text = [NSString stringWithFormat:@"操作失败: %d", exit_code];
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