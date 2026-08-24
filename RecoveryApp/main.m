#import <UIKit/UIKit.h>
#import <spawn.h>
#import <sys/wait.h>
#import <dlfcn.h>

extern char **environ;

/* Private persona API loaded via dlsym to avoid linker dependency on SDK stubs */
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
    return status;
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = UIColor.systemBackgroundColor;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 100, 300, 40)];
    title.text = @"AppHide 恢复工具";
    title.textAlignment = NSTextAlignmentCenter;
    title.font = [UIFont boldSystemFontOfSize:22];
    [vc.view addSubview:title];

    UILabel *desc = [[UILabel alloc] initWithFrame:CGRectMake(20, 150, 300, 60)];
    desc.text = @"将 /var/jb/Applications/ 下隐藏的 app 恢复到原位，然后重启桌面。";
    desc.numberOfLines = 0;
    desc.textAlignment = NSTextAlignmentCenter;
    desc.font = [UIFont systemFontOfSize:14];
    desc.textColor = UIColor.secondaryLabelColor;
    [vc.view addSubview:desc];

    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = CGRectMake(40, 260, 280, 54);
    btn.backgroundColor = UIColor.systemBlueColor;
    [btn setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [btn setTitle:@"恢复所有隐藏应用" forState:UIControlStateNormal];
    btn.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    btn.layer.cornerRadius = 14;
    btn.clipsToBounds = YES;
    [btn addTarget:self action:@selector(restoreTapped) forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:btn];

    UIButton *respringBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    respringBtn.frame = CGRectMake(40, 330, 280, 44);
    respringBtn.backgroundColor = UIColor.systemGrayColor;
    [respringBtn setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [respringBtn setTitle:@"仅重启桌面（不恢复）" forState:UIControlStateNormal];
    respringBtn.titleLabel.font = [UIFont systemFontOfSize:16];
    respringBtn.layer.cornerRadius = 12;
    respringBtn.clipsToBounds = YES;
    [respringBtn addTarget:self action:@selector(respringTapped) forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:respringBtn];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    return YES;
}

- (void)restoreTapped {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"恢复中"
        message:@"正在恢复隐藏的应用并重启桌面…"
        preferredStyle:UIAlertControllerStyleAlert];
    [self.window.rootViewController presentViewController:alert animated:YES completion:nil];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        char *showall[] = { "/var/jb/usr/bin/jbevasion", "apphide-showall", NULL };
        int r1 = run_as_root("/var/jb/usr/bin/jbevasion", showall);
        char *respring[] = { "/var/jb/usr/bin/jbevasion", "respring", NULL };
        int r2 = run_as_root("/var/jb/usr/bin/jbevasion", respring);

        dispatch_async(dispatch_get_main_queue(), ^{
            [alert dismissViewControllerAnimated:YES completion:nil];
            NSString *msg = (r1 == 0 && r2 == 0)
                ? @"恢复完成，桌面即将重启。"
                : [NSString stringWithFormat:@"恢复出错 (showall=%d, respring=%d)", r1, r2];
            UIAlertController *done = [UIAlertController alertControllerWithTitle:@"完成"
                message:msg preferredStyle:UIAlertControllerStyleAlert];
            [done addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [self.window.rootViewController presentViewController:done animated:YES completion:nil];
        });
    });
}

- (void)respringTapped {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"重启桌面"
        message:@"正在重启 SpringBoard…"
        preferredStyle:UIAlertControllerStyleAlert];
    [self.window.rootViewController presentViewController:alert animated:YES completion:nil];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        char *args[] = { "/var/jb/usr/bin/jbevasion", "respring", NULL };
        int r = run_as_root("/var/jb/usr/bin/jbevasion", args);

        dispatch_async(dispatch_get_main_queue(), ^{
            [alert dismissViewControllerAnimated:YES completion:nil];
            NSString *msg = (r == 0) ? @"桌面已重启。" : [NSString stringWithFormat:@"respring 失败: %d", r];
            UIAlertController *done = [UIAlertController alertControllerWithTitle:@"完成"
                message:msg preferredStyle:UIAlertControllerStyleAlert];
            [done addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [self.window.rootViewController presentViewController:done animated:YES completion:nil];
        });
    });
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}