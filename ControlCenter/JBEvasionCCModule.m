#import "JBEvasionCCModule.h"
#include "krw.h"
#include "apphide.h"
#include <dlfcn.h>
#include <dirent.h>
#include <sys/stat.h>

#define STASH_DIR "/var/jb/.apphide-stash"

static BOOL apps_are_hidden(void) {
    DIR *d = opendir(STASH_DIR);
    if (!d) return NO;
    BOOL found = NO;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strstr(ent->d_name, ".app")) { found = YES; break; }
    }
    closedir(d);
    return found;
}

@implementation JBEvasionCCModule

- (UIImage *)iconGlyph {
    return [UIImage systemImageNamed:@"eye.slash.circle.fill"];
}

- (UIColor *)selectedColor {
    return [UIColor systemGreenColor];
}

- (BOOL)_selected {
    return apps_are_hidden();
}

- (void)setSelected:(BOOL)selected {
    [super setSelected:selected];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int ret = krw_init();
        if (ret != 0) {
            NSLog(@"JBEvasionCC: krw_init failed (%d)", ret);
            return;
        }
        if (selected) {
            apphide_hide_all();
            NSLog(@"JBEvasionCC: hidden all apps");
        } else {
            apphide_unhide_all();
            NSLog(@"JBEvasionCC: restored all apps");
        }
    });
}

@end