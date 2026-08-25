#import <UIKit/UIKit.h>

@interface CCUIToggleModule : NSObject
@property (nonatomic, assign, getter=_selected) BOOL selected;
@property (nonatomic, copy, readonly) UIImage *iconGlyph;
@property (nonatomic, copy, readonly) UIColor *selectedColor;
- (void)setSelected:(BOOL)selected;
@end

@interface JBEvasionCCModule : CCUIToggleModule
@end