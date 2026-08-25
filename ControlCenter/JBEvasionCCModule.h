#import <UIKit/UIKit.h>

@interface JBEvasionCCModule : NSObject
@property (nonatomic, assign, getter=_selected) BOOL selected;
@property (nonatomic, copy, readonly) UIImage *iconGlyph;
@property (nonatomic, copy, readonly) UIColor *selectedColor;
@property (nonatomic, copy, readonly) NSString *moduleIdentifier;
- (void)setSelected:(BOOL)selected;
@end