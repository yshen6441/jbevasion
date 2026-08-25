#ifndef PSLISTCONTROLLER_H
#define PSLISTCONTROLLER_H

#import <UIKit/UIKit.h>
#import "PSSpecifier.h"

@class PSSpecifier;

@interface PSListController : UIViewController
@property(nonatomic, retain) NSArray *specifiers;
@property(nonatomic, retain) NSMutableArray *groups;
@property(nonatomic, retain) UITableView *table;
- (NSArray *)loadSpecifiersFromPlistName:(NSString *)name target:(id)target;
- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier;
- (id)readPreferenceValue:(PSSpecifier *)specifier;
- (void)reloadSpecifiers;
- (void)reloadSpecifier:(PSSpecifier *)specifier animated:(BOOL)animated;
@end

#endif
