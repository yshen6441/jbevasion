#ifndef PSSPECIFIER_H
#define PSSPECIFIER_H

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@class PSListController;

@interface PSSpecifier : NSObject
@property(nonatomic, retain) id target;
@property(nonatomic, retain) NSString *name;
@property(nonatomic, retain) id value;
@property(nonatomic, retain) NSArray *values;
@property(nonatomic, retain) NSDictionary *titleDictionary;
@property(nonatomic, retain) NSString *identifier;
@property(nonatomic, retain) NSDictionary *userInfo;
@property(nonatomic, readonly) Class cellClass;
+ (instancetype)preferenceSpecifierNamed:(NSString *)name target:(id)target set:(SEL)set get:(SEL)get detail:(Class)detail cell:(int)cell edit:(Class)edit;
- (id)propertyForKey:(NSString *)key;
- (void)setProperty:(id)property forKey:(NSString *)key;
- (SEL)getter;
- (SEL)setter;
- (void)performGetter;
- (void)performSetterWithValue:(id)value;
@end

#endif
