#import <Foundation/Foundation.h>

@interface APSConnection : NSObject
+ (NSString *)connectionsDebuggingStateOfStyle:(unsigned long long)style;
+ (void)finishLogin;
@end