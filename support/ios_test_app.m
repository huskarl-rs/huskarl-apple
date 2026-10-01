// UIKit host for the Rust OAuth test executable. The linker enters
// huskarl_test_app_main; the generated Rust main runs after local-network
// permission has had a chance to complete in a foreground application.
#import <UIKit/UIKit.h>
#include <stdio.h>

extern int main(int argc, char **argv);
static int test_argc;
static char **test_argv;

@interface HuskarlTestAppDelegate : UIResponder <UIApplicationDelegate>
@end
@implementation HuskarlTestAppDelegate
@end

@interface HuskarlTestSceneDelegate : UIResponder <UIWindowSceneDelegate>
@property(nonatomic, strong) UIWindow *window;
@end

@implementation HuskarlTestSceneDelegate
- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session
      options:(UISceneConnectionOptions *)options {
    (void)session;
    (void)options;
    fprintf(stderr, "OAuth test launcher: application ready\n");
    self.window = [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)scene];
    UIViewController *controller = [UIViewController new];
    controller.view.backgroundColor = UIColor.systemBackgroundColor;
    UILabel *label = [[UILabel alloc] initWithFrame:controller.view.bounds];
    label.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    label.numberOfLines = 0;
    label.textAlignment = NSTextAlignmentCenter;
    label.text = @"OAuth mTLS test\n\nAllow Local Network access to connect to the test servers on your Mac.";
    [controller.view addSubview:label];
    self.window.rootViewController = controller;
    [self.window makeKeyAndVisible];

    // No credentials are sent by this preflight. Its purpose is to wait for
    // local-network permission. The private test CA is intentionally not in
    // system trust; the Rust client performs the actual trusted TLS requests.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        NSURL *fixture = [NSBundle.mainBundle.bundleURL URLByAppendingPathComponent:@"oauth-fixture/metadata.json"];
        NSDictionary *metadata = [NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfURL:fixture]
                                                                 options:0 error:nil];
        NSURL *url = [NSURL URLWithString:metadata[@"issuer"]];
        NSURLSessionConfiguration *config = NSURLSessionConfiguration.ephemeralSessionConfiguration;
        config.waitsForConnectivity = YES;
        config.timeoutIntervalForResource = 60;
        NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
        [[session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            (void)data;
            (void)response;
            if (error && error.code != NSURLErrorServerCertificateUntrusted) {
                fprintf(stderr, "OAuth test launcher: preflight error %ld; running Rust checks for details\n", (long)error.code);
            } else {
                fprintf(stderr, "OAuth test launcher: network ready; Rust will validate the test CA\n");
            }
            [session finishTasksAndInvalidate];
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                exit(main(test_argc, test_argv));
            });
        }] resume];
    });
}
@end

int huskarl_test_app_main(int argc, char **argv) {
    fprintf(stderr, "OAuth test launcher: starting UIKit\n");
    test_argc = argc;
    test_argv = argv;
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(HuskarlTestAppDelegate.class));
    }
}
