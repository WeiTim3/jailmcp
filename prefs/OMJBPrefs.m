// OpenMinis-Jailbreak native Settings pane.
// Runs inside Preferences.app (UID 501, no sandbox). It talks to the bridge
// over 127.0.0.1:18765 with the same bearer token the MCP client uses.
#import <UIKit/UIKit.h>
#import <Preferences/Preferences.h>
#import <errno.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <sys/socket.h>
#import <sys/time.h>
#import <unistd.h>
#import <string.h>
#import <stdlib.h>
#import <stdio.h>
#import <stdarg.h>

static NSString * const OMJBTokenRelative =
    @"Documents/OpenMinis-Jailbreak/.bridge-state/token";
static NSString * const OMJBMCPURL = @"http://127.0.0.1:18765/mcp";

static void OMJBTrace(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *line = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    NSArray *paths = @[@"/var/mobile/Documents/OpenMinis-Jailbreak/prefs-trace.log",
                       [NSTemporaryDirectory() stringByAppendingPathComponent:@"prefs-trace.log"] ?: @""];
    for (NSString *path in paths) {
        if (path.length == 0) continue;
        FILE *file = fopen([path fileSystemRepresentation], "a");
        if (file) { fprintf(file, "%s\n", [line UTF8String]); fclose(file); }
    }
}

#pragma mark - Token discovery

// Settings sees the SYSTEM data volume at /var/mobile, while the bridge lives in
// the roothide jbroot. Try the direct path first, then the visible jbroot
// directories. Settings.app carries com.apple.private.security.no-sandbox, so
// it can read a 0600 mobile-owned token once the path is found.
static NSString *OMJBTokenPath(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray *candidates = [NSMutableArray arrayWithObjects:
        [@"/var/mobile" stringByAppendingPathComponent:OMJBTokenRelative],
        [@"/rootfs/private/var/mobile" stringByAppendingPathComponent:OMJBTokenRelative],
        [@"/private/var/mobile" stringByAppendingPathComponent:OMJBTokenRelative],
        nil];
    NSArray *roots = @[@"/rootfs/private/var/mobile/Containers/Shared/AppGroup",
                       @"/var/mobile/Containers/Shared/AppGroup"];
    for (NSString *root in roots) {
        NSArray *entries = [fm contentsOfDirectoryAtPath:root error:nil];
        for (NSString *name in entries) {
            if (![name hasPrefix:@".jbroot-"]) continue;
            NSString *token = [root stringByAppendingPathComponent:
                [name stringByAppendingPathComponent:
                    [@"var/mobile" stringByAppendingPathComponent:OMJBTokenRelative]]];
            [candidates addObject:token];
        }
    }
    for (NSString *path in candidates) {
        NSString *value = [NSString stringWithContentsOfFile:path
                                                    encoding:NSUTF8StringEncoding
                                                       error:nil];
        value = [value stringByTrimmingCharactersInSet:
                 [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (value.length >= 32 && value.length <= 128) return path;
    }
    return nil;
}

static NSDictionary *OMJBDict(id value) {
    return [value isKindOfClass:[NSDictionary class]] ? value : nil;
}

static BOOL OMJBBool(id value) {
    return [value isKindOfClass:[NSNumber class]] ? [value boolValue] : NO;
}

static NSString *OMJBReadToken(void) {
    NSString *path = OMJBTokenPath();
    if (!path) return nil;
    NSString *value = [NSString stringWithContentsOfFile:path
                                                encoding:NSUTF8StringEncoding
                                                   error:nil];
    value = [value stringByTrimmingCharactersInSet:
             [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    return value.length ? value : nil;
}

#pragma mark - Errors and raw loopback HTTP

static NSError *OMJBError(NSString *message, NSString *code, NSString *ref) {
    NSMutableDictionary *info = [NSMutableDictionary dictionary];
    info[NSLocalizedDescriptionKey] = message ?: @"操作失败";
    if (code.length) info[@"code"] = code;
    if (ref.length) info[@"ref"] = ref;
    return [NSError errorWithDomain:@"OpenMinisJailbreak" code:1 userInfo:info];
}

static NSString *OMJBDescribe(NSError *error) {
    if (!error) return @"";
    NSString *text = error.localizedDescription ?: @"操作失败";
    NSString *code = error.userInfo[@"code"];
    NSString *ref = error.userInfo[@"ref"];
    if (code.length) {
        text = [text stringByAppendingFormat:@"（%@%@）", code,
                ref.length ? [@", ref " stringByAppendingString:ref] : @""];
    }
    return text;
}

// Raw sockets avoid ATS entirely and keep the client small. The bridge always
// answers with Content-Length and Connection: close.
static NSData *OMJBRequest(NSString *method, NSString *path, NSData *body,
                           NSString *token, NSInteger *statusOut,
                           NSError **errorOut) {
    if (statusOut) *statusOut = 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        if (errorOut) *errorOut = OMJBError(@"无法创建本地 socket", @"ESOCKET", nil);
        return nil;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    struct timeval timeout = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(18765);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(fd);
        if (errorOut) *errorOut = OMJBError(@"bridge 未运行或回环端口不可达", @"ENOCONN", nil);
        return nil;
    }
    NSMutableString *head = [NSMutableString stringWithFormat:
        @"%@ %@ HTTP/1.1\r\nHost: 127.0.0.1:18765\r\n"
         "Authorization: Bearer %@\r\nConnection: close\r\n",
        method, path, token];
    if (body) {
        [head appendFormat:@"Content-Type: application/json\r\nContent-Length: %lu\r\n",
                           (unsigned long)body.length];
    }
    [head appendString:@"\r\n"];
    NSMutableData *request = [[head dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    if (body) [request appendData:body];
    const uint8_t *cursor = request.bytes;
    size_t remaining = request.length;
    while (remaining > 0) {
        ssize_t sent = send(fd, cursor, remaining, 0);
        if (sent <= 0) {
            close(fd);
            if (errorOut) *errorOut = OMJBError(@"发送请求失败", @"ESEND", nil);
            return nil;
        }
        cursor += sent;
        remaining -= (size_t)sent;
    }
    shutdown(fd, SHUT_WR);
    NSMutableData *response = [NSMutableData data];
    uint8_t buffer[16384];
    while (response.length < 2 * 1024 * 1024) {
        ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
        if (received <= 0) break;
        [response appendBytes:buffer length:(NSUInteger)received];
    }
    close(fd);
    if (response.length == 0) {
        if (errorOut) *errorOut = OMJBError(@"bridge 没有返回数据", @"EEMPTY", nil);
        return nil;
    }
    NSData *separator = [@"\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding];
    NSRange split = [response rangeOfData:separator options:0
                                    range:NSMakeRange(0, response.length)];
    if (split.location == NSNotFound) {
        if (errorOut) *errorOut = OMJBError(@"HTTP 响应格式错误", @"EPROTO", nil);
        return nil;
    }
    NSData *headData = [response subdataWithRange:NSMakeRange(0, split.location)];
    NSString *headText = [[NSString alloc] initWithData:headData encoding:NSUTF8StringEncoding];
    NSArray *lines = [headText componentsSeparatedByString:@"\r\n"];
    int status = 0;
    if (lines.count) sscanf([lines[0] UTF8String], "HTTP/%*s %d", &status);
    if (statusOut) *statusOut = status;
    NSData *payload = [response subdataWithRange:
        NSMakeRange(NSMaxRange(split), response.length - NSMaxRange(split))];
    NSUInteger declared = NSUIntegerMax;
    for (NSUInteger i = 1; i < lines.count; i++) {
        NSString *line = lines[i];
        NSRange colon = [line rangeOfString:@":"];
        if (colon.location == NSNotFound) continue;
        NSString *name = [[line substringToIndex:colon.location]
                          lowercaseString];
        if ([name isEqualToString:@"content-length"]) {
            declared = (NSUInteger)[[line substringFromIndex:colon.location + 1]
                                    integerValue];
        }
    }
    if (declared != NSUIntegerMax && payload.length > declared) {
        payload = [payload subdataWithRange:NSMakeRange(0, declared)];
    }
    return payload;
}

static id OMJBJSON(NSData *data, NSError **error) {
    if (!data.length) return nil;
    return [NSJSONSerialization JSONObjectWithData:data options:0 error:error];
}

#pragma mark - Bridge client

@interface OMJBClient : NSObject
+ (void)fetchStatus:(void (^)(NSDictionary *device, NSDictionary *info, NSError *error))completion;
+ (void)fetchConfig:(void (^)(NSDictionary *config, NSError *error))completion;
+ (void)setConfig:(NSDictionary *)patch completion:(void (^)(NSDictionary *config, NSError *error))completion;
+ (void)callTool:(NSString *)name arguments:(NSDictionary *)arguments
      completion:(void (^)(NSDictionary *value, NSError *error))completion;
+ (void)restart:(void (^)(NSError *error))completion;
+ (void)rollback:(void (^)(NSError *error))completion;
+ (void)logTail:(void (^)(NSString *text, NSError *error))completion;
+ (NSString *)token;
@end

@implementation OMJBClient

+ (NSString *)token { return OMJBReadToken(); }

+ (void)callTool:(NSString *)name arguments:(NSDictionary *)arguments
      completion:(void (^)(NSDictionary *, NSError *))completion {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *token = OMJBReadToken();
        if (!token) {
            completion(nil, OMJBError(@"找不到 bridge token", @"EAUTH", nil));
            return;
        }
        NSDictionary *payload = @{
            @"jsonrpc": @"2.0", @"id": @1, @"method": @"tools/call",
            @"params": @{ @"name": name, @"arguments": arguments ?: @{} }
        };
        NSError *jsonError = nil;
        NSData *body = [NSJSONSerialization dataWithJSONObject:payload options:0 error:&jsonError];
        if (!body) {
            completion(nil, OMJBError(@"无法编码请求", @"EJSON", nil));
            return;
        }
        NSInteger status = 0;
        NSError *netError = nil;
        NSData *response = OMJBRequest(@"POST", @"/mcp", body, token, &status, &netError);
        if (!response) { completion(nil, netError); return; }
        if (status == 401) {
            completion(nil, OMJBError(@"token 无效或已轮换", @"EAUTH", nil));
            return;
        }
        NSError *parseError = nil;
        id json = OMJBJSON(response, &parseError);
        if (![json isKindOfClass:[NSDictionary class]]) {
            completion(nil, OMJBError([NSString stringWithFormat:@"bridge 返回 HTTP %ld", (long)status],
                                      @"EHTTP", nil));
            return;
        }
        NSDictionary *result = ((NSDictionary *)json)[@"result"];
        if (![result isKindOfClass:[NSDictionary class]]) {
            completion(nil, OMJBError(@"响应缺少 result", @"EPROTO", nil));
            return;
        }
        NSArray *content = result[@"content"];
        NSString *text = ([content isKindOfClass:[NSArray class]] && content.count)
            ? content[0][@"text"] : nil;
        if ([result[@"isError"] boolValue]) {
            NSDictionary *errorPayload = OMJBJSON([text dataUsingEncoding:NSUTF8StringEncoding], NULL);
            NSDictionary *detail = [errorPayload isKindOfClass:[NSDictionary class]]
                ? errorPayload[@"error"] : nil;
            completion(nil, OMJBError(detail[@"message"] ?: @"操作失败",
                                      detail[@"code"], detail[@"ref"]));
            return;
        }
        NSDictionary *value = OMJBJSON([text dataUsingEncoding:NSUTF8StringEncoding], NULL);
        completion([value isKindOfClass:[NSDictionary class]] ? value : @{}, nil);
    });
}

+ (void)fetchStatus:(void (^)(NSDictionary *, NSDictionary *, NSError *))completion {
    [self callTool:@"jb_device_info" arguments:@{} completion:^(NSDictionary *device, NSError *error) {
        if (error) { completion(nil, nil, error); return; }
        [self callTool:@"jb_maintenance_info" arguments:@{}
            completion:^(NSDictionary *info, NSError *error2) {
                completion(device, info, error2);
            }];
    }];
}

+ (void)fetchConfig:(void (^)(NSDictionary *, NSError *))completion {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *token = OMJBReadToken();
        if (!token) {
            completion(nil, OMJBError(@"找不到 bridge token", @"EAUTH", nil));
            return;
        }
        NSInteger status = 0; NSError *netError = nil;
        NSData *response = OMJBRequest(@"GET", @"/ui/api/config", nil, token, &status, &netError);
        if (!response) { completion(nil, netError); return; }
        if (status == 401) { completion(nil, OMJBError(@"token 无效或已轮换", @"EAUTH", nil)); return; }
        if (status == 404) {
            completion(nil, OMJBError(@"请先安装 0.3.14 或更高版本", @"EOLD", nil));
            return;
        }
        id json = OMJBJSON(response, NULL);
        if (![json isKindOfClass:[NSDictionary class]]) {
            completion(nil, OMJBError(@"配置响应格式错误", @"EPROTO", nil));
            return;
        }
        completion(json, nil);
    });
}

+ (void)setConfig:(NSDictionary *)patch
       completion:(void (^)(NSDictionary *, NSError *))completion {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *token = OMJBReadToken();
        if (!token) {
            completion(nil, OMJBError(@"找不到 bridge token", @"EAUTH", nil));
            return;
        }
        NSError *jsonError = nil;
        NSData *body = [NSJSONSerialization dataWithJSONObject:patch options:0 error:&jsonError];
        if (!body) { completion(nil, OMJBError(@"无法编码配置", @"EJSON", nil)); return; }
        NSInteger status = 0; NSError *netError = nil;
        NSData *response = OMJBRequest(@"POST", @"/ui/api/config", body, token, &status, &netError);
        if (!response) { completion(nil, netError); return; }
        id json = OMJBJSON(response, NULL);
        if (status != 200) {
            NSDictionary *detail = [json isKindOfClass:[NSDictionary class]] ? json[@"error"] : nil;
            completion(nil, OMJBError(detail[@"message"] ?: @"保存失败", detail[@"code"], nil));
            return;
        }
        if (![json isKindOfClass:[NSDictionary class]]) {
            completion(nil, OMJBError(@"配置响应格式错误", @"EPROTO", nil));
            return;
        }
        completion(json, nil);
    });
}

+ (void)restart:(void (^)(NSError *))completion {
    [self callTool:@"jb_restart" arguments:@{} completion:^(NSDictionary *value, NSError *error) {
        completion(error);
    }];
}

+ (void)rollback:(void (^)(NSError *))completion {
    [self callTool:@"jb_rollback" arguments:@{} completion:^(NSDictionary *value, NSError *error) {
        completion(error);
    }];
}

+ (void)logTail:(void (^)(NSString *, NSError *))completion {
    [self callTool:@"jb_log_tail" arguments:@{ @"limit": @50 }
        completion:^(NSDictionary *value, NSError *error) {
            if (error) { completion(nil, error); return; }
            completion(value[@"text"] ?: @"（暂无记录）", nil);
        }];
}

@end

#pragma mark - Root pane

@interface OMJBRootListController : PSListController
@property (nonatomic, strong) NSDictionary *device;
@property (nonatomic, strong) NSDictionary *info;
@property (nonatomic, strong) NSDictionary *config;
@property (nonatomic, copy) NSString *lastError;
@property (nonatomic, assign) BOOL loaded;
@property (nonatomic, assign) BOOL loading;
@end

@interface OMJBProjectListController : UITableViewController
@property (nonatomic, strong) NSMutableDictionary *projects;
@property (nonatomic, strong) NSError *loadError;
@end

@interface OMJBLogController : UIViewController
@property (nonatomic, strong) UITextView *textView;
@end

@implementation OMJBRootListController

- (instancetype)init {
    OMJBTrace(@"OMJB init");
    self = [super init];
    if (self) {
        _loaded = NO;
        _loading = NO;
    }
    return self;
}

- (void)viewDidLoad {
    OMJBTrace(@"OMJB viewDidLoad");
    [super viewDidLoad];
    self.title = @"OpenMinis JB";
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh
                                                      target:self
                                                      action:@selector(refresh:)];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self refresh:nil];
}

- (void)refresh:(id)sender {
    if (_loading) return;
    _loading = YES;
    _lastError = nil;
    dispatch_async(dispatch_get_main_queue(), ^{ [self reloadSpecifiers]; });
    __weak typeof(self) weakSelf = self;
    [OMJBClient fetchStatus:^(NSDictionary *device, NSDictionary *info, NSError *error) {
        OMJBRootListController *strongSelf = weakSelf;
        if (!strongSelf) return;
        if (!error) {
            strongSelf.device = device;
            strongSelf.info = info;
        } else {
            strongSelf.lastError = OMJBDescribe(error);
            strongSelf.device = nil;
            strongSelf.info = nil;
        }
        [OMJBClient fetchConfig:^(NSDictionary *config, NSError *configError) {
            OMJBRootListController *inner = weakSelf;
            if (!inner) return;
            if (!configError) {
                inner.config = config;
            } else if (!inner.lastError) {
                inner.lastError = OMJBDescribe(configError);
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                inner.loading = NO;
                inner.loaded = YES;
                [inner reloadSpecifiers];
            });
        }];
    }];
}

- (NSString *)shortHash:(NSString *)hash {
    if (![hash isKindOfClass:[NSString class]] || hash.length < 16) return hash ?: @"—";
    return [hash substringToIndex:16];
}

- (id)statusValue:(PSSpecifier *)specifier {
    NSString *key = specifier.identifier;
    if (!_loaded) return @"读取中…";
    NSDictionary *supervisor = OMJBDict(_info[@"supervisor"]);
    if ([key isEqualToString:@"health"]) {
        if (_lastError && !_info) return @"无法连接";
        BOOL healthy = OMJBBool(_info[@"supervised"]) &&
                       [supervisor[@"event"] isEqualToString:@"healthy"];
        return healthy ? @"运行中" : @"异常";
    }
    if ([key isEqualToString:@"version"]) return _device[@"bridge"] ?: @"—";
    if ([key isEqualToString:@"api"]) {
        id api = _info[@"api"];
        return api ? [NSString stringWithFormat:@"v%@", api] : @"—";
    }
    if ([key isEqualToString:@"pid"]) {
        id pid = _device[@"pid"]; id uid = _device[@"uid"];
        return (pid && uid) ? [NSString stringWithFormat:@"%@ / %@", pid, uid] : @"—";
    }
    if ([key isEqualToString:@"supervisor"]) {
        id pid = supervisor[@"supervisor_pid"];
        return pid ? [NSString stringWithFormat:@"%@", pid] : @"—";
    }
    if ([key isEqualToString:@"rollback"]) {
        NSString *previous = OMJBDict(_info[@"active"])[@"previous"];
        return previous.length ? [self shortHash:previous] : @"无";
    }
    if ([key isEqualToString:@"source"]) return [self shortHash:_device[@"source_sha256"]];
    if ([key isEqualToString:@"projects"]) {
        NSDictionary *projects = OMJBDict(_config[@"projects"]);
        return projects ? [NSString stringWithFormat:@"%lu 个", (unsigned long)projects.count] : @"—";
    }
    if ([key isEqualToString:@"url"]) return OMJBMCPURL;
    if ([key isEqualToString:@"error"]) return _lastError ?: @"无";
    return @"—";
}

- (id)shellValue:(PSSpecifier *)specifier {
    return @(OMJBBool(_config[@"allow_mobile_shell"]));
}

- (void)setShell:(id)value forSpecifier:(PSSpecifier *)specifier {
    BOOL enabled = [value boolValue];
    [OMJBClient setConfig:@{ @"allow_mobile_shell": @(enabled) }
               completion:^(NSDictionary *config, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error) {
                [self alert:@"保存失败" message:OMJBDescribe(error)];
            } else {
                self.config = config;
            }
            [self reloadSpecifiers];
        });
    }];
}

- (void)alert:(NSString *)title message:(NSString *)message {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert =
            [UIAlertController alertControllerWithTitle:title
                                                message:message
                                         preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"好"
                                                  style:UIAlertActionStyleDefault
                                                handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    });
}

- (void)confirm:(NSString *)title message:(NSString *)message
      okTitle:(NSString *)okTitle destructive:(BOOL)destructive
        action:(void (^)(void))action {
    UIAlertController *alert =
        [UIAlertController alertControllerWithTitle:title
                                            message:message
                                     preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:okTitle
                                              style:destructive ? UIAlertActionStyleDestructive
                                                                : UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) { action(); }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)restart {
    [self confirm:@"重启 bridge" message:@"连接会短暂中断，随后自动恢复。"
          okTitle:@"重启" destructive:NO action:^{
        [OMJBClient restart:^(NSError *error) {
            if (error) {
                [self alert:@"重启失败" message:OMJBDescribe(error)];
                return;
            }
            [self alert:@"已请求重启" message:@"几秒后自动恢复；返回本页可刷新状态。"];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ [self refresh:nil]; });
        }];
    }];
}

- (void)rollback {
    NSString *previous = OMJBDict(_info[@"active"])[@"previous"];
    if (!previous.length) {
        [self alert:@"没有可回退的版本" message:@"active.previous 为空。"];
        return;
    }
    [self confirm:[NSString stringWithFormat:@"回退到 %@…", [self shortHash:previous]]
          message:@"当前版本会保留，可以再次回退。"
          okTitle:@"回退" destructive:YES action:^{
        [OMJBClient rollback:^(NSError *error) {
            if (error) {
                [self alert:@"回退失败" message:OMJBDescribe(error)];
                return;
            }
            [self alert:@"已请求回退" message:@"supervisor 会在健康检查后切换版本。"];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ [self refresh:nil]; });
        }];
    }];
}

- (void)copyURL {
    [UIPasteboard generalPasteboard].string = OMJBMCPURL;
    [self alert:@"已复制" message:OMJBMCPURL];
}

- (void)copyToken {
    NSString *token = OMJBReadToken();
    if (!token) {
        [self alert:@"找不到 token" message:@"尝试了系统目录与 jbroot 路径。"];
        return;
    }
    [UIPasteboard generalPasteboard].string = token;
    [self alert:@"已复制 token" message:@"已放入剪贴板，请勿分享给不可信的应用。"];
}

- (void)manageProjects {
    OMJBProjectListController *controller = [[OMJBProjectListController alloc] init];
    [self.navigationController pushViewController:controller animated:YES];
}

- (void)showLog {
    OMJBLogController *controller = [[OMJBLogController alloc] init];
    [self.navigationController pushViewController:controller animated:YES];
}

@end

#pragma mark - Project roots

@implementation OMJBProjectListController

- (void)viewDidLoad {
    OMJBTrace(@"OMJB viewDidLoad");
    [super viewDidLoad];
    self.title = @"项目根";
    self.projects = [NSMutableDictionary dictionary];
    self.tableView.tableFooterView = [UIView new];
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemAdd
                                                      target:self
                                                      action:@selector(addProject:)];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self load];
}

- (void)load {
    __weak typeof(self) weakSelf = self;
    [OMJBClient fetchConfig:^(NSDictionary *config, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            OMJBProjectListController *strongSelf = weakSelf;
            if (!strongSelf) return;
            if (error) {
                strongSelf.loadError = error;
                strongSelf.projects = [NSMutableDictionary dictionary];
            } else {
                strongSelf.loadError = nil;
                NSDictionary *loaded = OMJBDict(config[@"projects"]);
                strongSelf.projects = loaded ? [loaded mutableCopy] : [NSMutableDictionary dictionary];
            }
            [strongSelf.tableView reloadData];
            if (error) [strongSelf alert:@"读取失败" message:OMJBDescribe(error)];
        });
    }];
}

- (NSArray *)sortedNames {
    return [[self.projects allKeys] sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.projects.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"project"];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:@"project"];
    }
    NSString *name = [self sortedNames][indexPath.row];
    cell.textLabel.text = name;
    cell.detailTextLabel.text = self.projects[name];
    cell.detailTextLabel.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

- (BOOL)tableView:(UITableView *)tableView canEditRowAtIndexPath:(NSIndexPath *)indexPath {
    return YES;
}

- (void)tableView:(UITableView *)tableView commitEditingStyle:(UITableViewCellEditingStyle)editingStyle
    forRowAtIndexPath:(NSIndexPath *)indexPath {
    if (editingStyle != UITableViewCellEditingStyleDelete) return;
    NSString *name = [self sortedNames][indexPath.row];
    NSMutableDictionary *next = [self.projects mutableCopy];
    [next removeObjectForKey:name];
    __weak typeof(self) weakSelf = self;
    [OMJBClient setConfig:@{ @"projects": next } completion:^(NSDictionary *config, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            OMJBProjectListController *strongSelf = weakSelf;
            if (!strongSelf) return;
            if (error) {
                [strongSelf alert:@"删除失败" message:OMJBDescribe(error)];
                [strongSelf.tableView reloadData];
                return;
            }
            NSDictionary *loaded = OMJBDict(config[@"projects"]);
            strongSelf.projects = loaded ? [loaded mutableCopy] : [NSMutableDictionary dictionary];
            [strongSelf.tableView reloadData];
        });
    }];
}

- (void)addProject:(id)sender {
    UIAlertController *alert =
        [UIAlertController alertControllerWithTitle:@"添加项目根"
                                            message:@"名称只允许字母、数字、. _ -；路径必须是已存在的目录。"
                                     preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.placeholder = @"名称，例如 work";
        field.autocapitalizationType = UITextAutocapitalizationTypeNone;
        field.autocorrectionType = UITextAutocorrectionTypeNo;
    }];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *field) {
        field.placeholder = @"/var/mobile/Documents/…";
        field.autocapitalizationType = UITextAutocapitalizationTypeNone;
        field.autocorrectionType = UITextAutocorrectionTypeNo;
        field.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    __weak typeof(self) weakSelf = self;
    [alert addAction:[UIAlertAction actionWithTitle:@"添加" style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *name = [alert.textFields[0].text stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        NSString *path = [alert.textFields[1].text stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (!name.length || !path.length) {
            [weakSelf alert:@"名称和路径都要填" message:nil];
            return;
        }
        NSMutableDictionary *next = [weakSelf.projects mutableCopy];
        next[name] = path;
        [OMJBClient setConfig:@{ @"projects": next } completion:^(NSDictionary *config, NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                OMJBProjectListController *strongSelf = weakSelf;
                if (!strongSelf) return;
                if (error) {
                    [strongSelf alert:@"添加失败" message:OMJBDescribe(error)];
                    return;
                }
                NSDictionary *loaded = OMJBDict(config[@"projects"]);
                strongSelf.projects = loaded ? [loaded mutableCopy] : [NSMutableDictionary dictionary];
                [strongSelf.tableView reloadData];
            });
        }];
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)alert:(NSString *)title message:(NSString *)message {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end

#pragma mark - Error log

@implementation OMJBLogController

- (void)viewDidLoad {
    OMJBTrace(@"OMJB viewDidLoad");
    [super viewDidLoad];
    self.title = @"错误日志";
    self.view.backgroundColor = [UIColor systemBackgroundColor];
    self.textView = [[UITextView alloc] initWithFrame:CGRectZero];
    self.textView.editable = NO;
    self.textView.selectable = YES;
    self.textView.alwaysBounceVertical = YES;
    self.textView.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    self.textView.textContainerInset = UIEdgeInsetsMake(12, 10, 20, 10);
    self.textView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.textView];
    [NSLayoutConstraint activateConstraints:@[
        [self.textView.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [self.textView.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
        [self.textView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [self.textView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
    ]];
    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh
                                                      target:self
                                                      action:@selector(load)];
    [self load];
}

- (void)load {
    __weak typeof(self) weakSelf = self;
    [OMJBClient logTail:^(NSString *text, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            OMJBLogController *strongSelf = weakSelf;
            if (!strongSelf) return;
            strongSelf.textView.text = error ? OMJBDescribe(error) : text;
        });
    }];
}

@end
