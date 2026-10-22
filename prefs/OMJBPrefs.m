// OpenMinis-Jailbreak native Settings pane.
//
// IMPORTANT: this file deliberately contains NO @implementation blocks.
// Every class is created at runtime with objc_allocateClassPair in a
// constructor. Settings is an arm64e process and the ObjC metadata emitted by
// this Linux toolchain for static classes is not loadable there (libobjc
// readClass crashes while mapping the image). Runtime-created classes have no
// __objc_classlist entry and avoid that path entirely.
#import <UIKit/UIKit.h>
#import <Preferences/Preferences.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <errno.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <sys/socket.h>
#import <sys/time.h>
#import <unistd.h>
#import <string.h>
#import <stdlib.h>

static NSString * const OMJBTokenRelative =
    @"Documents/OpenMinis-Jailbreak/.bridge-state/token";
static NSString * const OMJBMCPURL = @"http://127.0.0.1:18765/mcp";
static const char kOMJBTextViewKey;

static NSDictionary *gDevice = nil;
static NSDictionary *gInfo = nil;
static NSDictionary *gConfig = nil;
static NSString *gLastError = nil;
static BOOL gLoaded = NO;
static BOOL gLoading = NO;

#pragma mark - Small helpers

static NSDictionary *OMJBDict(id value) {
    return [value isKindOfClass:[NSDictionary class]] ? value : nil;
}

static BOOL OMJBBool(id value) {
    return [value isKindOfClass:[NSNumber class]] ? [value boolValue] : NO;
}

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

#pragma mark - Token discovery and raw loopback HTTP

static NSString *OMJBTokenPath(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray *candidates = [NSMutableArray arrayWithObjects:
        [@"/var/mobile" stringByAppendingPathComponent:OMJBTokenRelative],
        [@"/rootfs/private/var/mobile" stringByAppendingPathComponent:OMJBTokenRelative],
        [@"/private/var/mobile" stringByAppendingPathComponent:OMJBTokenRelative],
        nil];
    NSArray *roots = @[@"/rootfs/private/var/mobile/Containers/Shared/AppGroup",
                       @"/var/mobile/Containers/Shared/AppGroup",
                       @"/private/var/mobile/Containers/Shared/AppGroup"];
    for (NSString *root in roots) {
        for (NSString *name in [fm contentsOfDirectoryAtPath:root error:nil]) {
            if (![name hasPrefix:@".jbroot-"]) continue;
            [candidates addObject:[root stringByAppendingPathComponent:
                [name stringByAppendingPathComponent:
                    [@"var/mobile" stringByAppendingPathComponent:OMJBTokenRelative]]]];
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

// Raw sockets bypass ATS. The bridge always answers with Content-Length and
// Connection: close.
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
    NSString *headText = [[NSString alloc] initWithData:
        [response subdataWithRange:NSMakeRange(0, split.location)]
                                                encoding:NSUTF8StringEncoding];
    NSArray *lines = [headText componentsSeparatedByString:@"\r\n"];
    int status = 0;
    if (lines.count) sscanf([lines[0] UTF8String], "HTTP/%*s %d", &status);
    if (statusOut) *statusOut = status;
    NSData *payload = [response subdataWithRange:
        NSMakeRange(NSMaxRange(split), response.length - NSMaxRange(split))];
    NSUInteger declared = NSUIntegerMax;
    for (NSUInteger i = 1; i < lines.count; i++) {
        NSRange colon = [lines[i] rangeOfString:@":"];
        if (colon.location == NSNotFound) continue;
        NSString *name = [[lines[i] substringToIndex:colon.location] lowercaseString];
        if ([name isEqualToString:@"content-length"]) {
            declared = (NSUInteger)[[lines[i] substringFromIndex:colon.location + 1]
                                    integerValue];
        }
    }
    if (declared != NSUIntegerMax && payload.length > declared) {
        payload = [payload subdataWithRange:NSMakeRange(0, declared)];
    }
    return payload;
}

static id OMJBJSON(NSData *data) {
    if (!data.length) return nil;
    return [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
}

#pragma mark - Bridge calls

static void OMJBCallTool(NSString *name, NSDictionary *arguments,
                         void (^completion)(NSDictionary *, NSError *)) {
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
        NSData *body = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
        NSInteger status = 0;
        NSError *netError = nil;
        NSData *response = OMJBRequest(@"POST", @"/mcp", body, token, &status, &netError);
        if (!response) { completion(nil, netError); return; }
        if (status == 401) {
            completion(nil, OMJBError(@"token 无效或已轮换", @"EAUTH", nil));
            return;
        }
        NSDictionary *json = OMJBDict(OMJBJSON(response));
        NSDictionary *result = OMJBDict(json[@"result"]);
        if (!result) {
            completion(nil, OMJBError([NSString stringWithFormat:@"bridge 返回 HTTP %ld",
                                       (long)status], @"EHTTP", nil));
            return;
        }
        NSArray *content = result[@"content"];
        NSString *text = ([content isKindOfClass:[NSArray class]] && content.count)
            ? content[0][@"text"] : nil;
        if (OMJBBool(result[@"isError"])) {
            NSDictionary *detail = OMJBDict(OMJBDict(OMJBJSON(
                [text dataUsingEncoding:NSUTF8StringEncoding]))[@"error"]);
            completion(nil, OMJBError(detail[@"message"] ?: @"操作失败",
                                      detail[@"code"], detail[@"ref"]));
            return;
        }
        NSDictionary *value = OMJBDict(OMJBJSON([text dataUsingEncoding:NSUTF8StringEncoding]));
        completion(value ?: @{}, nil);
    });
}

static void OMJBFetchStatus(void (^completion)(NSDictionary *, NSDictionary *, NSError *)) {
    OMJBCallTool(@"jb_device_info", @{}, ^(NSDictionary *device, NSError *error) {
        if (error) { completion(nil, nil, error); return; }
        OMJBCallTool(@"jb_maintenance_info", @{}, ^(NSDictionary *info, NSError *error2) {
            completion(device, info, error2);
        });
    });
}

static void OMJBFetchConfig(void (^completion)(NSDictionary *, NSError *)) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *token = OMJBReadToken();
        if (!token) { completion(nil, OMJBError(@"找不到 bridge token", @"EAUTH", nil)); return; }
        NSInteger status = 0; NSError *netError = nil;
        NSData *response = OMJBRequest(@"GET", @"/ui/api/config", nil, token, &status, &netError);
        if (!response) { completion(nil, netError); return; }
        if (status == 401) { completion(nil, OMJBError(@"token 无效或已轮换", @"EAUTH", nil)); return; }
        if (status == 404) { completion(nil, OMJBError(@"请先安装 0.3.14 或更高版本", @"EOLD", nil)); return; }
        NSDictionary *json = OMJBDict(OMJBJSON(response));
        if (!json) { completion(nil, OMJBError(@"配置响应格式错误", @"EPROTO", nil)); return; }
        completion(json, nil);
    });
}

static void OMJBSetConfig(NSDictionary *patch, void (^completion)(NSDictionary *, NSError *)) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *token = OMJBReadToken();
        if (!token) { completion(nil, OMJBError(@"找不到 bridge token", @"EAUTH", nil)); return; }
        NSData *body = [NSJSONSerialization dataWithJSONObject:patch options:0 error:nil];
        NSInteger status = 0; NSError *netError = nil;
        NSData *response = OMJBRequest(@"POST", @"/ui/api/config", body, token, &status, &netError);
        if (!response) { completion(nil, netError); return; }
        NSDictionary *json = OMJBDict(OMJBJSON(response));
        if (status != 200) {
            NSDictionary *detail = OMJBDict(json[@"error"]);
            completion(nil, OMJBError(detail[@"message"] ?: @"保存失败", detail[@"code"], nil));
            return;
        }
        if (!json) { completion(nil, OMJBError(@"配置响应格式错误", @"EPROTO", nil)); return; }
        completion(json, nil);
    });
}

#pragma mark - UI helpers

static NSArray *OMJBBuildSpecifiers(id host);

static void OMJBAlert(id host, NSString *title, NSString *message) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert =
            [UIAlertController alertControllerWithTitle:title
                                                message:message
                                         preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"好"
                                                  style:UIAlertActionStyleDefault
                                                handler:nil]];
        [(UIViewController *)host presentViewController:alert animated:YES completion:nil];
    });
}

static void OMJBConfirm(id host, NSString *title, NSString *message,
                        NSString *okTitle, BOOL destructive, void (^action)(void)) {
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
    [(UIViewController *)host presentViewController:alert animated:YES completion:nil];
}

static void OMJBReload(id host) {
    NSMutableArray *items = [OMJBBuildSpecifiers(host) mutableCopy];
    [(PSListController *)host setSpecifiers:items];
    [(PSListController *)host reloadSpecifiers];
}

static void OMJBRefresh(id host) {
    if (gLoading) return;
    gLoading = YES;
    gLastError = nil;
    dispatch_async(dispatch_get_main_queue(), ^{ OMJBReload(host); });
    OMJBFetchStatus(^(NSDictionary *device, NSDictionary *info, NSError *error) {
        OMJBFetchConfig(^(NSDictionary *config, NSError *configError) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (error) {
                    gLastError = OMJBDescribe(error);
                    gDevice = nil;
                    gInfo = nil;
                } else {
                    gDevice = device;
                    gInfo = info;
                }
                if (configError) {
                    if (!gLastError) gLastError = OMJBDescribe(configError);
                } else {
                    gConfig = config;
                }
                gLoading = NO;
                gLoaded = YES;
                OMJBReload(host);
            });
        });
    });
}

static NSString *OMJBShortHash(NSString *hash) {
    if (![hash isKindOfClass:[NSString class]] || hash.length < 16) return hash ?: @"—";
    return [hash substringToIndex:16];
}

static PSSpecifier *OMJBTitleRow(NSString *label, id host, const char *getter) {
    return [PSSpecifier preferenceSpecifierNamed:label
                                          target:host
                                             set:NULL
                                             get:sel_registerName(getter)
                                          detail:Nil
                                            cell:PSTitleValueCell
                                            edit:Nil];
}

static PSSpecifier *OMJBButtonRow(NSString *label, id host,
                                  const char *action, BOOL destructive) {
    PSSpecifier *specifier =
        [PSSpecifier preferenceSpecifierNamed:label
                                        target:host
                                           set:NULL
                                           get:NULL
                                        detail:Nil
                                          cell:PSButtonCell
                                          edit:Nil];
    specifier.buttonAction = sel_registerName(action);
    if (destructive) [specifier setProperty:@YES forKey:@"isDestructive"];
    return specifier;
}

static PSSpecifier *OMJBGroup(NSString *label, NSString *footer) {
    PSSpecifier *group = [PSSpecifier groupSpecifierWithName:label];
    if (footer.length) [group setProperty:footer forKey:@"footerText"];
    return group;
}

static NSArray *OMJBBuildSpecifiers(id host) {
    NSMutableArray *items = [NSMutableArray array];
    [items addObject:OMJBGroup(@"状态",
        @"bridge 以 mobile 身份运行，只监听 127.0.0.1。")];
    [items addObject:OMJBTitleRow(@"运行状态", host, "healthValue")];
    [items addObject:OMJBTitleRow(@"bridge", host, "versionValue")];
    [items addObject:OMJBTitleRow(@"API", host, "apiValue")];
    [items addObject:OMJBTitleRow(@"PID / UID", host, "pidValue")];
    [items addObject:OMJBTitleRow(@"supervisor", host, "supervisorValue")];
    [items addObject:OMJBTitleRow(@"可回退版本", host, "rollbackValue")];
    [items addObject:OMJBTitleRow(@"source sha256", host, "sourceValue")];
    [items addObject:OMJBTitleRow(@"最近错误", host, "errorValue")];

    [items addObject:OMJBGroup(@"操作", nil)];
    [items addObject:OMJBButtonRow(@"重启 bridge", host, "restart", NO)];
    [items addObject:OMJBButtonRow(@"回退上一版", host, "rollback", YES)];

    [items addObject:OMJBGroup(@"能力",
        @"Shell 与整机读取都以 mobile 身份运行，不是沙箱。")];
    PSSpecifier *shell =
        [PSSpecifier preferenceSpecifierNamed:@"mobile Shell"
                                        target:host
                                           set:sel_registerName("setShell:forSpecifier:")
                                           get:sel_registerName("shellValue")
                                        detail:Nil
                                          cell:PSSwitchCell
                                          edit:Nil];
    [items addObject:shell];
    [items addObject:OMJBTitleRow(@"项目根", host, "projectsValue")];
    [items addObject:OMJBButtonRow(@"添加项目根…", host, "addProject", NO)];
    [items addObject:OMJBButtonRow(@"移除项目根…", host, "removeProject", YES)];

    [items addObject:OMJBGroup(@"连接",
        @"token 位于 .bridge-state/token（0600）。复制后等同 mobile 权限。")];
    [items addObject:OMJBTitleRow(@"MCP 地址", host, "urlValue")];
    [items addObject:OMJBButtonRow(@"复制 MCP 地址", host, "copyURL", NO)];
    [items addObject:OMJBButtonRow(@"复制 token", host, "copyToken", NO)];

    [items addObject:OMJBGroup(@"诊断", nil)];
    [items addObject:OMJBButtonRow(@"查看错误日志", host, "showLog", NO)];
    return items;
}

#pragma mark - Status getters

static id OMJBHealthValue(id self, SEL _cmd) {
    if (!gLoaded) return @"读取中…";
    if (gLastError && !gInfo) return @"无法连接";
    NSDictionary *supervisor = OMJBDict(gInfo[@"supervisor"]);
    BOOL healthy = OMJBBool(gInfo[@"supervised"]) &&
                   [supervisor[@"event"] isEqualToString:@"healthy"];
    return healthy ? @"运行中" : @"异常";
}

static id OMJBVersionValue(id self, SEL _cmd) { return gDevice[@"bridge"] ?: @"—"; }

static id OMJBApiValue(id self, SEL _cmd) {
    id api = gInfo[@"api"];
    return api ? [NSString stringWithFormat:@"v%@", api] : @"—";
}

static id OMJBPidValue(id self, SEL _cmd) {
    id pid = gDevice[@"pid"]; id uid = gDevice[@"uid"];
    return (pid && uid) ? [NSString stringWithFormat:@"%@ / %@", pid, uid] : @"—";
}

static id OMJBSupervisorValue(id self, SEL _cmd) {
    id pid = OMJBDict(gInfo[@"supervisor"])[@"supervisor_pid"];
    return pid ? [NSString stringWithFormat:@"%@", pid] : @"—";
}

static id OMJBRollbackValue(id self, SEL _cmd) {
    NSString *previous = OMJBDict(gInfo[@"active"])[@"previous"];
    return previous.length ? OMJBShortHash(previous) : @"无";
}

static id OMJBSourceValue(id self, SEL _cmd) {
    return OMJBShortHash(gDevice[@"source_sha256"]);
}

static id OMJBErrorValue(id self, SEL _cmd) { return gLastError ?: @"无"; }

static id OMJBProjectsValue(id self, SEL _cmd) {
    NSDictionary *projects = OMJBDict(gConfig[@"projects"]);
    return projects ? [NSString stringWithFormat:@"%lu 个", (unsigned long)projects.count] : @"—";
}

static id OMJBURLValue(id self, SEL _cmd) { return OMJBMCPURL; }

static id OMJBShellValue(id self, SEL _cmd) {
    return @(OMJBBool(gConfig[@"allow_mobile_shell"]));
}

#pragma mark - Actions

static void OMJBRootRefresh(id self, SEL _cmd, id sender) { OMJBRefresh(self); }

static void OMJBRestartAction(id self, SEL _cmd) {
    OMJBConfirm(self, @"重启 bridge", @"连接会短暂中断，随后自动恢复。",
                @"重启", NO, ^{
        OMJBCallTool(@"jb_restart", @{}, ^(NSDictionary *value, NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (error) {
                    OMJBAlert(self, @"重启失败", OMJBDescribe(error));
                } else {
                    OMJBAlert(self, @"已请求重启", @"几秒后自动恢复；返回本页可刷新状态。");
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                                 (int64_t)(3 * NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), ^{ OMJBRefresh(self); });
                }
            });
        });
    });
}

static void OMJBRollbackAction(id self, SEL _cmd) {
    NSString *previous = OMJBDict(gInfo[@"active"])[@"previous"];
    if (!previous.length) {
        OMJBAlert(self, @"没有可回退的版本", @"active.previous 为空。");
        return;
    }
    NSString *title = [NSString stringWithFormat:@"回退到 %@…", OMJBShortHash(previous)];
    OMJBConfirm(self, title, @"当前版本会保留，可以再次回退。", @"回退", YES, ^{
        OMJBCallTool(@"jb_rollback", @{}, ^(NSDictionary *value, NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (error) {
                    OMJBAlert(self, @"回退失败", OMJBDescribe(error));
                } else {
                    OMJBAlert(self, @"已请求回退", @"supervisor 会在健康检查后切换版本。");
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                                 (int64_t)(3 * NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), ^{ OMJBRefresh(self); });
                }
            });
        });
    });
}

static void OMJBCopyURLAction(id self, SEL _cmd) {
    [UIPasteboard generalPasteboard].string = OMJBMCPURL;
    OMJBAlert(self, @"已复制", OMJBMCPURL);
}

static void OMJBCopyTokenAction(id self, SEL _cmd) {
    NSString *token = OMJBReadToken();
    if (!token) {
        OMJBAlert(self, @"找不到 token", @"尝试了系统目录与 jbroot 路径。");
        return;
    }
    [UIPasteboard generalPasteboard].string = token;
    OMJBAlert(self, @"已复制 token", @"已放入剪贴板，请勿分享给不可信的应用。");
}

static void OMJBSetShellAction(id self, SEL _cmd, id value, id specifier) {
    BOOL enabled = OMJBBool(value);
    OMJBSetConfig(@{ @"allow_mobile_shell": @(enabled) },
                  ^(NSDictionary *config, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error) {
                OMJBAlert(self, @"保存失败", OMJBDescribe(error));
            } else {
                gConfig = config;
            }
            OMJBReload(self);
        });
    });
}

static void OMJBAddProjectAction(id self, SEL _cmd) {
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
    [alert addAction:[UIAlertAction actionWithTitle:@"取消"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"添加"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        NSString *name = [alert.textFields[0].text stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        NSString *path = [alert.textFields[1].text stringByTrimmingCharactersInSet:
                          [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (!name.length || !path.length) {
            OMJBAlert(self, @"名称和路径都要填", nil);
            return;
        }
        NSMutableDictionary *projects = [OMJBDict(gConfig[@"projects"]) mutableCopy];
        if (!projects) projects = [NSMutableDictionary dictionary];
        projects[name] = path;
        OMJBSetConfig(@{ @"projects": projects },
                      ^(NSDictionary *config, NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (error) {
                    OMJBAlert(self, @"添加失败", OMJBDescribe(error));
                } else {
                    gConfig = config;
                    OMJBReload(self);
                }
            });
        });
    }]];
    [(UIViewController *)self presentViewController:alert animated:YES completion:nil];
}

static void OMJBRemoveProjectAction(id self, SEL _cmd) {
    NSDictionary *projects = OMJBDict(gConfig[@"projects"]);
    if (!projects.count) {
        OMJBAlert(self, @"没有项目根", @"先添加一个项目根。");
        return;
    }
    UIAlertController *sheet =
        [UIAlertController alertControllerWithTitle:@"移除项目根"
                                            message:@"只改配置，不删除文件。"
                                     preferredStyle:UIAlertControllerStyleActionSheet];
    for (NSString *name in [[projects allKeys] sortedArrayUsingSelector:
                            @selector(localizedCaseInsensitiveCompare:)]) {
        [sheet addAction:[UIAlertAction actionWithTitle:name
                                                  style:UIAlertActionStyleDestructive
                                                handler:^(UIAlertAction *action) {
            NSMutableDictionary *next = [projects mutableCopy];
            [next removeObjectForKey:name];
            OMJBSetConfig(@{ @"projects": next },
                          ^(NSDictionary *config, NSError *error) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    if (error) {
                        OMJBAlert(self, @"移除失败", OMJBDescribe(error));
                    } else {
                        gConfig = config;
                        OMJBReload(self);
                    }
                });
            });
        }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消"
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    [(UIViewController *)self presentViewController:sheet animated:YES completion:nil];
}

static void OMJBShowLogAction(id self, SEL _cmd) {
    Class logClass = objc_getClass("OMJBLogController");
    if (!logClass) {
        OMJBAlert(self, @"日志不可用", @"OMJBLogController 未注册。");
        return;
    }
    id controller = [[logClass alloc] init];
    [[(UIViewController *)self navigationController] pushViewController:controller
                                                               animated:YES];
}

static void OMJBLoadLog(id self) {
    OMJBCallTool(@"jb_log_tail", @{ @"limit": @50 },
                 ^(NSDictionary *value, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            UITextView *view = objc_getAssociatedObject(self, &kOMJBTextViewKey);
            view.text = error ? OMJBDescribe(error) : (value[@"text"] ?: @"（暂无记录）");
        });
    });
}

static void OMJBLogRefresh(id self, SEL _cmd, id sender) { OMJBLoadLog(self); }

static void OMJBLogViewDidLoad(id self, SEL _cmd) {
    struct objc_super parent = { self, class_getSuperclass(object_getClass(self)) };
    ((void (*)(struct objc_super *, SEL))objc_msgSendSuper)(&parent, _cmd);
    [(UIViewController *)self setTitle:@"错误日志"];
    [[(UIViewController *)self view] setBackgroundColor:[UIColor systemBackgroundColor]];
    UITextView *view = [[UITextView alloc] initWithFrame:CGRectZero];
    view.editable = NO;
    view.selectable = YES;
    view.alwaysBounceVertical = YES;
    view.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    view.textContainerInset = UIEdgeInsetsMake(12, 10, 20, 10);
    view.translatesAutoresizingMaskIntoConstraints = NO;
    [[(UIViewController *)self view] addSubview:view];
    [NSLayoutConstraint activateConstraints:@[
        [view.topAnchor constraintEqualToAnchor:
            [(UIViewController *)self view].safeAreaLayoutGuide.topAnchor],
        [view.bottomAnchor constraintEqualToAnchor:[(UIViewController *)self view].bottomAnchor],
        [view.leadingAnchor constraintEqualToAnchor:[(UIViewController *)self view].leadingAnchor],
        [view.trailingAnchor constraintEqualToAnchor:[(UIViewController *)self view].trailingAnchor],
    ]];
    objc_setAssociatedObject(self, &kOMJBTextViewKey, view,
                             OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    UIBarButtonItem *refresh =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh
                                                      target:self
                                                      action:sel_registerName("refresh:")];
    [[(UIViewController *)self navigationItem] setRightBarButtonItem:refresh];
    OMJBLoadLog(self);
}

#pragma mark - Runtime classes

typedef struct {
    const char *name;
    IMP implementation;
    const char *types;
} OMJBMethod;

static void OMJBAddMethods(Class cls, const OMJBMethod *methods, size_t count) {
    for (size_t i = 0; i < count; i++) {
        class_addMethod(cls, sel_registerName(methods[i].name),
                        methods[i].implementation, methods[i].types);
    }
}

static id OMJBRootInit(id self, SEL _cmd) {
    struct objc_super parent = { self, class_getSuperclass(object_getClass(self)) };
    return ((id (*)(struct objc_super *, SEL))objc_msgSendSuper)(&parent, _cmd);
}

static void OMJBRootViewDidLoad(id self, SEL _cmd) {
    struct objc_super parent = { self, class_getSuperclass(object_getClass(self)) };
    ((void (*)(struct objc_super *, SEL))objc_msgSendSuper)(&parent, _cmd);
    [(PSListController *)self setTitle:@"OpenMinis JB"];
    UIBarButtonItem *refresh =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh
                                                      target:self
                                                      action:sel_registerName("refresh:")];
    [[(PSListController *)self navigationItem] setRightBarButtonItem:refresh];
    OMJBReload(self);
}

static void OMJBRootViewWillAppear(id self, SEL _cmd, BOOL animated) {
    struct objc_super parent = { self, class_getSuperclass(object_getClass(self)) };
    ((void (*)(struct objc_super *, SEL, BOOL))objc_msgSendSuper)(&parent, _cmd, animated);
    OMJBRefresh(self);
}

static id OMJBRootSpecifiers(id self, SEL _cmd) { return OMJBBuildSpecifiers(self); }

__attribute__((constructor)) static void OMJBRegisterClasses(void) {
    static const OMJBMethod rootMethods[] = {
        { "init", (IMP)OMJBRootInit, "@@:" },
        { "viewDidLoad", (IMP)OMJBRootViewDidLoad, "v@:" },
        { "viewWillAppear:", (IMP)OMJBRootViewWillAppear, "v@:B" },
        { "specifiers", (IMP)OMJBRootSpecifiers, "@@:" },
        { "refresh:", (IMP)OMJBRootRefresh, "v@:@" },
        { "restart", (IMP)OMJBRestartAction, "v@:" },
        { "rollback", (IMP)OMJBRollbackAction, "v@:" },
        { "copyURL", (IMP)OMJBCopyURLAction, "v@:" },
        { "copyToken", (IMP)OMJBCopyTokenAction, "v@:" },
        { "addProject", (IMP)OMJBAddProjectAction, "v@:" },
        { "removeProject", (IMP)OMJBRemoveProjectAction, "v@:" },
        { "showLog", (IMP)OMJBShowLogAction, "v@:" },
        { "setShell:forSpecifier:", (IMP)OMJBSetShellAction, "v@:@@" },
        { "shellValue", (IMP)OMJBShellValue, "@@:" },
        { "healthValue", (IMP)OMJBHealthValue, "@@:" },
        { "versionValue", (IMP)OMJBVersionValue, "@@:" },
        { "apiValue", (IMP)OMJBApiValue, "@@:" },
        { "pidValue", (IMP)OMJBPidValue, "@@:" },
        { "supervisorValue", (IMP)OMJBSupervisorValue, "@@:" },
        { "rollbackValue", (IMP)OMJBRollbackValue, "@@:" },
        { "sourceValue", (IMP)OMJBSourceValue, "@@:" },
        { "errorValue", (IMP)OMJBErrorValue, "@@:" },
        { "projectsValue", (IMP)OMJBProjectsValue, "@@:" },
        { "urlValue", (IMP)OMJBURLValue, "@@:" },
    };
    Class root = objc_allocateClassPair(objc_getClass("PSListController"),
                                        "OMJBRootListController", 0);
    if (root) {
        OMJBAddMethods(root, rootMethods, sizeof(rootMethods) / sizeof(rootMethods[0]));
        objc_registerClassPair(root);
    }

    static const OMJBMethod logMethods[] = {
        { "viewDidLoad", (IMP)OMJBLogViewDidLoad, "v@:" },
        { "refresh:", (IMP)OMJBLogRefresh, "v@:@" },
    };
    Class log = objc_allocateClassPair(objc_getClass("UIViewController"),
                                       "OMJBLogController", 0);
    if (log) {
        OMJBAddMethods(log, logMethods, sizeof(logMethods) / sizeof(logMethods[0]));
        objc_registerClassPair(log);
    }
}
