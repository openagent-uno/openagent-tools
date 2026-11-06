// Public Cocoa/ScreenCaptureKit bridge; compiled into the native helper.
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <AVFoundation/AVFoundation.h>
#import <AVFAudio/AVFAudio.h>
#import <CoreMedia/CoreMedia.h>
#import <AudioToolbox/AudioToolbox.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#import <sys/stat.h>
#import <unistd.h>
#import <stdlib.h>
#import <fcntl.h>
#import <sys/file.h>
#import <errno.h>

static NSMutableDictionary<NSString *, NSDictionary *> *OAApps;
static NSLock *OAAppsLock;
// Cancellation callback/context are request-local parameters below; never captured
// by asynchronous OS completions after the Rust request has returned.
typedef struct { void *context; BOOL (*cancelled)(void *); NSTimeInterval deadline; AXUIElementRef window; AXUIElementRef element; CFTypeRef expectedValue; } OARequest;
static BOOL OACheck(OARequest r) { return (r.cancelled && r.cancelled(r.context)) || NSDate.timeIntervalSinceReferenceDate >= r.deadline; }
static NSDictionary *OAError(NSString *code, NSString *message) { return @{ @"error": @{ @"code": code, @"message": message ?: code } }; }
static NSString *OANonce(NSString *prefix) { return [prefix stringByAppendingString:NSUUID.UUID.UUIDString]; }
static void OAInit(void) { static dispatch_once_t once; dispatch_once(&once, ^{ OAApps=[NSMutableDictionary new]; OAAppsLock=[NSLock new]; }); }
static NSArray *OAFileVersion(NSString *path) { struct stat s; if (!path || stat(path.fileSystemRepresentation,&s)!=0 || !S_ISREG(s.st_mode)) return nil; return @[@(s.st_dev),@(s.st_ino),@(s.st_size),@(s.st_mtimespec.tv_sec),@(s.st_mtimespec.tv_nsec)]; }
static NSDictionary *OAApp(NSURL *url) {
    NSString *path=url.URLByResolvingSymlinksInPath.path;
    if (![path.pathExtension.lowercaseString isEqual:@"app"]) return nil;
    NSBundle *bundle=[NSBundle bundleWithURL:[NSURL fileURLWithPath:path]];
    NSString *executable=bundle.executableURL.path;
    NSArray *info=OAFileVersion([path stringByAppendingPathComponent:@"Contents/Info.plist"]), *binary=OAFileVersion(executable);
    if (!bundle.bundleIdentifier || !info || !binary || ![NSFileManager.defaultManager isExecutableFileAtPath:executable]) return nil;
    id label=[bundle objectForInfoDictionaryKey:@"CFBundleDisplayName"] ?: [bundle objectForInfoDictionaryKey:@"CFBundleName"];
    NSString *name=[label isKindOfClass:NSString.class]?label:path.lastPathComponent;
    if(name.length>512)name=[name substringToIndex:512];
    return @{ @"bundle_path":path,@"bundle_id":bundle.bundleIdentifier,@"name":name,@"executable_path":executable,@"version_info":info,@"version_binary":binary };
}
static NSString *OARegister(NSDictionary *app) {
    OAInit(); [OAAppsLock lock];
    NSTimeInterval now=NSDate.timeIntervalSinceReferenceDate;
    for (NSString *key in OAApps.allKeys) if ([OAApps[key][@"expires"] doubleValue] <= now) [OAApps removeObjectForKey:key];
    while (OAApps.count>=4096) [OAApps removeObjectForKey:OAApps.allKeys.firstObject];
    NSString *ref=OANonce(@"app-"); OAApps[ref]=@{@"app":app,@"expires":@(now+600)}; [OAAppsLock unlock]; return ref;
}
static NSDictionary *OAResolve(NSString *ref, BOOL consume) {
    OAInit(); [OAAppsLock lock]; NSDictionary *stored=OAApps[ref];
    if (consume) [OAApps removeObjectForKey:ref]; [OAAppsLock unlock];
    if (!stored || [stored[@"expires"] doubleValue]<=NSDate.timeIntervalSinceReferenceDate) return nil;
    NSDictionary *old=stored[@"app"], *current=OAApp([NSURL fileURLWithPath:old[@"bundle_path"]]);
    if (!current || ![old isEqual:current]) return nil;
    return current;
}
static NSDictionary *OAPublicApp(NSDictionary *app, NSString *ref) {
    NSMutableArray *pids=[NSMutableArray new];
    for (NSRunningApplication *running in NSWorkspace.sharedWorkspace.runningApplications)
        if ([running.bundleURL.URLByResolvingSymlinksInPath.path isEqual:app[@"bundle_path"]]) [pids addObject:@(running.processIdentifier)];
    return @{ @"app_ref":ref,@"bundle_path":app[@"bundle_path"],@"bundle_id":app[@"bundle_id"],@"name":app[@"name"],@"running_pids":pids,@"expires_in_ms":@600000 };
}
static NSDictionary *OAListApps(OARequest request) {
    NSMutableArray *apps=[NSMutableArray new];NSMutableSet *seen=[NSMutableSet new];__block BOOL truncated=NO;
    void (^append)(NSString *)=^(NSString *path){
        if(OACheck(request)||apps.count>=1000){truncated=YES;return;}
        NSDictionary *app=OAApp([NSURL fileURLWithPath:path]);
        if(!app||[seen containsObject:app[@"bundle_path"]])return;
        [seen addObject:app[@"bundle_path"]];[apps addObject:OAPublicApp(app,OARegister(app))];
    };
    // Observe current processes first so a bounded directory scan never hides
    // the live target whose exact app reference the caller needs.
    for(NSRunningApplication *app in NSWorkspace.sharedWorkspace.runningApplications){
        if(OACheck(request)){truncated=YES;break;}if(app.bundleURL.path)append(app.bundleURL.path);
    }
    NSArray *roots=@[@"/Applications",@"/System/Applications",@"/System/Library/CoreServices/Applications",[NSHomeDirectory() stringByAppendingPathComponent:@"Applications"]];
    for(NSString *root in roots){
        if(OACheck(request)||apps.count>=1000){truncated=YES;break;}
        NSMutableArray *queue=[NSMutableArray arrayWithObject:@[@0,root]];
        while(queue.count){
            if(OACheck(request)||apps.count>=1000){truncated=YES;break;}
            NSArray *item=queue.firstObject;[queue removeObjectAtIndex:0];
            NSArray *children=[NSFileManager.defaultManager contentsOfDirectoryAtPath:item[1] error:nil];
            for(NSString *name in children){
                if(OACheck(request)||apps.count>=1000){truncated=YES;break;}
                if([name hasPrefix:@"."])continue;NSString *path=[item[1] stringByAppendingPathComponent:name];
                if([name.pathExtension.lowercaseString isEqual:@"app"])append(path);
                else if([item[0] integerValue]<2){BOOL directory=NO;if([NSFileManager.defaultManager fileExistsAtPath:path isDirectory:&directory]&&directory)[queue addObject:@[@([item[0] integerValue]+1),path]];}
            }
        }
    }
    return @{@"apps":apps,@"truncated":@(truncated),@"coverage":@"running_bundles_then_standard_application_directories",@"host_authorization_required":@YES};
}
static BOOL OAWait(dispatch_semaphore_t semaphore, OARequest request) {
    while (!OACheck(request)) if (dispatch_semaphore_wait(semaphore,dispatch_time(DISPATCH_TIME_NOW,20*NSEC_PER_MSEC))==0) return YES;
    return NO;
}
static NSDictionary *OALaunch(NSDictionary *arguments, OARequest request) {
    NSDictionary *app=OAResolve(arguments[@"app_ref"],YES); if (!app) return OAError(@"stale_app_ref",@"List apps again; exact app bundle changed or reference expired");
    if (OACheck(request)) return OAError(@"native_cancelled",@"Launch was not started");
    NSWorkspaceOpenConfiguration *configuration=NSWorkspaceOpenConfiguration.configuration;
    configuration.activates=[arguments[@"activate"] boolValue]; configuration.createsNewApplicationInstance=NO;
    dispatch_semaphore_t semaphore=dispatch_semaphore_create(0); __block NSRunningApplication *running=nil; __block NSError *error=nil;
    [NSWorkspace.sharedWorkspace openApplicationAtURL:[NSURL fileURLWithPath:app[@"bundle_path"]] configuration:configuration completionHandler:^(NSRunningApplication *result,NSError *failure){ running=result;error=failure;dispatch_semaphore_signal(semaphore); }];
    if (!OAWait(semaphore,request)) return OAError(@"native_launch_indeterminate",@"OS launch was submitted; inspect running apps before another attempt");
    if (!running || error || ![running.bundleURL.URLByResolvingSymlinksInPath.path isEqual:app[@"bundle_path"]]) return OAError(@"native_launch_failed",error.localizedDescription ?: @"OS did not confirm the exact app");
    NSDictionary *confirmed=OAApp(running.bundleURL);if(!confirmed||![confirmed isEqual:app])return OAError(@"native_launch_indeterminate",@"Exact app changed during launch; inspect running apps before another attempt");
    NSMutableDictionary *result=[OAPublicApp(app,OARegister(app)) mutableCopy]; result[@"pid"]=@(running.processIdentifier);result[@"launched"]=@YES; return result;
}
static NSDictionary *OAPolicy(NSDictionary *arguments) {
    NSDictionary *app=nil;
    if (arguments[@"app_ref"]) { app=OAResolve(arguments[@"app_ref"],NO); if (!app) return OAError(@"stale_app_ref",@"List apps again"); }
    BOOL output=NO; if (@available(macOS 13.0,*)) output=YES;
    NSMutableDictionary *result=[@{@"platform":@"macos",@"host_authorization_required":@YES,@"authorization_source":@"host_capability_grant",@"accessibility_granted":@(AXIsProcessTrusted()),@"screen_recording_granted":@(CGPreflightScreenCaptureAccess()),@"system_audio_backend_supported":@(output),@"microphone_supported":@NO,@"input_targeting":@"exact_observed_window_and_process",@"clipboard_formats":@[@"text/plain",@"text/html",@"text/rtf",@"image/png"]} mutableCopy];
    if (app) result[@"app"]=OAPublicApp(app,arguments[@"app_ref"]);
    return result;
}
static BOOL OATargetFocused(pid_t pid,OARequest request) {
    if(OACheck(request)||NSWorkspace.sharedWorkspace.frontmostApplication.processIdentifier!=pid)return NO;
    if(!request.window)return YES;
    AXUIElementRef app=AXUIElementCreateApplication(pid),focused=NULL;
    AXUIElementSetMessagingTimeout(app,(float)MAX(0.001,MIN(0.25,request.deadline-NSDate.timeIntervalSinceReferenceDate)));
    AXError status=AXUIElementCopyAttributeValue(app,kAXFocusedWindowAttribute,(CFTypeRef*)&focused);CFRelease(app);
    BOOL exact=status==kAXErrorSuccess&&focused&&CFEqual(focused,request.window);if(focused)CFRelease(focused);return exact&&!OACheck(request);
}
static BOOL OAElementStable(pid_t pid,OARequest request) {
    if(!OATargetFocused(pid,request))return NO;if(!request.element)return YES;
    AXUIElementRef app=AXUIElementCreateApplication(pid),focused=NULL;CFTypeRef value=NULL;
    float timeout=(float)MAX(0.001,MIN(0.25,request.deadline-NSDate.timeIntervalSinceReferenceDate));AXUIElementSetMessagingTimeout(app,timeout);AXUIElementSetMessagingTimeout(request.element,timeout);
    AXError status=AXUIElementCopyAttributeValue(app,kAXFocusedUIElementAttribute,(CFTypeRef*)&focused);CFRelease(app);
    BOOL stable=status==0&&focused&&CFEqual(focused,request.element);if(focused)CFRelease(focused);
    if(stable&&request.expectedValue){status=AXUIElementCopyAttributeValue(request.element,kAXValueAttribute,&value);stable=status==0&&value&&CFEqual(value,request.expectedValue);if(value)CFRelease(value);}
    return stable&&!OACheck(request);
}
static CGKeyCode OAKey(NSString *key) {
    static NSDictionary *keys; static dispatch_once_t once;dispatch_once(&once,^{ keys=@{@"a":@0,@"s":@1,@"d":@2,@"f":@3,@"h":@4,@"g":@5,@"z":@6,@"x":@7,@"c":@8,@"v":@9,@"b":@11,@"q":@12,@"w":@13,@"e":@14,@"r":@15,@"y":@16,@"t":@17,@"1":@18,@"2":@19,@"3":@20,@"4":@21,@"6":@22,@"5":@23,@"=":@24,@"9":@25,@"7":@26,@"-":@27,@"8":@28,@"0":@29,@"]":@30,@"o":@31,@"u":@32,@"[":@33,@"i":@34,@"p":@35,@"return":@36,@"enter":@36,@"l":@37,@"j":@38,@"'":@39,@"k":@40,@";":@41,@"\\":@42,@",":@43,@"/":@44,@"n":@45,@"m":@46,@".":@47,@"tab":@48,@"space":@49,@"backspace":@51,@"escape":@53,@"esc":@53,@"delete":@117,@"home":@115,@"end":@119,@"pageup":@116,@"pagedown":@121,@"left":@123,@"right":@124,@"down":@125,@"up":@126,@"f1":@122,@"f2":@120,@"f3":@99,@"f4":@118,@"f5":@96,@"f6":@97,@"f7":@98,@"f8":@100,@"f9":@101,@"f10":@109,@"f11":@103,@"f12":@111}; });
    NSNumber *code=keys[key.lowercaseString];return code?code.unsignedShortValue:UINT16_MAX;
}
// Resolve native app menu shortcuts using the public AX shortcut metadata.
// PID-targeted key events bypass AppKit's normal menu routing on some macOS
// versions. Only an exact, unique advertised command is invoked; no replay.
static CFTypeRef OAAttribute(AXUIElementRef element,CFStringRef name,OARequest request){
    if(OACheck(request))return NULL;float timeout=(float)MAX(0.001,MIN(0.25,request.deadline-NSDate.timeIntervalSinceReferenceDate));AXUIElementSetMessagingTimeout(element,timeout);
    CFTypeRef value=NULL;AXUIElementCopyAttributeValue(element,name,&value);return value;
}
static BOOL OAMenuMatches(AXUIElementRef item,NSString *key,NSUInteger modifiers,OARequest request){
    CFTypeRef characters=OAAttribute(item,kAXMenuItemCmdCharAttribute,request),flags=OAAttribute(item,kAXMenuItemCmdModifiersAttribute,request),enabled=OAAttribute(item,kAXEnabledAttribute,request);
    BOOL matches=characters&&CFGetTypeID(characters)==CFStringGetTypeID()&&[((__bridge NSString*)characters).lowercaseString isEqual:key.lowercaseString];
    long actual=-1;if(flags&&CFGetTypeID(flags)==CFNumberGetTypeID())CFNumberGetValue(flags,kCFNumberLongType,&actual);
    matches=matches&&actual==modifiers&&enabled&&CFGetTypeID(enabled)==CFBooleanGetTypeID()&&CFBooleanGetValue(enabled);
    if(characters)CFRelease(characters);if(flags)CFRelease(flags);if(enabled)CFRelease(enabled);return matches&&!OACheck(request);
}
static int OAMenuEquivalent(pid_t pid,NSString *key,CGEventFlags flags,OARequest request){
    if(!(flags&kCGEventFlagMaskCommand)||key.length!=1)return 0;
    NSUInteger modifiers=(flags&kCGEventFlagMaskShift?kAXMenuItemModifierShift:0)|(flags&kCGEventFlagMaskAlternate?kAXMenuItemModifierOption:0)|(flags&kCGEventFlagMaskControl?kAXMenuItemModifierControl:0);
    AXUIElementRef app=AXUIElementCreateApplication(pid);CFTypeRef menu=OAAttribute(app,kAXMenuBarAttribute,request);CFRelease(app);
    if(!menu)return OACheck(request)?-1:0;
    NSMutableArray *queue=[NSMutableArray arrayWithObject:(__bridge id)menu];CFRelease(menu);AXUIElementRef match=NULL;NSUInteger visited=0;BOOL ambiguous=NO;
    while(queue.count&&!OACheck(request)&&visited++<1000){
        id object=queue.lastObject;[queue removeLastObject];if(CFGetTypeID((__bridge CFTypeRef)object)!=AXUIElementGetTypeID())continue;
        AXUIElementRef item=(__bridge AXUIElementRef)object;
        if(OAMenuMatches(item,key,modifiers,request)){if(match){ambiguous=YES;break;}match=(AXUIElementRef)CFRetain(item);}
        CFTypeRef children=OAAttribute(item,kAXChildrenAttribute,request);if(children){if(CFGetTypeID(children)==CFArrayGetTypeID()){CFIndex count=CFArrayGetCount(children);if(count>1000){ambiguous=YES;CFRelease(children);break;}for(CFIndex i=0;i<count;i++)[queue addObject:(__bridge id)CFArrayGetValueAtIndex(children,i)];}CFRelease(children);}
    }
    int result=0;
    if(ambiguous||OACheck(request)||queue.count)result=-1;
    else if(match){
        if(OACheck(request)){if(match)CFRelease(match);return -1;}
        AXUIElementSetMessagingTimeout(match,(float)MAX(0.001,MIN(0.25,request.deadline-NSDate.timeIntervalSinceReferenceDate)));
        CFArrayRef actions=NULL;AXError status=AXUIElementCopyActionNames(match,&actions);BOOL press=status==0&&actions&&CFArrayContainsValue(actions,CFRangeMake(0,CFArrayGetCount(actions)),kAXPressAction);if(actions)CFRelease(actions);
        if(press&&OAMenuMatches(match,key,modifiers,request)&&OAElementStable(pid,request))result=AXUIElementPerformAction(match,kAXPressAction)==kAXErrorSuccess?1:-1;else result=-1;
    }
    if(match)CFRelease(match);return result;
}
static BOOL OAKeyPress(pid_t pid,NSString *key,OARequest request,NSUInteger hold) {
    NSArray *parts=[key componentsSeparatedByString:@"+"]; CGEventFlags flags=kCGEventFlagMaskNonCoalesced;NSString *last=parts.lastObject;
    for (NSString *modifier in [parts subarrayWithRange:NSMakeRange(0,parts.count-1)]) {
        NSString *name=modifier.lowercaseString;
        if ([name isEqual:@"cmd"]||[name isEqual:@"command"]||[name isEqual:@"super"]) flags|=kCGEventFlagMaskCommand;
        else if ([name isEqual:@"ctrl"]||[name isEqual:@"control"]) flags|=kCGEventFlagMaskControl;
        else if ([name isEqual:@"alt"]||[name isEqual:@"option"]) flags|=kCGEventFlagMaskAlternate;
        else if ([name isEqual:@"shift"]) flags|=kCGEventFlagMaskShift;else return NO;
    }
    CGKeyCode code=OAKey(last);if(code==UINT16_MAX||OACheck(request)||!OATargetFocused(pid,request))return NO;
    int equivalent=hold==0?OAMenuEquivalent(pid,last,flags,request):0;
    if(equivalent!=0)return equivalent>0;
    if(!OAElementStable(pid,request))return NO;
    CGEventSourceRef source=CGEventSourceCreate(kCGEventSourceStatePrivate);
    CGEventRef down=CGEventCreateKeyboardEvent(source,code,true),up=CGEventCreateKeyboardEvent(source,code,false);
    if(source)CFRelease(source);
    if(!down||!up){if(down)CFRelease(down);if(up)CFRelease(up);return NO;}
    CGEventSetFlags(down,flags);CGEventSetFlags(up,flags);
    if(last.length==1){NSString *characters=(flags&kCGEventFlagMaskShift)?last.uppercaseString:last.lowercaseString;UniChar scalar=[characters characterAtIndex:0];CGEventKeyboardSetUnicodeString(down,1,&scalar);CGEventKeyboardSetUnicodeString(up,1,&scalar);}
    CGEventPostToPid(pid,down);
    NSTimeInterval until=NSDate.timeIntervalSinceReferenceDate+hold/1000.0;while(NSDate.timeIntervalSinceReferenceDate<until&&!OACheck(request)&&OATargetFocused(pid,request))usleep(10000);
    CGEventPostToPid(pid,up);CFRelease(down);CFRelease(up);return !OACheck(request)&&OATargetFocused(pid,request);
}
static void OABindMouse(CGEventRef event,NSDictionary *arguments){
    CGEventSetIntegerValueField(event,kCGMouseEventWindowUnderMousePointer,[arguments[@"window_id"]longLongValue]);
    CGEventSetIntegerValueField(event,kCGMouseEventWindowUnderMousePointerThatCanHandleThisEvent,[arguments[@"window_id"]longLongValue]);
    CGEventSetIntegerValueField(event,kCGEventTargetUnixProcessID,[arguments[@"pid"]intValue]);
}
static CGEventRef OAMouse(CGEventType type,CGPoint point,CGMouseButton button,NSUInteger count,NSDictionary *arguments){
    // A PID-targeted event already carries the exact Cocoa window number.
    // Its Quartz location must therefore be window-relative, not a second
    // screen-space location. Cocoa's CGEvent bridge flips Y against main height.
    NSPoint location=NSMakePoint(point.x-[arguments[@"x"]doubleValue],CGRectGetHeight(CGDisplayBounds(CGMainDisplayID()))-(point.y-[arguments[@"y"]doubleValue]));
    NSEvent *native=[NSEvent mouseEventWithType:(NSEventType)type location:location modifierFlags:0 timestamp:NSProcessInfo.processInfo.systemUptime windowNumber:[arguments[@"window_id"]integerValue] context:nil eventNumber:0 clickCount:count pressure:(type==kCGEventLeftMouseUp||type==kCGEventRightMouseUp||type==kCGEventOtherMouseUp)?0:1];
    CGEventRef event=native.CGEvent?CGEventCreateCopy(native.CGEvent):NULL;
    if(event){CGEventSetIntegerValueField(event,kCGMouseEventButtonNumber,button);OABindMouse(event,arguments);}return event;
}
static NSDictionary *OAInput(NSDictionary *a,OARequest request) {
    pid_t pid=[a[@"pid"] intValue];NSString *action=a[@"action"];
    if ([action isEqual:@"focus"]) { NSRunningApplication *app=[NSRunningApplication runningApplicationWithProcessIdentifier:pid];if(!app||OACheck(request)||![app activateWithOptions:NSApplicationActivateIgnoringOtherApps])return OAError(@"native_focus_failed",@"OS refused activation");while(!OACheck(request)&&NSWorkspace.sharedWorkspace.frontmostApplication.processIdentifier!=pid)usleep(10000);if(OACheck(request))return OAError(@"native_focus_indeterminate",@"Activation was submitted but not confirmed; inspect focused app before another mutation");return @{@"ok":@YES}; }
    if(!AXIsProcessTrusted())return OAError(@"accessibility_permission_required",@"Accessibility access required");
    if(!OATargetFocused(pid,request))return OAError(@"native_target_not_focused",@"Focus the exact observed app/window first");
    if(OACheck(request))return OAError(@"native_cancelled",@"Input was not started");
    if(!OAElementStable(pid,request))return OAError(@"stale_accessibility_element",@"Selected element/focus/value changed before native input");
    if([action isEqual:@"key"]) { if(!OAKeyPress(pid,a[@"key"],request,[a[@"duration_ms"]isKindOfClass:NSNumber.class]?[a[@"duration_ms"]unsignedIntegerValue]:0))return OAError(@"native_key_not_confirmed",@"Key command was not confirmed and may have reached the target; inspect the exact app before another attempt"); }
    else if([action isEqual:@"type"]) {
        NSString *text=a[@"text"];NSUInteger offset=0;
        while(offset<text.length){ if(OACheck(request)||!OATargetFocused(pid,request))return OAError(@"native_input_indeterminate",@"Focus/cancellation changed after typing started; inspect target before another attempt");NSUInteger count=MIN((NSUInteger)64,text.length-offset);if(offset+count<text.length&&CFStringIsSurrogateHighCharacter([text characterAtIndex:offset+count-1]))count--;
            UniChar chars[64];[text getCharacters:chars range:NSMakeRange(offset,count)];CGEventRef down=CGEventCreateKeyboardEvent(NULL,0,true),up=CGEventCreateKeyboardEvent(NULL,0,false);if(!down||!up){if(down)CFRelease(down);if(up)CFRelease(up);return OAError(@"native_event_failed",@"Cannot construct keyboard event");}CGEventKeyboardSetUnicodeString(down,count,chars);CGEventKeyboardSetUnicodeString(up,count,chars);CGEventPostToPid(pid,down);CGEventPostToPid(pid,up);CFRelease(down);CFRelease(up);offset+=count;
        }
    } else {
        NSArray *coordinate=a[@"coordinate"];CGPoint point=CGPointMake([a[@"x"] doubleValue]+[coordinate[0] doubleValue],[a[@"y"] doubleValue]+[coordinate[1] doubleValue]);
        if([action isEqual:@"scroll"]) { NSString *direction=a[@"direction"];int amount=[a[@"amount"] intValue];BOOL horizontal=[direction isEqual:@"left"]||[direction isEqual:@"right"];if([direction isEqual:@"down"]||[direction isEqual:@"right"])amount=-amount;CGEventRef source=CGEventCreateScrollWheelEvent(NULL,kCGScrollEventUnitPixel,2,horizontal?0:amount,horizontal?amount:0),event=OAMouse(kCGEventMouseMoved,point,kCGMouseButtonLeft,0,a);if(!source||!event){if(source)CFRelease(source);if(event)CFRelease(event);return OAError(@"native_event_failed",@"Cannot construct window-bound scroll event");}CGEventSetType(event,kCGEventScrollWheel);CGEventField fields[]={kCGScrollWheelEventDeltaAxis1,kCGScrollWheelEventDeltaAxis2,kCGScrollWheelEventFixedPtDeltaAxis1,kCGScrollWheelEventFixedPtDeltaAxis2,kCGScrollWheelEventPointDeltaAxis1,kCGScrollWheelEventPointDeltaAxis2,kCGScrollWheelEventIsContinuous};for(NSUInteger i=0;i<sizeof(fields)/sizeof(fields[0]);i++)CGEventSetIntegerValueField(event,fields[i],CGEventGetIntegerValueField(source,fields[i]));CFRelease(source);if(!OATargetFocused(pid,request)){CFRelease(event);return OAError(@"native_target_not_focused",@"Scroll was not submitted because the target changed");}CGEventPostToPid(pid,event);CFRelease(event); }
        else {
            BOOL right=[a[@"button"] isEqual:@"right"],middle=[a[@"button"]isEqual:@"middle"];CGMouseButton button=middle?kCGMouseButtonCenter:(right?kCGMouseButtonRight:kCGMouseButtonLeft);CGEventType downType=middle?kCGEventOtherMouseDown:(right?kCGEventRightMouseDown:kCGEventLeftMouseDown),upType=middle?kCGEventOtherMouseUp:(right?kCGEventRightMouseUp:kCGEventLeftMouseUp);
            NSUInteger count=[a[@"click_count"]isKindOfClass:NSNumber.class]?[a[@"click_count"]unsignedIntegerValue]:1,hold=[a[@"duration_ms"]isKindOfClass:NSNumber.class]?[a[@"duration_ms"]unsignedIntegerValue]:0;
            for(NSUInteger n=0;n<count;n++){
                if(OACheck(request)||!OATargetFocused(pid,request))return OAError(@"native_input_indeterminate",@"Focus/cancellation changed during explicit click sequence");
                CGEventRef down=OAMouse(downType,point,button,n+1,a);if(!down)return OAError(@"native_event_failed",@"Cannot construct mouse event");CGEventSetIntegerValueField(down,kCGMouseEventClickState,n+1);OABindMouse(down,a);CGEventPostToPid(pid,down);CFRelease(down);
                if([action isEqual:@"drag"]){NSArray *to=a[@"to_coordinate"];point=CGPointMake([a[@"x"] doubleValue]+[to[0] doubleValue],[a[@"y"] doubleValue]+[to[1] doubleValue]);CGEventRef drag=OAMouse(middle?kCGEventOtherMouseDragged:(right?kCGEventRightMouseDragged:kCGEventLeftMouseDragged),point,button,n+1,a);if(drag){OABindMouse(drag,a);CGEventPostToPid(pid,drag);CFRelease(drag);}}
                NSTimeInterval until=NSDate.timeIntervalSinceReferenceDate+hold/1000.0;while(NSDate.timeIntervalSinceReferenceDate<until&&!OACheck(request))usleep(10000);
                CGEventRef up=OAMouse(upType,point,button,n+1,a);if(up){CGEventSetIntegerValueField(up,kCGMouseEventClickState,n+1);OABindMouse(up,a);CGEventPostToPid(pid,up);CFRelease(up);}
            }
        }
    }
    return @{@"ok":@YES,@"pid":@(pid),@"delivery":@"target_process",@"requires_fresh_snapshot":@YES};
}
static NSString *OAType(NSString *mime) { return @{@"text/plain":@"public.utf8-plain-text",@"text/html":@"public.html",@"text/rtf":@"public.rtf",@"image/png":@"public.png"}[mime]; }
static NSDictionary *OAPasteLocked(NSDictionary *a,OARequest request) {
    NSPasteboard *board=NSPasteboard.generalPasteboard;NSInteger originalCount=board.changeCount;NSMutableArray *saved=[NSMutableArray new];NSUInteger bytes=0;
    NSArray *original=board.pasteboardItems ?: @[];
    if(original.count>32)return OAError(@"clipboard_restore_limit",@"Existing clipboard has too many items; clipboard untouched");
    for(NSPasteboardItem *item in original){NSPasteboardItem *copy=[NSPasteboardItem new];if(item.types.count>64)return OAError(@"clipboard_restore_limit",@"Existing clipboard has too many representations; clipboard untouched");for(NSString *type in item.types){NSData *data=[item dataForType:type];if(!data)return OAError(@"clipboard_restore_unavailable",@"Cannot save every existing clipboard representation; clipboard untouched");bytes+=data.length;if(bytes>8*1024*1024)return OAError(@"clipboard_restore_limit",@"Existing clipboard exceeds8MiB; clipboard untouched");[copy setData:data forType:type];}[saved addObject:copy];}
    NSPasteboardItem *item=[NSPasteboardItem new];
    for(NSDictionary *representation in a[@"items"]){NSString *type=OAType(representation[@"mime_type"]);NSData *data=[[NSData alloc]initWithBase64EncodedString:representation[@"data_base64"] options:0];if(!type||!data)return OAError(@"invalid_clipboard_format",@"Only explicit plain text,HTML,RTF orPNG representations are accepted");if(![item setData:data forType:type])return OAError(@"clipboard_write_failed",@"Cannot prepare clipboard representation");}
    pid_t pid=[a[@"pid"]intValue];if(OACheck(request)||!OAElementStable(pid,request)||board.changeCount!=originalCount)return OAError(@"clipboard_changed",@"Clipboard/focus changed before paste; clipboard untouched");
    BOOL wrote=NO,submitted=NO,restored=NO;NSInteger ours=0;
    // Temporary clipboard ownership requires a completed advertised AX command.
    // A raw queued Cmd+V could run after restoration and paste unrelated data.
    @try { ours=[board clearContents];wrote=[board writeObjects:@[item]];ours=board.changeCount;if(wrote&&!OACheck(request)&&OATargetFocused(pid,request))submitted=OAMenuEquivalent(pid,@"v",kCGEventFlagMaskCommand,request)>0;if(submitted)[NSThread sleepForTimeInterval:0.15]; }
    @finally { if(board.changeCount==ours){[board clearContents];restored=saved.count?[board writeObjects:saved]:YES;} }
    if(!wrote||!submitted)return @{ @"error":@{@"code":@"paste_not_confirmed",@"message":@"Paste was not submitted or became uncertain; inspect target before another attempt"},@"clipboard_restored":@(restored) };
    return @{@"ok":@YES,@"paste_submitted":@YES,@"clipboard_restored":@(restored),@"clipboard_restore_reason":restored?@"original_representations_restored":@"external_clipboard_change_preserved",@"requires_fresh_snapshot":@YES};
}

static NSDictionary *OAPaste(NSDictionary *a,OARequest request) {
    // Per-user OS lock serializes clipboard transactions across independently
    // scoped helper processes, rather than just within one model/session.
    NSString *path=[NSString stringWithFormat:@"/tmp/uno.openagent.clipboard.%u.lock",getuid()];
    int fd=open(path.fileSystemRepresentation,O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC,0600);struct stat info;
    if(fd<0)return OAError(@"clipboard_lease_unavailable",@"Cannot acquire private clipboard transaction lease");
    if(fstat(fd,&info)!=0||!S_ISREG(info.st_mode)||info.st_uid!=getuid()||info.st_nlink!=1||(info.st_mode&077)!=0){close(fd);return OAError(@"clipboard_lease_unavailable",@"Clipboard transaction lock ownership/mode is invalid");}
    while(flock(fd,LOCK_EX|LOCK_NB)!=0){if(OACheck(request)||errno!=EWOULDBLOCK){close(fd);return OAError(@"clipboard_lease_busy",@"Another clipboard transaction is active; no clipboard content changed");}usleep(10000);}
    @try{return OAPasteLocked(a,request);}@finally{flock(fd,LOCK_UN);close(fd);}
}

API_AVAILABLE(macos(13.0))
@interface OAAudio: NSObject<SCStreamOutput,SCStreamDelegate>
@property SCStream *stream;@property AVAudioFile *file;@property dispatch_queue_t queue;@property NSString *identifier;@property NSString *path;@property NSString *appRef;@property NSNumber *pid;@property BOOL finished;@property dispatch_group_t stopping;@property BOOL stopSubmitted;@property BOOL stopGroupFinished;@property BOOL startPending;@property BOOL cancelled;@property NSError *failure;@property uint64_t frames;@property NSDate *started;@property NSTimeInterval expires;
@end
static void OAFinishAudio(OAAudio *record,NSError *error){
    @synchronized(record){
        if(error)record.failure=error;record.file=nil;record.stream=nil;record.finished=YES;
        if(record.stopping&&!record.stopGroupFinished){record.stopGroupFinished=YES;dispatch_group_leave(record.stopping);}
    }
}
@implementation OAAudio
- (void)stream:(SCStream*)stream didStopWithError:(NSError*)error { OAFinishAudio(self,error); }
- (void)stream:(SCStream*)stream didOutputSampleBuffer:(CMSampleBufferRef)sample ofType:(SCStreamOutputType)type {
    @autoreleasepool {
    if(type!=SCStreamOutputTypeAudio||!CMSampleBufferDataIsReady(sample))return;
    @synchronized(self){if(self.cancelled||self.finished)return;
        CMAudioFormatDescriptionRef description=CMSampleBufferGetFormatDescription(sample);const AudioStreamBasicDescription *basic=CMAudioFormatDescriptionGetStreamBasicDescription(description);if(!basic)return;if(basic->mSampleRate!=24000||basic->mChannelsPerFrame!=2){self.failure=[NSError errorWithDomain:@"uno.openagent.audio" code:1 userInfo:@{NSLocalizedDescriptionKey:@"OS delivered an unexpected audio format; no24kHz stereo claim is made"}];return;}
        AVAudioFormat *format=[[AVAudioFormat alloc]initWithStreamDescription:basic];AVAudioFrameCount frames=(AVAudioFrameCount)CMSampleBufferGetNumSamples(sample);if(!format||!frames)return;
        AVAudioPCMBuffer *pcm=[[AVAudioPCMBuffer alloc]initWithPCMFormat:format frameCapacity:frames];pcm.frameLength=frames;
        size_t size=0;OSStatus status=CMSampleBufferGetAudioBufferListWithRetainedBlockBuffer(sample,&size,NULL,0,NULL,NULL,kCMSampleBufferFlag_AudioBufferList_Assure16ByteAlignment,NULL);if(status!=noErr&&size==0)return;
        AudioBufferList *list=malloc(size);CMBlockBufferRef retained=NULL;status=CMSampleBufferGetAudioBufferListWithRetainedBlockBuffer(sample,NULL,list,size,kCFAllocatorDefault,kCFAllocatorDefault,kCMSampleBufferFlag_AudioBufferList_Assure16ByteAlignment,&retained);
        if(status!=noErr||list->mNumberBuffers!=pcm.mutableAudioBufferList->mNumberBuffers){if(retained)CFRelease(retained);free(list);return;}
        for(UInt32 i=0;i<list->mNumberBuffers;i++){AudioBuffer source=list->mBuffers[i];AudioBuffer *destination=&pcm.mutableAudioBufferList->mBuffers[i];if(source.mDataByteSize>destination->mDataByteSize){if(retained)CFRelease(retained);free(list);return;}memcpy(destination->mData,source.mData,source.mDataByteSize);destination->mDataByteSize=source.mDataByteSize;}
        if(!self.file){NSMutableDictionary *settings=[format.settings mutableCopy];settings[AVLinearPCMIsNonInterleaved]=@NO;NSError *error=nil;self.file=[[AVAudioFile alloc]initForWriting:[NSURL fileURLWithPath:self.path] settings:settings commonFormat:format.commonFormat interleaved:format.interleaved error:&error];if(error)self.failure=error;}
        NSError *error=nil;if(self.file){if(![self.file writeFromBuffer:pcm error:&error])self.failure=error;else self.frames+=frames;}
        if(retained)CFRelease(retained);free(list);
    }
    }
}
@end
static NSMutableDictionary<NSString *,id> *OAAudios;static NSLock *OAAudioLock;
static void OAAudioInit(void){static dispatch_once_t once;dispatch_once(&once,^{OAAudios=[NSMutableDictionary new];OAAudioLock=[NSLock new];});}
static void OAStopAudio(OAAudio *record,dispatch_semaphore_t done) API_AVAILABLE(macos(13.0));
static void OAStopAudio(OAAudio *record,dispatch_semaphore_t done){
    @synchronized(record){
        if(record.finished){if(done)dispatch_semaphore_signal(done);return;}
        if(!record.stopping){record.stopping=dispatch_group_create();dispatch_group_enter(record.stopping);}
        if(done)dispatch_group_notify(record.stopping,dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{dispatch_semaphore_signal(done);});
        // Do not stop/release a stream while startCapture is pending. A late
        // completion observes this request and stops the retained exact stream.
        if(record.startPending||record.stopSubmitted)return;
        record.stopSubmitted=YES;
        [record.stream stopCaptureWithCompletionHandler:^(NSError *error){dispatch_async(record.queue,^{OAFinishAudio(record,error);});}];
    }
}
static NSDictionary *OAAudioStart(NSDictionary *a,OARequest request){
    if(@available(macOS 13.0,*)){
        if(!CGPreflightScreenCaptureAccess())return OAError(@"screen_recording_permission_required",@"Screen Recording/System Audio grant required; no capture started");
        NSDictionary *app=nil;if(a[@"app_ref"]){app=OAResolve(a[@"app_ref"],NO);if(!app)return OAError(@"stale_app_ref",@"List apps again before selecting an audio source");}
        OAAudioInit();[OAAudioLock lock];
        while(OAAudios.count>=16){NSString *expired=nil;for(NSString *key in OAAudios){OAAudio *candidate=OAAudios[key];if(candidate.finished){expired=key;break;}}if(!expired)break;[OAAudios removeObjectForKey:expired];}
        for(OAAudio *existing in OAAudios.allValues)if(!existing.finished){[OAAudioLock unlock];return OAError(@"audio_recording_active",@"Stop the current owned recording before starting another");}[OAAudioLock unlock];
        __block SCShareableContent *content=nil;__block NSError *failure=nil;dispatch_semaphore_t ready=dispatch_semaphore_create(0);
        [SCShareableContent getShareableContentExcludingDesktopWindows:YES onScreenWindowsOnly:YES completionHandler:^(SCShareableContent *value,NSError *error){content=value;failure=error;dispatch_semaphore_signal(ready);}];
        if(!OAWait(ready,request)||failure||!content.displays.count)return OAError(@"audio_source_unavailable",failure.localizedDescription?:@"Cannot obtain an authorized system-audio source");
        SCDisplay *display=content.displays.firstObject;SCContentFilter *filter=nil;NSNumber *pid=nil;
        if(app){NSMutableArray *matched=[NSMutableArray new];for(SCRunningApplication *candidate in content.applications){NSRunningApplication *running=[NSRunningApplication runningApplicationWithProcessIdentifier:candidate.processID];if([running.bundleURL.URLByResolvingSymlinksInPath.path isEqual:app[@"bundle_path"]]){[matched addObject:candidate];pid=@(candidate.processID);}}if(matched.count!=1)return OAError(@"audio_source_ambiguous",@"App audio source must resolve to one current exact process");filter=[[SCContentFilter alloc]initWithDisplay:display includingApplications:matched exceptingWindows:@[]];}
        else filter=[[SCContentFilter alloc]initWithDisplay:display excludingApplications:@[] exceptingWindows:@[]];
        char template[]="/tmp/openagent-audio-XXXXXX";char *directory=mkdtemp(template);if(!directory)return OAError(@"audio_artifact_failed",@"Cannot create private recording directory");chmod(directory,0700);
        OAAudio *record=[OAAudio new];record.identifier=OANonce(@"audio-");record.path=[[NSString stringWithUTF8String:directory]stringByAppendingPathComponent:@"recording.wav"];record.appRef=a[@"app_ref"];record.pid=pid;record.started=NSDate.date;record.expires=NSDate.timeIntervalSinceReferenceDate+[a[@"max_duration_ms"]doubleValue]/1000+60;record.queue=dispatch_queue_create("uno.openagent.audio.samples",DISPATCH_QUEUE_SERIAL);
        SCStreamConfiguration *configuration=[SCStreamConfiguration new];configuration.width=2;configuration.height=2;configuration.capturesAudio=YES;configuration.sampleRate=24000;configuration.channelCount=2;configuration.excludesCurrentProcessAudio=YES;
        record.stream=[[SCStream alloc]initWithFilter:filter configuration:configuration delegate:record];NSError *error=nil;if(![record.stream addStreamOutput:record type:SCStreamOutputTypeAudio sampleHandlerQueue:record.queue error:&error])return OAError(@"audio_capture_failed",error.localizedDescription);
        [OAAudioLock lock];OAAudios[record.identifier]=record;[OAAudioLock unlock];
        dispatch_semaphore_t started=dispatch_semaphore_create(0);record.startPending=YES;
        [record.stream startCaptureWithCompletionHandler:^(NSError *error){
            @synchronized(record){record.startPending=NO;}
            if(error)OAFinishAudio(record,error);
            else if(record.cancelled||record.stopping)OAStopAudio(record,nil);
            dispatch_semaphore_signal(started);
        }];
        if(!OAWait(started,request)||record.failure){record.cancelled=YES;OAStopAudio(record,nil);return OAError(@"audio_capture_failed",record.failure.localizedDescription?:@"Capture did not confirm within the request budget; late capture completion is cancelled and stopped");}
        NSInteger milliseconds=[a[@"max_duration_ms"]integerValue];record.started=NSDate.date;record.expires=NSDate.timeIntervalSinceReferenceDate+milliseconds/1000.0+60;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,milliseconds*NSEC_PER_MSEC),dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{OAStopAudio(record,nil);});
        return @{@"recording_id":record.identifier,@"source":@"system_output",@"source_scope":app?@"exact_app_process":@"all_system_output",@"app_ref":record.appRef?:NSNull.null,@"pid":record.pid?:NSNull.null,@"sample_rate":@24000,@"channels":@2,@"format":@"wav",@"max_duration_ms":@(milliseconds),@"expires_in_ms":@(milliseconds+60000),@"recording":@(!record.finished)};
    }return OAError(@"audio_unsupported_platform",@"System-output audio requires macOS13 or later");
}
static NSDictionary *OAAudioStop(NSDictionary *a,OARequest request){
    if(@available(macOS 13.0,*)){
        OAAudioInit();[OAAudioLock lock];OAAudio *record=OAAudios[a[@"recording_id"]];if(record&&record.expires<=NSDate.timeIntervalSinceReferenceDate){[OAAudios removeObjectForKey:a[@"recording_id"]];record=nil;}[OAAudioLock unlock];if(!record)return OAError(@"stale_recording_id",@"Recording resource is unknown or already consumed");
        dispatch_semaphore_t stopped=dispatch_semaphore_create(0);OAStopAudio(record,stopped);if(!OAWait(stopped,request))return OAError(@"audio_stop_indeterminate",@"Recording stop is pending; inspect this resource before another attempt");
        if(![a[@"return_audio"] boolValue]){[OAAudioLock lock];[OAAudios removeObjectForKey:record.identifier];[OAAudioLock unlock];return @{@"recording_id":record.identifier,@"recording":@NO,@"has_samples":@(record.frames>0),@"filepath":record.path,@"source":@"system_output"};}
        if(record.failure)return OAError(@"audio_capture_failed",record.failure.localizedDescription);
        NSData *data=[NSData dataWithContentsOfFile:record.path options:NSDataReadingMappedIfSafe error:nil];if(!data||!record.frames)return OAError(@"audio_no_samples",@"No audio samples were delivered; silence/permission is not claimed as a successful recording");if(data.length>64*1024*1024)return OAError(@"audio_output_limit",@"Recording exceeds64MiB output budget");
        [OAAudioLock lock];[OAAudios removeObjectForKey:record.identifier];[OAAudioLock unlock];
        return @{@"recording_id":record.identifier,@"source":@"system_output",@"source_scope":record.appRef?@"exact_app_process":@"all_system_output",@"app_ref":record.appRef?:NSNull.null,@"pid":record.pid?:NSNull.null,@"sample_rate":@24000,@"channels":@2,@"format":@"wav",@"mime_type":@"audio/wav",@"filepath":record.path,@"bytes":@(data.length),@"frames":@(record.frames),@"data_base64":[data base64EncodedStringWithOptions:0],@"recording":@NO};
    }return OAError(@"audio_unsupported_platform",@"System-output audio requires macOS13 or later");
}
char *oa_native_request(const char *json, void *context, BOOL (*cancelled)(void *), double budget_ms, const void *window, const void *element, const void *expectedValue){
    @autoreleasepool{@try{
        OAInit();NSData *data=[NSData dataWithBytes:json length:strlen(json)];NSDictionary *a=[NSJSONSerialization JSONObjectWithData:data options:0 error:nil];if(![a isKindOfClass:NSDictionary.class])return strdup("{\"error\":{\"code\":\"invalid_native_request\"}}");
        NSString *op=a[@"op"];double maximum=[op isEqual:@"audio_start"]?8000:3000;OARequest r={context,cancelled,NSDate.timeIntervalSinceReferenceDate+MAX(0.001,MIN(budget_ms,maximum))/1000,(AXUIElementRef)window,(AXUIElementRef)element,(CFTypeRef)expectedValue};NSDictionary *result;
        if([op isEqual:@"list_apps"])result=OAListApps(r);else if([op isEqual:@"launch_app"])result=OALaunch(a,r);else if([op isEqual:@"app_policy"])result=OAPolicy(a);else if([op isEqual:@"window_input"])result=OAInput(a,r);else if([op isEqual:@"paste"])result=OAPaste(a,r);else if([op isEqual:@"audio_start"])result=OAAudioStart(a,r);else if([op isEqual:@"audio_stop"])result=OAAudioStop(a,r);else result=OAError(@"unknown_native_operation",@"Unknown native operation");
        NSData *encoded=[NSJSONSerialization dataWithJSONObject:result options:0 error:nil];return strdup(encoded?[[[NSString alloc]initWithData:encoded encoding:NSUTF8StringEncoding]UTF8String]:"{\"error\":{\"code\":\"native_encoding_failed\"}}");
    }@catch(NSException *exception){return strdup("{\"error\":{\"code\":\"native_exception\",\"message\":\"Native operation failed; inspect state before another mutation\"}}");}}
}
void oa_native_free(char *text){free(text);}
