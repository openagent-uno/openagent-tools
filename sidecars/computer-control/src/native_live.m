// Continuous exact-display capture; no network, identity, files or audio.
#import <AppKit/AppKit.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <CoreGraphics/CoreGraphics.h>
#import <stdint.h>

API_AVAILABLE(macos(12.3))
@interface OALiveScreen : NSObject<SCStreamOutput, SCStreamDelegate>
@property SCStream *stream;
@property NSCondition *condition;
@property CVPixelBufferRef latest;
@property BOOL closed;
@property BOOL failed;
@property NSInteger failureCode;
@property NSUInteger width;
@property NSUInteger height;
@end
@implementation OALiveScreen
- (void)dealloc { if(_latest)CVPixelBufferRelease(_latest); }
- (void)stream:(SCStream *)stream didStopWithError:(NSError *)error {
    [self.condition lock]; self.failed=YES; self.failureCode=error.code; [self.condition broadcast]; [self.condition unlock];
}
- (void)stream:(SCStream *)stream didOutputSampleBuffer:(CMSampleBufferRef)sample ofType:(SCStreamOutputType)type {
    @autoreleasepool {
        if(type!=SCStreamOutputTypeScreen || !CMSampleBufferDataIsReady(sample))return;
        NSArray *attachments=(__bridge NSArray *)CMSampleBufferGetSampleAttachmentsArray(sample,NO);
        NSNumber *status=attachments.firstObject[SCStreamFrameInfoStatus];
        if(status && status.integerValue!=SCFrameStatusComplete)return;
        CVPixelBufferRef buffer=CMSampleBufferGetImageBuffer(sample);
        if(!buffer)return;
        [self.condition lock];
        if(!self.closed){
            if(CVPixelBufferGetWidth(buffer)!=self.width || CVPixelBufferGetHeight(buffer)!=self.height || CVPixelBufferGetPixelFormatType(buffer)!=kCVPixelFormatType_32BGRA)self.failed=YES;
            else { CVPixelBufferRetain(buffer); if(self.latest)CVPixelBufferRelease(self.latest); self.latest=buffer; }
            [self.condition broadcast];
        }
        [self.condition unlock];
    }
}
@end

static BOOL OALiveWait(dispatch_semaphore_t ready, double seconds) {
    NSDate *deadline=[NSDate dateWithTimeIntervalSinceNow:seconds];
    while(deadline.timeIntervalSinceNow>0){
        if(dispatch_semaphore_wait(ready,DISPATCH_TIME_NOW)==0)return YES;
        // Framework completions may target the CLI's main run loop.
        if(NSThread.isMainThread)[NSRunLoop.currentRunLoop runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
        else if(dispatch_semaphore_wait(ready,dispatch_time(DISPATCH_TIME_NOW,10*NSEC_PER_MSEC))==0)return YES;
    }
    return NO;
}

void *oa_live_start(uint32_t display_id, uint32_t width, uint32_t height, uint32_t fps, int *error_code) {
    @autoreleasepool {
        *error_code=1;
        if(!CGPreflightScreenCaptureAccess())return NULL;
        if(@available(macOS 12.3,*)){
            *error_code=2;
            __block SCShareableContent *content=nil;
            __block NSError *failure=nil;
            dispatch_semaphore_t ready=dispatch_semaphore_create(0);
            [SCShareableContent getShareableContentExcludingDesktopWindows:NO onScreenWindowsOnly:NO completionHandler:^(SCShareableContent *value,NSError *error){content=value;failure=error;dispatch_semaphore_signal(ready);}];
            if(!OALiveWait(ready,5)||failure||!content)return NULL;
            SCDisplay *display=nil;
            for(SCDisplay *candidate in content.displays)if(candidate.displayID==display_id){display=candidate;break;}
            *error_code=3;if(!display)return NULL;
            OALiveScreen *record=[OALiveScreen new];record.condition=[NSCondition new];record.width=width;record.height=height;
            SCContentFilter *filter=[[SCContentFilter alloc]initWithDisplay:display excludingWindows:@[]];
            SCStreamConfiguration *configuration=[SCStreamConfiguration new];
            configuration.width=width;configuration.height=height;configuration.pixelFormat=kCVPixelFormatType_32BGRA;
            configuration.minimumFrameInterval=CMTimeMake(1,fps);configuration.queueDepth=3;configuration.showsCursor=YES;
            if(@available(macOS 13.0,*))configuration.capturesAudio=NO;
            record.stream=[[SCStream alloc]initWithFilter:filter configuration:configuration delegate:record];
            NSError *error=nil;dispatch_queue_t queue=dispatch_queue_create("uno.openagent.desktop.frames",DISPATCH_QUEUE_SERIAL);
            *error_code=4;
            if(![record.stream addStreamOutput:record type:SCStreamOutputTypeScreen sampleHandlerQueue:queue error:&error])return NULL;
            dispatch_semaphore_t started=dispatch_semaphore_create(0);
            [record.stream startCaptureWithCompletionHandler:^(NSError *error){
                [record.condition lock];if(error){record.failed=YES;record.failureCode=error.code;}BOOL cancelled=record.closed;[record.condition unlock];
                if(cancelled)[record.stream stopCaptureWithCompletionHandler:^(NSError *ignored){record.stream=nil;}];
                dispatch_semaphore_signal(started);
            }];
            if(!OALiveWait(started,5)||record.failed){
                if(record.failureCode)*error_code=(int)record.failureCode;
                [record.condition lock];record.closed=YES;[record.condition unlock];
                [record.stream stopCaptureWithCompletionHandler:^(NSError *ignored){record.stream=nil;}];
                return NULL;
            }
            *error_code=0;return (__bridge_retained void *)record;
        }
        *error_code=5;return NULL;
    }
}

int oa_live_next(void *handle, uint8_t *destination, size_t length) {
    @autoreleasepool {
        if(@available(macOS 12.3,*)){
            OALiveScreen *record=(__bridge OALiveScreen *)handle;
            [record.condition lock];
            NSDate *deadline=[NSDate dateWithTimeIntervalSinceNow:3];
            while(!record.latest&&!record.failed&&!record.closed && deadline.timeIntervalSinceNow>0)[record.condition waitUntilDate:deadline];
            if(record.closed||record.failed||!record.latest||length!=record.width*record.height*4){[record.condition unlock];return -1;}
            CVPixelBufferRef buffer=record.latest;CVPixelBufferRetain(buffer);[record.condition unlock];
            if(CVPixelBufferLockBaseAddress(buffer,kCVPixelBufferLock_ReadOnly)!=kCVReturnSuccess){CVPixelBufferRelease(buffer);return -1;}
            size_t stride=CVPixelBufferGetBytesPerRow(buffer);const uint8_t *base=CVPixelBufferGetBaseAddress(buffer);
            if(!base||stride<record.width*4){CVPixelBufferUnlockBaseAddress(buffer,kCVPixelBufferLock_ReadOnly);CVPixelBufferRelease(buffer);return -1;}
            for(size_t y=0;y<record.height;y++)for(size_t x=0;x<record.width;x++){
                const uint8_t *pixel=base+y*stride+x*4;uint8_t *output=destination+(y*record.width+x)*4;
                output[0]=pixel[2];output[1]=pixel[1];output[2]=pixel[0];output[3]=255;
            }
            CVPixelBufferUnlockBaseAddress(buffer,kCVPixelBufferLock_ReadOnly);CVPixelBufferRelease(buffer);return 0;
        }
        return -1;
    }
}

void oa_live_stop(void *handle) {
    @autoreleasepool {
        if(@available(macOS 12.3,*)){
            OALiveScreen *record=(__bridge_transfer OALiveScreen *)handle;
            [record.condition lock];record.closed=YES;
            if(record.latest){CVPixelBufferRelease(record.latest);record.latest=NULL;}
            [record.condition broadcast];[record.condition unlock];
            dispatch_semaphore_t done=dispatch_semaphore_create(0);
            [record.stream stopCaptureWithCompletionHandler:^(NSError *ignored){record.stream=nil;dispatch_semaphore_signal(done);}];
            OALiveWait(done,2);
        }
    }
}

int oa_live_supported(void) { if(@available(macOS 12.3,*))return 1;return 0; }

void oa_live_application_initialize(void) {
    @autoreleasepool { [NSApplication sharedApplication];[NSApp setActivationPolicy:NSApplicationActivationPolicyProhibited]; }
}
void oa_live_application_pump(void) {
    @autoreleasepool { [NSRunLoop.currentRunLoop runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]]; }
}
