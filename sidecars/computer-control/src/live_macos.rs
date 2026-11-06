//! Owned ScreenCaptureKit stream; the host process owns cancellation.
use anyhow::{bail, Result};
use std::ffi::c_void;
extern "C" {
    fn oa_live_supported()->i32;
    fn oa_live_application_initialize();
    fn oa_live_application_pump();
    fn oa_live_start(display:u32,width:u32,height:u32,fps:u32,error:*mut i32)->*mut c_void;
    fn oa_live_next(handle:*mut c_void,destination:*mut u8,length:usize)->i32;
    fn oa_live_stop(handle:*mut c_void);
}
pub struct ScreenStream { handle:*mut c_void,width:u32,height:u32 }
impl ScreenStream {
    pub fn supported()->bool {unsafe{oa_live_supported()!=0}}
    pub fn start(display:u32,width:u32,height:u32,fps:u32)->Result<Self>{
        let mut error=0;
        let handle=unsafe{oa_live_start(display,width,height,fps,&mut error)};
        if handle.is_null(){bail!("native live display unavailable (code {error}); verify Screen Recording permission");}
        Ok(Self{handle,width,height})
    }
    pub fn frame(&self)->Result<image::RgbaImage>{
        let mut data=vec![0u8;self.width as usize*self.height as usize*4];
        if unsafe{oa_live_next(self.handle,data.as_mut_ptr(),data.len())}!=0{bail!("native live display stopped or changed");}
        image::RgbaImage::from_raw(self.width,self.height,data).ok_or_else(||anyhow::anyhow!("invalid native frame"))
    }
}
impl Drop for ScreenStream {fn drop(&mut self){unsafe{oa_live_stop(self.handle);}}}

pub fn application_initialize(){unsafe{oa_live_application_initialize();}}
pub fn application_pump(){unsafe{oa_live_application_pump();}}
