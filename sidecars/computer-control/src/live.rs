//! Continuous H.264 Annex-B frames. No file writes or network/identity policy.
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use openh264::{
    encoder::{Encoder, EncoderConfig, FrameRate, FrameType, UsageType},
    formats::{RgbaSliceU8, YUVBuffer},
};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

fn options(request: &Value) -> Result<(u64, u64, Option<u32>)> {
    let object = request
        .as_object()
        .ok_or_else(|| anyhow!("live options must be an object"))?;
    if object
        .keys()
        .any(|key| !["display_id", "fps", "max_duration_seconds"].contains(&key.as_str()))
    {
        bail!("unknown live option");
    }
    let number = |key: &str, default: u64, min: u64, max: u64| -> Result<u64> {
        let value = match request.get(key) {
            None => default,
            Some(value) => value.as_u64().ok_or_else(|| anyhow!("invalid {key}"))?,
        };
        if !(min..=max).contains(&value) {
            bail!("invalid {key}");
        }
        Ok(value)
    };
    let fps = number("fps", 20, 1, 30)?;
    let seconds = number("max_duration_seconds", 60, 1, 300)?;
    let display = if request.get("display_id").is_some() {
        Some(number("display_id", 0, 0, u32::MAX as u64)? as u32)
    } else {
        None
    };
    Ok((fps, seconds, display))
}

pub fn serve() -> Result<()> {
    let mut reader = io::BufReader::new(io::stdin());
    let mut line = String::new();
    reader.by_ref().take(8193).read_line(&mut line)?;
    if line.len() > 8192 {
        bail!("invalid live request");
    }
    let request: Value = serde_json::from_str(&line)?;
    let (fps, seconds, display) = options(&request)?;
    let monitors = xcap::Monitor::all()?;
    let monitor = if let Some(id) = display {
        monitors.into_iter().find(|m| m.id().ok() == Some(id))
    } else {
        monitors
            .iter()
            .position(|m| m.is_primary().unwrap_or(false))
            .and_then(|i| monitors.get(i).cloned())
            .or_else(|| monitors.into_iter().next())
    }
    .ok_or_else(|| anyhow!("display unavailable"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let eof = stop.clone();
    std::thread::spawn(move || {
        let mut command = String::new();
        let _ = reader.by_ref().take(8193).read_line(&mut command);
        eof.store(true, Ordering::SeqCst);
    });
    let original_geometry=(monitor.width()?,monitor.height()?);
    #[cfg(target_os="macos")]
    let scale=crate::scaling::size_to_api_scale(original_geometry.0,original_geometry.1);
    #[cfg(target_os="macos")]
    let api_width=((original_geometry.0 as f64*scale).round() as u32).max(2);
    #[cfg(target_os="macos")]
    let api_height=((original_geometry.1 as f64*scale).round() as u32).max(2);
    #[cfg(target_os="macos")]
    let native=crate::live_macos::ScreenStream::start(monitor.id()?,api_width&!1,api_height&!1,fps as u32)?;
    let config = EncoderConfig::new()
        .max_frame_rate(FrameRate::from_hz(fps as f32))
        .usage_type(UsageType::ScreenContentRealTime);
    let mut encoder = Encoder::with_api_config(openh264::OpenH264API::from_source(), config)?;
    let mut writer = io::BufWriter::new(io::stdout().lock());
    let started = Instant::now();
    let interval = Duration::from_secs_f64(1.0 / fps as f64);
    let mut resizer = fast_image_resize::Resizer::new();
    let mut seq = 0u64;
    let mut dimensions = None;
    while !stop.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(seconds) {
        let tick = Instant::now();
        if (monitor.width()?,monitor.height()?)!=original_geometry{bail!("display geometry changed; reopen live stream");}
        #[cfg(target_os="macos")]
        let rgba=native.frame()?;
        #[cfg(not(target_os="macos"))]
        let rgba = crate::capture::capture_display_frame_rgba(&monitor)?;
        #[cfg(not(target_os="macos"))]
        let scale = crate::scaling::size_to_api_scale(rgba.width(), rgba.height());
        #[cfg(target_os="macos")]
        let (input_w,input_h)=(api_width,api_height);
        #[cfg(not(target_os="macos"))]
        let (input_w,input_h)=(((rgba.width() as f64*scale).round() as u32).max(2),((rgba.height() as f64*scale).round() as u32).max(2));
        let w = input_w & !1;
        let h = input_h & !1;
        if dimensions.is_some_and(|value| value != (w, h, input_w, input_h)) {
            bail!("display geometry changed; reopen live stream");
        }
        dimensions = Some((w, h, input_w, input_h));
        let scaled = if rgba.width() == w && rgba.height() == h {
            rgba
        } else {
            crate::record::resize_rgba(&mut resizer, rgba, w, h)?
        };
        let yuv =
            YUVBuffer::from_rgb_source(RgbaSliceU8::new(scaled.as_raw(), (w as usize, h as usize)));
        let encoded = encoder.encode(&yuv).context("encode live desktop")?;
        let key = matches!(encoded.frame_type(), FrameType::IDR | FrameType::I);
        let mut data = Vec::new();
        encoded.write_vec(&mut data);
        // OpenH264 may skip a frame under load or on a static desktop. A skip
        // has no access unit: preserve the decoder sequence and last picture.
        if data.is_empty() {
            if let Some(delay) = interval.checked_sub(tick.elapsed()) {
                std::thread::sleep(delay);
            }
            continue;
        }
        if data.len() > 1024 * 1024 {
            bail!("encoded frame exceeds limit");
        }
        if seq == 0 {
            let nals = crate::record::split_annexb(&data);
            let sps = nals
                .iter()
                .find(|n| n.len() >= 4 && (n[0] & 31) == 7)
                .ok_or_else(|| anyhow!("missing stream configuration"))?;
            let codec = format!("avc1.{:02X}{:02X}{:02X}", sps[1], sps[2], sps[3]);
            writeln!(
                writer,
                "{}",
                json!({"type":"config","protocol":"openagent-video/1","codec":codec,"width":w,"height":h,"input_width":input_w,"input_height":input_h,"fps":fps})
            )?;
        }
        writeln!(
            writer,
            "{}",
            json!({"type":"frame","seq":seq,"timestamp_us":started.elapsed().as_micros() as u64,"key":key,"data":STANDARD.encode(data)})
        )?;
        writer.flush()?;
        seq += 1;
        if let Some(delay) = interval.checked_sub(tick.elapsed()) {
            std::thread::sleep(delay);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_display_and_limits() {
        assert_eq!(
            options(&json!({"display_id":42,"fps":20})).unwrap(),
            (20, 60, Some(42))
        );
        for value in [
            json!({"display_id":-1}),
            json!({"display_id":"42"}),
            json!({"fps":null}),
            json!({"fps":31}),
            json!({"max_duration_seconds":301}),
            json!({"command":"x"}),
            json!([]),
        ] {
            assert!(options(&value).is_err());
        }
    }
}
