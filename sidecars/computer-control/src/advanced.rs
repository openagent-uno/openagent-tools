//! Host-neutral native app/input/clipboard/audio contracts. All opaque resources
//! require an originating host principal; the MCP bridge does not grant access.
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LaunchArgs {
    pub app_ref: String,
    #[serde(default = "yes")]
    pub activate: bool,
}
fn yes() -> bool {
    true
}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyArgs {
    pub app_ref: Option<String>,
}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AudioStartArgs {
    /// Only public system-loopback audio is supported; never microphone fallback.
    pub source: String,
    pub app_ref: Option<String>,
    #[serde(default)]
    pub all_system_output: bool,
    #[serde(default = "audio_duration")]
    pub max_duration_ms: u32,
}
fn audio_duration() -> u32 {
    60000
}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AudioStopArgs {
    pub recording_id: String,
    #[serde(default = "yes")]
    pub return_audio: bool,
}
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InputAction {
    Focus,
    Key,
    Type,
    Click,
    Drag,
    Scroll,
}
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WindowInput {
    pub action: InputAction,
    pub text: Option<String>,
    pub key: Option<String>,
    /// Window-relative logical points, not screenshot pixel coordinates.
    pub coordinate: Option<[f64; 2]>,
    pub to_coordinate: Option<[f64; 2]>,
    pub direction: Option<String>,
    pub amount: Option<u32>,
    pub button: Option<String>,
    /// Explicit click count1..3; no automatic repeat on uncertainty.
    pub click_count: Option<u8>,
    /// Hold key/button for0..1000ms within the native request budget.
    pub duration_ms: Option<u32>,
}
impl WindowInput {
    pub fn validate(&self) -> Result<()> {
        match self.action {
            InputAction::Type => {
                if self.text.as_ref().map_or(true, |s| s.len() > 16384) {
                    return Err(anyhow!(
                        "invalid_native_input: type requires text up to16KiB"
                    ));
                }
            }
            InputAction::Key => {
                if self
                    .key
                    .as_ref()
                    .map_or(true, |s| s.is_empty() || s.len() > 128)
                {
                    return Err(anyhow!("invalid_native_input: key chord required"));
                }
            }
            InputAction::Click | InputAction::Drag | InputAction::Scroll => {
                if self.coordinate.is_none() {
                    return Err(anyhow!(
                        "invalid_native_input: window-relative coordinate required"
                    ));
                }
            }
            InputAction::Focus => {}
        }
        if self
            .coordinate
            .iter()
            .chain(self.to_coordinate.iter())
            .flatten()
            .any(|n| !n.is_finite() || *n < 0.)
        {
            return Err(anyhow!("invalid_native_input: invalid coordinates"));
        }
        if matches!(self.action, InputAction::Drag) && self.to_coordinate.is_none() {
            return Err(anyhow!("invalid_native_input: drag requires to_coordinate"));
        }
        if matches!(self.action, InputAction::Scroll)
            && (!matches!(
                self.direction.as_deref(),
                Some("up" | "down" | "left" | "right")
            ) || !matches!(self.amount, Some(1..=10000)))
        {
            return Err(anyhow!(
                "invalid_native_input: scroll direction/amount required"
            ));
        }
        if self
            .button
            .as_ref()
            .is_some_and(|s| s != "left" && s != "right" && s != "middle")
        {
            return Err(anyhow!(
                "invalid_native_input: button must be left or right"
            ));
        }
        if self.click_count.is_some_and(|n| !(1..=3).contains(&n))
            || self.duration_ms.is_some_and(|n| n > 1000)
        {
            return Err(anyhow!(
                "invalid_native_input: click_count1..3 and duration_ms0..1000 required"
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WindowInputArgs {
    pub snapshot_id: String,
    pub element_id: Option<String>,
    pub input: WindowInput,
}
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClipboardItem {
    pub mime_type: String,
    pub data_base64: String,
}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PasteArgs {
    pub snapshot_id: String,
    pub element_id: String,
    pub items: Vec<ClipboardItem>,
}
pub fn validate_clipboard(items: &[ClipboardItem]) -> Result<()> {
    use base64::Engine;
    let mut total = 0;
    let mut types = std::collections::HashSet::new();
    if items.is_empty() || items.len() > 4 {
        return Err(anyhow!(
            "invalid_clipboard_format: provide1..4 explicit representations"
        ));
    }
    for item in items {
        if !["text/plain", "text/html", "text/rtf", "image/png"].contains(&item.mime_type.as_str())
            || !types.insert(&item.mime_type)
        {
            return Err(anyhow!(
                "invalid_clipboard_format: unsupported/duplicate MIME type"
            ));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&item.data_base64)
            .map_err(|_| anyhow!("invalid_clipboard_format: invalid base64"))?;
        total += bytes.len();
        if total > 8 * 1024 * 1024 {
            return Err(anyhow!("clipboard_input_limit:8MiB maximum"));
        }
        if item.mime_type.starts_with("text/") {
            std::str::from_utf8(&bytes).map_err(|_| {
                anyhow!("invalid_clipboard_format: text representations must be UTF-8")
            })?;
        }
        if item.mime_type == "image/png" && !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            return Err(anyhow!("invalid_clipboard_format: PNG signature required"));
        }
    }
    Ok(())
}
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TextSelection {
    pub start: Option<u32>,
    pub length: Option<u32>,
    pub text: Option<String>,
    pub prefix: Option<String>,
    pub suffix: Option<String>,
    #[serde(default = "selection_mode")]
    pub mode: String,
}
fn selection_mode() -> String {
    "text".into()
}
impl TextSelection {
    pub fn range(&self, value: &str) -> Result<(usize, usize)> {
        if !["text", "before", "after"].contains(&self.mode.as_str()) {
            return Err(anyhow!("invalid_text_selection: unknown mode"));
        }
        if let (Some(start), Some(length)) = (self.start, self.length) {
            if self.text.is_some()
                || self.prefix.is_some()
                || self.suffix.is_some()
                || self.mode != "text"
            {
                return Err(anyhow!(
                    "invalid_text_selection: range and text match cannot be mixed"
                ));
            }
            let start = start as usize;
            let end = start
                .checked_add(length as usize)
                .ok_or_else(|| anyhow!("invalid_text_selection: range overflow"))?;
            let boundaries: Vec<_> = std::iter::once(0)
                .chain(value.chars().scan(0, |n, c| {
                    *n += c.len_utf16();
                    Some(*n)
                }))
                .collect();
            if !boundaries.contains(&start) || !boundaries.contains(&end) {
                return Err(anyhow!("invalid_text_selection: UTF-16 range crosses character boundary or exceeds value"));
            }
            return Ok((start, length as usize));
        }
        if self.start.is_some() || self.length.is_some() {
            return Err(anyhow!(
                "invalid_text_selection: start and length required together"
            ));
        }
        let text = self
            .text
            .as_deref()
            .filter(|s| !s.is_empty() && s.len() <= 16384)
            .ok_or_else(|| anyhow!("invalid_text_selection: nonempty bounded text required"))?;
        let matches: Vec<_> = value
            .match_indices(text)
            .filter(|(index, _)| {
                self.prefix
                    .as_ref()
                    .map_or(true, |prefix| value[..*index].ends_with(prefix))
                    && self.suffix.as_ref().map_or(true, |suffix| {
                        value[index + text.len()..].starts_with(suffix)
                    })
            })
            .collect();
        if matches.len() != 1 {
            return Err(anyhow!(
                "ambiguous_text_selection: expected one exact match, found{}",
                matches.len()
            ));
        }
        let start = value[..matches[0].0].encode_utf16().count();
        let length = text.encode_utf16().count();
        Ok(match self.mode.as_str() {
            "before" => (start, 0),
            "after" => (start + length, 0),
            _ => (start, length),
        })
    }
}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectArgs {
    pub snapshot_id: String,
    pub element_id: String,
    pub selection: TextSelection,
}
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerformArgs {
    pub snapshot_id: String,
    pub element_id: String,
    pub native_action: String,
}

pub fn request(
    value: serde_json::Value,
    cancelled: Arc<AtomicBool>,
    budget: Option<Duration>,
) -> Result<serde_json::Value> {
    request_internal(
        value,
        cancelled,
        budget,
        std::ptr::null(),
        std::ptr::null(),
        std::ptr::null(),
    )
}
/// The caller retains this exact AX window for the complete synchronous call.
#[cfg(target_os = "macos")]
pub unsafe fn request_window(
    value: serde_json::Value,
    cancelled: Arc<AtomicBool>,
    budget: Option<Duration>,
    window: *const std::ffi::c_void,
    element: *const std::ffi::c_void,
    expected_value: *const std::ffi::c_void,
) -> Result<serde_json::Value> {
    request_internal(value, cancelled, budget, window, element, expected_value)
}
fn operation_budget(operation: Option<&str>) -> Duration {
    // ScreenCaptureKit initializes asynchronously; this remains below the host
    // call deadline. AX/input/tree queries keep their existing three-second cap.
    Duration::from_secs(if operation == Some("audio_start") { 8 } else { 3 })
}
fn request_internal(
    mut value: serde_json::Value,
    cancelled: Arc<AtomicBool>,
    budget: Option<Duration>,
    window: *const std::ffi::c_void,
    element: *const std::ffi::c_void,
    expected_value: *const std::ffi::c_void,
) -> Result<serde_json::Value> {
    let maximum = operation_budget(value.get("op").and_then(|op| op.as_str()));
    let limit = budget.unwrap_or(maximum).min(maximum);
    if cancelled.load(Ordering::SeqCst) || limit.is_zero() {
        return Err(anyhow!("native_cancelled: request was not started"));
    }
    #[cfg(target_os = "macos")]
    {
        use std::ffi::{c_char, c_void, CStr, CString};
        struct Context {
            cancelled: Arc<AtomicBool>,
            deadline: Instant,
        }
        extern "C" fn check(context: *mut c_void) -> bool {
            let context = unsafe { &*(context as *const Context) };
            context.cancelled.load(Ordering::SeqCst) || Instant::now() >= context.deadline
        }
        extern "C" {
            fn oa_native_request(
                json: *const c_char,
                context: *mut c_void,
                cancelled: extern "C" fn(*mut c_void) -> bool,
                budget_ms: f64,
                window: *const c_void,
                element: *const c_void,
                expected_value: *const c_void,
            ) -> *mut c_char;
            fn oa_native_free(text: *mut c_char);
        }
        let text = CString::new(value.to_string())?;
        let mut context = Context {
            cancelled,
            deadline: Instant::now() + limit,
        };
        let result = unsafe {
            oa_native_request(
                text.as_ptr(),
                (&mut context as *mut Context).cast(),
                check,
                limit.as_secs_f64() * 1000.,
                window,
                element,
                expected_value,
            )
        };
        if result.is_null() {
            return Err(anyhow!("native_response_unavailable"));
        }
        let bytes = unsafe { CStr::from_ptr(result) }.to_bytes().to_vec();
        unsafe { oa_native_free(result) };
        value = serde_json::from_slice(&bytes)?;
        if let Some(error) = value.get("error") {
            return Err(anyhow!(
                "{}: {}",
                error
                    .get("code")
                    .and_then(|x| x.as_str())
                    .unwrap_or("native_error"),
                error
                    .get("message")
                    .and_then(|x| x.as_str())
                    .unwrap_or("Native operation failed; inspect current state before retrying")
            ));
        }
        Ok(value)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (
            &mut value,
            cancelled,
            limit,
            window,
            element,
            expected_value,
        );
        Err(anyhow!(
            "native_controls_unsupported_platform: these native controls support macOS only"
        ))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn audio_start_has_a_separate_bounded_os_initialization_budget() {
        assert_eq!(super::operation_budget(Some("audio_start")), std::time::Duration::from_secs(8));
        for op in [None, Some("window_input"), Some("audio_stop"), Some("list_apps")] {
            assert_eq!(super::operation_budget(op), std::time::Duration::from_secs(3));
        }
    }
    use super::*;
    #[test]
    fn text_ranges_are_unicode_and_ambiguity_safe() {
        let s = |text, start, length, mode: &str| TextSelection {
            text,
            start,
            length,
            prefix: None,
            suffix: None,
            mode: mode.into(),
        };
        assert_eq!(
            s(Some("🌞".into()), None, None, "text")
                .range("a🌞b")
                .unwrap(),
            (1, 2)
        );
        assert!(s(None, Some(2), Some(1), "text").range("a🌞b").is_err());
        assert!(s(Some("x".into()), None, None, "text")
            .range("x x")
            .is_err());
        let mut selector = s(Some("x".into()), None, None, "after");
        selector.prefix = Some("a".into());
        assert_eq!(selector.range("ax bx").unwrap(), (2, 0));
    }
    #[test]
    fn clipboard_formats_are_explicit_and_bounded() {
        assert!(validate_clipboard(&[]).is_err());
        assert!(validate_clipboard(&[ClipboardItem {
            mime_type: "public.file-url".into(),
            data_base64: "".into()
        }])
        .is_err());
        assert!(validate_clipboard(&[ClipboardItem {
            mime_type: "text/plain".into(),
            data_base64: "Y2lhbw==".into()
        }])
        .is_ok());
    }
}
