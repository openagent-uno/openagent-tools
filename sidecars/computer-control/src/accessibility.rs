//! Bounded native accessibility snapshots. Element handles are process-local,
//! short-lived and single-use: an uncertain mutation is never replayed.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_SNAPSHOTS: usize = 8;
const SNAPSHOT_TTL: Duration = Duration::from_secs(120);

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotArgs {
    pub window_id: u32,
    #[schemars(range(min = 1))]
    pub pid: u32,
    /// Maximum tree depth (1–30, default 12).
    #[schemars(range(min = 1, max = 30))]
    pub max_depth: Option<u8>,
    /// Maximum elements (1–1000, default 300). Responses identify truncation.
    #[schemars(range(min = 1, max = 1000))]
    pub max_nodes: Option<u16>,
}

impl SnapshotArgs {
    fn limits(&self) -> Result<(usize, usize)> {
        let depth = self.max_depth.unwrap_or(12) as usize;
        let nodes = self.max_nodes.unwrap_or(300) as usize;
        if !(1..=30).contains(&depth) || !(1..=1000).contains(&nodes) || self.pid == 0 {
            return Err(anyhow!("invalid_accessibility_arguments: max_depth must be 1..30, max_nodes 1..1000 and pid nonzero"));
        }
        Ok((depth, nodes))
    }
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ElementAction {
    Press,
    ShowMenu,
    SetValue,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionArgs {
    #[schemars(length(min = 1, max = 128))]
    pub snapshot_id: String,
    #[schemars(length(min = 9, max = 11))]
    pub element_id: String,
    pub action: ElementAction,
    /// Required only for set_value. Limited to 16 KiB; secure fields are excluded.
    #[schemars(length(max = 16384))]
    pub value: Option<String>,
}

impl ActionArgs {
    fn index(&self) -> Result<usize> {
        if self.snapshot_id.len() > 128 {
            return Err(anyhow!(
                "invalid_accessibility_arguments: invalid snapshot_id"
            ));
        }
        let index = self
            .element_id
            .strip_prefix("element-")
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|index| *index < 1000 && self.element_id == format!("element-{index}"))
            .ok_or_else(|| anyhow!("invalid_accessibility_arguments: invalid element_id"))?;
        match (&self.action, &self.value) {
            (ElementAction::SetValue, Some(value)) if value.len() <= 16 * 1024 => {}
            (ElementAction::SetValue, _) => {
                return Err(anyhow!(
                    "invalid_accessibility_arguments: set_value requires a value of at most 16 KiB"
                ))
            }
            (_, None) => {}
            _ => {
                return Err(anyhow!(
                    "invalid_accessibility_arguments: value is supported only for set_value"
                ))
            }
        }
        Ok(index)
    }
}

pub enum Mutation {
    Simple(ElementAction, Option<String>),
    ObservedAction(String),
    Select(crate::advanced::TextSelection),
    Input(crate::advanced::WindowInput),
    Paste(Vec<crate::advanced::ClipboardItem>),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct WindowTarget {
    window_id: u32,
    pid: u32,
    title: String,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    process_started: [u64; 2],
}

struct SnapshotStore<T> {
    nonce: String,
    next_id: u64,
    entries: VecDeque<(String, Instant, (u32, u32), T)>,
}

impl<T> Default for SnapshotStore<T> {
    fn default() -> Self {
        Self {
            nonce: format!(
                "{:x}-{:x}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ),
            next_id: 0,
            entries: VecDeque::new(),
        }
    }
}

impl<T> SnapshotStore<T> {
    fn insert(&mut self, target: (u32, u32), value: T, now: Instant) -> String {
        // A new observation supersedes handles from an older tree of this window.
        self.entries.retain(|(_, created, previous, _)| {
            *previous != target && now.duration_since(*created) < SNAPSHOT_TTL
        });
        while self.entries.len() >= MAX_SNAPSHOTS {
            self.entries.pop_front();
        }
        self.next_id += 1;
        let id = format!("ax-{}-{}", self.nonce, self.next_id);
        self.entries.push_back((id.clone(), now, target, value));
        id
    }

    fn take(&mut self, id: &str, now: Instant) -> Result<T> {
        let index = self
            .entries
            .iter()
            .position(|(key, _, _, _)| key == id)
            .ok_or_else(|| {
                anyhow!("stale_accessibility_snapshot: take a new snapshot before acting")
            })?;
        let (_, created, _, value) = self.entries.remove(index).expect("located entry");
        if now.duration_since(created) >= SNAPSHOT_TTL {
            return Err(anyhow!(
                "stale_accessibility_snapshot: snapshot expired; take a new snapshot"
            ));
        }
        Ok(value)
    }
}

#[cfg(target_os = "macos")]
#[derive(Default)]
pub struct AccessibilityService {
    snapshots: SnapshotStore<macos::NativeSnapshot>,
}
#[cfg(not(target_os = "macos"))]
#[derive(Default)]
pub struct AccessibilityService;

impl AccessibilityService {
    pub fn snapshot(
        &mut self,
        args: SnapshotArgs,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<serde_json::Value> {
        let (max_depth, max_nodes) = args.limits()?;
        #[cfg(target_os = "macos")]
        {
            let (snapshot, mut result) =
                macos::snapshot(args.window_id, args.pid, max_depth, max_nodes, cancelled)?;
            let id = self
                .snapshots
                .insert((args.window_id, args.pid), snapshot, Instant::now());
            result["snapshot_id"] = serde_json::Value::String(id);
            Ok(result)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (max_depth, max_nodes, cancelled);
            Err(anyhow!("accessibility_unsupported_platform: native accessibility tools currently support macOS only"))
        }
    }

    pub fn mutate(
        &mut self,
        snapshot_id: String,
        element_id: String,
        mutation: Mutation,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<serde_json::Value> {
        let identity = ActionArgs {
            snapshot_id,
            element_id,
            action: ElementAction::Press,
            value: None,
        };
        let index = identity.index()?;
        match &mutation {
            Mutation::Input(input) => input.validate()?,
            Mutation::Paste(items) => crate::advanced::validate_clipboard(items)?,
            Mutation::ObservedAction(name) if name.is_empty() || name.len() > 128 => {
                return Err(anyhow!(
                    "invalid_native_action: provide an observed action name up to128bytes"
                ))
            }
            _ => {}
        }
        #[cfg(target_os = "macos")]
        {
            let snapshot = self.snapshots.take(&identity.snapshot_id, Instant::now())?;
            macos::act(snapshot, index, mutation, cancelled)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (index, mutation, cancelled);
            Err(anyhow!(
                "native_controls_unsupported_platform: these native controls support macOS only"
            ))
        }
    }

    pub fn action(
        &mut self,
        args: ActionArgs,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<serde_json::Value> {
        let index = args.index()?;
        #[cfg(target_os = "macos")]
        {
            // Remove before validating/executing the target. Any uncertain result
            // requires a fresh observation instead of repeating the mutation.
            let snapshot = self.snapshots.take(&args.snapshot_id, Instant::now())?;
            macos::act(
                snapshot,
                index,
                Mutation::Simple(args.action, args.value),
                cancelled,
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (index, cancelled);
            Err(anyhow!("accessibility_unsupported_platform: native accessibility tools currently support macOS only"))
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::ffi::c_void;
    use std::ptr;

    const MESSAGE_TIMEOUT_SECONDS: f32 = 0.25;
    const REQUEST_BUDGET: Duration = Duration::from_secs(3);
    #[derive(Clone)]
    struct QueryContext {
        deadline: Instant,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }
    thread_local! {
        static QUERY_CONTEXT: std::cell::RefCell<Option<QueryContext>> = const { std::cell::RefCell::new(None) };
    }
    struct QueryGuard(Option<QueryContext>);
    impl QueryGuard {
        fn new(cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>) -> Self {
            let context = QueryContext {
                deadline: Instant::now() + REQUEST_BUDGET,
                cancelled,
            };
            Self(QUERY_CONTEXT.with(|slot| slot.replace(Some(context))))
        }
    }
    impl Drop for QueryGuard {
        fn drop(&mut self) {
            QUERY_CONTEXT.with(|slot| slot.replace(self.0.take()));
        }
    }
    fn query_timeout() -> Result<f32> {
        QUERY_CONTEXT.with(|slot| {
            let context = slot.borrow();
            let Some(context) = context.as_ref() else { return Ok(MESSAGE_TIMEOUT_SECONDS); };
            if context.cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(anyhow!("accessibility_cancelled: native request cancelled before the next operation"));
            }
            let remaining = context.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!("accessibility_timeout: aggregate native request budget expired; take a fresh snapshot"));
            }
            Ok(remaining.as_secs_f32().min(MESSAGE_TIMEOUT_SECONDS))
        })
    }

    type Ref = *const c_void;
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct Point {
        x: f64,
        y: f64,
    }
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct Size {
        width: f64,
        height: f64,
    }
    #[repr(C)]
    struct Range {
        location: isize,
        length: isize,
    }

    // Public ApplicationServices and CoreFoundation declarations from Apple's
    // AXUIElement.h, AXValue.h and CF*.h. No private AX window-number API.
    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn AXUIElementCreateApplication(pid: i32) -> Ref;
        fn AXUIElementGetTypeID() -> usize;
        fn AXUIElementGetPid(element: Ref, pid: *mut i32) -> i32;
        fn AXUIElementCopyAttributeValue(element: Ref, attribute: Ref, value: *mut Ref) -> i32;
        fn AXUIElementCopyActionNames(element: Ref, value: *mut Ref) -> i32;
        fn AXUIElementPerformAction(element: Ref, action: Ref) -> i32;
        fn AXUIElementSetAttributeValue(element: Ref, attribute: Ref, value: Ref) -> i32;
        fn AXUIElementIsAttributeSettable(element: Ref, attribute: Ref, settable: *mut u8) -> i32;
        fn AXUIElementSetMessagingTimeout(element: Ref, timeout: f32) -> i32;
        fn AXValueCreate(kind: u32, value: *const c_void) -> Ref;
        fn AXValueGetTypeID() -> usize;
        fn AXValueGetValue(value: Ref, kind: u32, output: *mut c_void) -> u8;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRelease(value: Ref);
        fn CFRetain(value: Ref) -> Ref;
        fn CFGetTypeID(value: Ref) -> usize;
        fn CFEqual(left: Ref, right: Ref) -> u8;
        fn CFStringGetTypeID() -> usize;
        fn CFStringCreateWithBytes(
            allocator: Ref,
            bytes: *const u8,
            length: isize,
            encoding: u32,
            external: u8,
        ) -> Ref;
        fn CFStringGetLength(value: Ref) -> isize;
        fn CFStringGetBytes(
            value: Ref,
            range: Range,
            encoding: u32,
            loss: u8,
            external: u8,
            buffer: *mut u8,
            size: isize,
            used: *mut isize,
        ) -> isize;
        fn CFNumberGetTypeID() -> usize;
        fn CFArrayGetTypeID() -> usize;
        fn CFArrayGetCount(value: Ref) -> isize;
        fn CFArrayGetValueAtIndex(value: Ref, index: isize) -> Ref;
        fn CFBooleanGetTypeID() -> usize;
        fn CFBooleanGetValue(value: Ref) -> u8;
        static kCFBooleanTrue: Ref;
    }

    /// Owns exactly one create/copy-rule CF reference. Every borrowed array item
    /// is retained before it escapes its array. All access is serialized by the
    /// service mutex; AX/CF IPC references may be used on any worker thread.
    struct Object(Ref);
    unsafe impl Send for Object {}
    impl Drop for Object {
        fn drop(&mut self) {
            unsafe { CFRelease(self.0) }
        }
    }
    impl Clone for Object {
        fn clone(&self) -> Self {
            unsafe { Self(CFRetain(self.0)) }
        }
    }
    impl Object {
        fn owned(value: Ref) -> Result<Self> {
            if value.is_null() {
                Err(anyhow!("accessibility_unavailable: null native reference"))
            } else {
                let object = Self(value);
                if unsafe { CFGetTypeID(value) == AXUIElementGetTypeID() } {
                    object.prepare_query()?;
                }
                Ok(object)
            }
        }
        fn prepare_query(&self) -> Result<()> {
            let timeout = query_timeout()?;
            // Apple scopes a timeout to this exact AX object, not its children
            // or even equal references. Apply it before every remote operation.
            let status = unsafe { AXUIElementSetMessagingTimeout(self.0, timeout) };
            if status != 0 {
                return Err(ax_error(status));
            }
            Ok(())
        }
        fn string(value: &str) -> Result<Self> {
            Self::owned(unsafe {
                CFStringCreateWithBytes(
                    ptr::null(),
                    value.as_ptr(),
                    value.len() as isize,
                    0x08000100,
                    0,
                )
            })
        }
        fn attr(&self, name: &str) -> Result<Option<Self>> {
            let key = Self::string(name)?;
            let mut value = ptr::null();
            self.prepare_query()?;
            let status = unsafe { AXUIElementCopyAttributeValue(self.0, key.0, &mut value) };
            match status {
                0 => Ok(Some(Self::owned(value)?)),
                // Unsupported/no-value attributes are normal on AX nodes.
                -25205 | -25212 => Ok(None),
                _ => Err(ax_error(status).context(format!("read native attribute {name}"))),
            }
        }
        fn text(&self) -> Option<String> {
            self.text_limit(512)
        }
        fn text_limit(&self, limit: usize) -> Option<String> {
            if unsafe { CFGetTypeID(self.0) != CFStringGetTypeID() } {
                return None;
            }
            let length = unsafe { CFStringGetLength(self.0) };
            if length < 0 || length > 64 * 1024 {
                return Some("[value exceeds text limit]".into());
            }
            let mut bytes = vec![0u8; length as usize * 4 + 1];
            let mut used = 0;
            let converted = unsafe {
                CFStringGetBytes(
                    self.0,
                    Range {
                        location: 0,
                        length,
                    },
                    0x08000100,
                    0,
                    0,
                    bytes.as_mut_ptr(),
                    bytes.len() as isize,
                    &mut used,
                )
            };
            if converted != length || used < 0 || used as usize > bytes.len() {
                return None;
            }
            Some(
                String::from_utf8_lossy(&bytes[..used as usize])
                    .chars()
                    .take(limit)
                    .collect(),
            )
        }
        fn observation_attr(&self, name: &str) -> Result<Option<Self>> {
            if name != "AXDescription" {
                return self.attr(name);
            }
            // AppKit rich-text descendants may report generic failure for an
            // optional absent description. It is descriptive metadata, never
            // an identity/ownership permission or a required editable value.
            let key = Self::string(name)?;
            let mut value = ptr::null();
            self.prepare_query()?;
            match unsafe { AXUIElementCopyAttributeValue(self.0, key.0, &mut value) } {
                0 => Ok(Some(Self::owned(value)?)),
                -25200 | -25205 | -25212 => Ok(None),
                code => Err(ax_error(code)),
            }
        }
        fn text_attr(&self, name: &str) -> Result<Option<String>> {
            Ok(self.observation_attr(name)?.and_then(|value| value.text()))
        }
        fn bool_attr(&self, name: &str) -> Result<Option<bool>> {
            Ok(self.attr(name)?.and_then(|value| {
                if unsafe { CFGetTypeID(value.0) == CFBooleanGetTypeID() } {
                    Some(unsafe { CFBooleanGetValue(value.0) != 0 })
                } else {
                    None
                }
            }))
        }
        fn array(&self, expected_type: usize, limit: usize) -> Result<Vec<Self>> {
            if unsafe { CFGetTypeID(self.0) != CFArrayGetTypeID() } {
                return Err(anyhow!(
                    "accessibility_invalid_response: expected native array"
                ));
            }
            let count = unsafe { CFArrayGetCount(self.0) };
            if count < 0 {
                return Err(anyhow!(
                    "accessibility_invalid_response: invalid native array size"
                ));
            }
            let mut values = Vec::new();
            for index in 0..(count as usize).min(limit) {
                let value = unsafe { CFArrayGetValueAtIndex(self.0, index as isize) };
                if value.is_null() || unsafe { CFGetTypeID(value) != expected_type } {
                    return Err(anyhow!(
                        "accessibility_invalid_response: unexpected native array element"
                    ));
                }
                query_timeout()?;
                values.push(Self::owned(unsafe { CFRetain(value) })?);
            }
            Ok(values)
        }
        fn equal(&self, other: &Self) -> bool {
            unsafe { CFEqual(self.0, other.0) != 0 }
        }
        fn selection_range(&self) -> Result<Option<[usize; 2]>> {
            let Some(value) = self.attr("AXSelectedTextRange")? else {
                return Ok(None);
            };
            if unsafe { CFGetTypeID(value.0) != AXValueGetTypeID() } {
                return Ok(None);
            }
            let mut range = Range {
                location: 0,
                length: 0,
            };
            if unsafe { AXValueGetValue(value.0, 4, (&mut range as *mut Range).cast()) } == 0
                || range.location < 0
                || range.length < 0
            {
                return Ok(None);
            }
            Ok(Some([range.location as usize, range.length as usize]))
        }
        fn bounds(&self) -> Result<Option<[f64; 4]>> {
            let (Some(position), Some(size)) = (self.attr("AXPosition")?, self.attr("AXSize")?)
            else {
                return Ok(None);
            };
            if unsafe {
                CFGetTypeID(position.0) != AXValueGetTypeID()
                    || CFGetTypeID(size.0) != AXValueGetTypeID()
            } {
                return Ok(None);
            }
            let mut point = Point::default();
            let mut extent = Size::default();
            if unsafe { AXValueGetValue(position.0, 1, (&mut point as *mut Point).cast()) } == 0
                || unsafe { AXValueGetValue(size.0, 2, (&mut extent as *mut Size).cast()) } == 0
            {
                return Ok(None);
            }
            let bounds = [point.x, point.y, extent.width, extent.height];
            Ok(bounds
                .iter()
                .all(|value| value.is_finite())
                .then_some(bounds))
        }
    }

    #[repr(C)]
    #[derive(Default)]
    struct ProcessInfo {
        fields: [u32; 12],
        command: [u8; 16],
        name: [u8; 32],
        counters: [u32; 6],
        started_seconds: u64,
        started_microseconds: u64,
    }
    #[link(name = "proc")]
    extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            argument: u64,
            buffer: *mut c_void,
            size: i32,
        ) -> i32;
    }

    fn process_started(pid: u32) -> Result<[u64; 2]> {
        let pid = i32::try_from(pid)
            .map_err(|_| anyhow!("invalid_accessibility_arguments: invalid pid"))?;
        let mut info = ProcessInfo::default();
        let size = std::mem::size_of::<ProcessInfo>() as i32;
        let read = unsafe { proc_pidinfo(pid, 3, 0, (&mut info as *mut ProcessInfo).cast(), size) };
        if read != size || info.fields[3] != pid as u32 {
            return Err(anyhow!(
                "stale_window_target: cannot verify process generation"
            ));
        }
        Ok([info.started_seconds, info.started_microseconds])
    }

    fn ax_error(code: i32) -> anyhow::Error {
        match code {
            -25204 => anyhow!("accessibility_timeout: app did not answer; take a fresh snapshot before another action"),
            -25202 => anyhow!("stale_accessibility_element: native element no longer exists; take a fresh snapshot"),
            -25211 => anyhow!("accessibility_permission_required: enable the signed computer-control helper in macOS Accessibility settings"),
            _ => anyhow!("accessibility_operation_failed: native AX error {code}; outcome may be uncertain, inspect a fresh snapshot"),
        }
    }

    fn require_permission() -> Result<()> {
        if !macos_accessibility_client::accessibility::application_is_trusted() {
            return Err(anyhow!("accessibility_permission_required: enable 'openagent-computer-control' in System Settings → Privacy & Security → Accessibility, then retry"));
        }
        Ok(())
    }

    fn target(window_id: u32, pid: u32) -> Result<WindowTarget> {
        crate::capture::require_screen_recording_permission()?;
        let window = xcap::Window::all()?.into_iter()
            .find(|window| window.id().ok() == Some(window_id) && window.pid().ok() == Some(pid))
            .ok_or_else(|| anyhow!("stale_window_target: exact window_id/pid pair is unavailable; list windows again"))?;
        Ok(WindowTarget {
            window_id,
            pid,
            title: window.title()?,
            x: window.x()?,
            y: window.y()?,
            width: window.width()?,
            height: window.height()?,
            process_started: process_started(pid)?,
        })
    }

    fn window(target: &WindowTarget) -> Result<Object> {
        let pid = i32::try_from(target.pid)
            .map_err(|_| anyhow!("invalid_accessibility_arguments: pid outside native range"))?;
        let app = Object::owned(unsafe { AXUIElementCreateApplication(pid) })?;
        let status = unsafe { AXUIElementSetMessagingTimeout(app.0, 0.25) };
        if status != 0 {
            return Err(ax_error(status));
        }
        let values = app
            .attr("AXWindows")?
            .ok_or_else(|| anyhow!("accessibility_unavailable: app exposes no windows"))?;
        if unsafe { CFGetTypeID(values.0) != CFArrayGetTypeID() || CFArrayGetCount(values.0) > 200 }
        {
            return Err(anyhow!(
                "accessibility_window_limit: cannot uniquely verify the app window inventory"
            ));
        }
        let windows = values.array(unsafe { AXUIElementGetTypeID() }, 200)?;
        let mut matches = Vec::new();
        let started = Instant::now();
        for item in windows {
            if started.elapsed() > Duration::from_secs(3) {
                return Err(anyhow!(
                    "accessibility_timeout: cannot finish window identity verification"
                ));
            }
            let Some(bounds) = item.bounds()? else {
                continue;
            };
            let title = item.text_attr("AXTitle")?.unwrap_or_default();
            if window_matches(target, bounds, &title)
                && !matches.iter().any(|other: &Object| item.equal(other))
            {
                matches.push(item);
            }
        }
        if matches.len() != 1 {
            return Err(anyhow!("ambiguous_accessibility_window: expected exactly one matching AX window, found {}; refresh window inventory", matches.len()));
        }
        Ok(matches.pop().expect("exactly one match"))
    }

    fn window_matches(target: &WindowTarget, bounds: [f64; 4], title: &str) -> bool {
        let expected = [
            target.x as f64,
            target.y as f64,
            target.width as f64,
            target.height as f64,
        ];
        bounds
            .iter()
            .zip(expected)
            .all(|(actual, expected)| (*actual - expected).abs() <= 2.0)
            && (target.title.is_empty() || target.title == title)
    }

    #[derive(Clone, Debug, PartialEq, Serialize)]
    struct Description {
        role: String,
        subrole: Option<String>,
        title: Option<String>,
        description: Option<String>,
        identifier: Option<String>,
        value: Option<String>,
        enabled: Option<bool>,
        focused: Option<bool>,
        bounds: Option<[f64; 4]>,
        actions: Vec<String>,
        value_settable: bool,
        selected_text_range: Option<[usize; 2]>,
    }

    impl Description {
        fn read(element: &Object) -> Result<Self> {
            let role = element
                .text_attr("AXRole")?
                .ok_or_else(|| anyhow!("stale_accessibility_element: no native role"))?;
            let subrole = element.text_attr("AXSubrole")?;
            let secure =
                role == "AXSecureTextField" || subrole.as_deref() == Some("AXSecureTextField");
            let mut names = ptr::null();
            element.prepare_query()?;
            let status = unsafe { AXUIElementCopyActionNames(element.0, &mut names) };
            let mut actions: Vec<String> = match status {
                0 => Object::owned(names)?
                    .array(unsafe { CFStringGetTypeID() }, 128)?
                    .into_iter()
                    .filter_map(|value| value.text())
                    .collect(),
                -25206 | -25208 => Vec::new(),
                _ => return Err(ax_error(status)),
            };
            actions.sort();
            let mut settable = 0;
            let attribute = Object::string("AXValue")?;
            element.prepare_query()?;
            let status =
                unsafe { AXUIElementIsAttributeSettable(element.0, attribute.0, &mut settable) };
            if status != 0 && status != -25205 && status != -25212 {
                return Err(ax_error(status));
            }
            Ok(Self {
                role,
                subrole,
                title: element.text_attr("AXTitle")?,
                description: element.text_attr("AXDescription")?,
                identifier: element.text_attr("AXIdentifier")?,
                value: if secure {
                    None
                } else {
                    element.text_attr("AXValue")?
                },
                enabled: element.bool_attr("AXEnabled")?,
                focused: element.bool_attr("AXFocused")?,
                bounds: element.bounds()?,
                actions,
                value_settable: !secure && settable != 0,
                selected_text_range: if secure {
                    None
                } else {
                    element.selection_range()?
                },
            })
        }
    }

    // Keep exact immutable native scalar values for stale-state comparisons.
    // The displayed text is bounded to 512 characters; comparing that truncated
    // text alone could overwrite a concurrent edit beyond its visible prefix.
    struct ObservedState {
        values: Vec<Option<Object>>,
        complete: bool,
    }
    impl ObservedState {
        fn read(element: &Object, secure: bool, budget: &mut usize) -> Result<Self> {
            let mut values = Vec::new();
            let mut complete = true;
            for name in [
                "AXRole",
                "AXSubrole",
                "AXTitle",
                "AXDescription",
                "AXIdentifier",
                "AXEnabled",
                "AXFocused",
                "AXValue",
            ] {
                if secure && name == "AXValue" {
                    values.push(None);
                    continue;
                }
                let mut value = element.observation_attr(name)?;
                if let Some(raw) = &value {
                    let kind = unsafe { CFGetTypeID(raw.0) };
                    let bytes = if kind == unsafe { CFStringGetTypeID() } {
                        let length = unsafe { CFStringGetLength(raw.0) };
                        if length < 0 {
                            return Err(anyhow!(
                                "accessibility_invalid_response: invalid text size"
                            ));
                        }
                        (length as usize).saturating_mul(4)
                    } else if kind == unsafe { CFBooleanGetTypeID() }
                        || kind == unsafe { CFNumberGetTypeID() }
                    {
                        32
                    } else {
                        complete = false;
                        value = None;
                        0
                    };
                    if bytes > *budget {
                        complete = false;
                        value = None;
                    } else {
                        *budget -= bytes;
                    }
                }
                values.push(value);
            }
            Ok(Self { values, complete })
        }
        fn matches(&self, other: &Self) -> bool {
            self.complete
                && other.complete
                && self.values.len() == other.values.len()
                && self
                    .values
                    .iter()
                    .zip(&other.values)
                    .all(|(left, right)| match (left, right) {
                        (Some(left), Some(right)) => left.equal(right),
                        (None, None) => true,
                        _ => false,
                    })
        }
    }
    struct Entry {
        element: Object,
        description: Description,
        observed: ObservedState,
    }
    pub(super) struct NativeSnapshot {
        target: WindowTarget,
        root: Object,
        entries: Vec<Entry>,
    }

    pub(super) fn snapshot(
        window_id: u32,
        pid: u32,
        max_depth: usize,
        max_nodes: usize,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<(NativeSnapshot, serde_json::Value)> {
        let _queries = QueryGuard::new(cancelled);
        query_timeout()?;
        require_permission()?;
        let target = target(window_id, pid)?;
        let root = window(&target)?;
        let started = Instant::now();
        let mut stack = vec![(root.clone(), None::<String>, 0usize)];
        let mut entries: Vec<Entry> = Vec::new();
        let mut rows = Vec::new();
        let mut truncated = false;
        let mut retained_bytes = 2 * 1024 * 1024;
        while let Some((element, parent, depth)) = stack.pop() {
            if entries.len() >= max_nodes || started.elapsed() > Duration::from_secs(3) {
                truncated = true;
                break;
            }
            if entries.iter().any(|entry| entry.element.equal(&element)) {
                continue;
            }
            let description = Description::read(&element)?;
            let id = format!("element-{}", entries.len());
            let secure = description.role == "AXSecureTextField"
                || description.subrole.as_deref() == Some("AXSecureTextField");
            let observed = ObservedState::read(&element, secure, &mut retained_bytes)?;
            rows.push(serde_json::json!({"element_id": id, "parent_id": parent, "depth": depth, "state": description, "actionable": observed.complete}));
            entries.push(Entry {
                element: element.clone(),
                description,
                observed,
            });
            let children = element.attr("AXChildren")?;
            if let Some(children) = children {
                let children = children.array(unsafe { AXUIElementGetTypeID() }, max_nodes + 1)?;
                if depth >= max_depth {
                    truncated |= !children.is_empty();
                    continue;
                }
                let remaining = max_nodes.saturating_sub(entries.len() + stack.len());
                if children.len() > remaining {
                    truncated = true;
                }
                for child in children.into_iter().take(remaining).rev() {
                    stack.push((child, Some(id.clone()), depth + 1));
                }
            }
        }
        let result = serde_json::json!({"platform": "macos", "window": target, "elements": rows, "truncated": truncated,
            "expires_in_ms": SNAPSHOT_TTL.as_millis(), "single_use": true,
            "supported_actions": ["press", "show_menu", "set_value"]});
        Ok((
            NativeSnapshot {
                target,
                root,
                entries,
            },
            result,
        ))
    }

    fn remaining_budget() -> Result<Duration> {
        query_timeout()?;
        Ok(QUERY_CONTEXT.with(|slot| {
            slot.borrow()
                .as_ref()
                .map(|c| c.deadline.saturating_duration_since(Instant::now()))
                .unwrap_or(REQUEST_BUDGET)
        }))
    }
    fn require_focused(root: &Object, target: &WindowTarget) -> Result<()> {
        let app = Object::owned(unsafe { AXUIElementCreateApplication(target.pid as i32) })?;
        if app.bool_attr("AXFrontmost")? != Some(true)
            || !app
                .attr("AXFocusedWindow")?
                .is_some_and(|window| window.equal(root))
        {
            return Err(anyhow!(
                "native_target_not_focused: focus the exact app/window explicitly before input"
            ));
        }
        Ok(())
    }
    fn focus_element(element: &Object) -> Result<()> {
        if element.bool_attr("AXFocused")? == Some(true) {
            return Ok(());
        }
        let name = Object::string("AXFocused")?;
        let mut settable = 0;
        element.prepare_query()?;
        let status = unsafe { AXUIElementIsAttributeSettable(element.0, name.0, &mut settable) };
        if status != 0 || settable == 0 {
            return Err(anyhow!("native_element_not_focusable"));
        }
        element.prepare_query()?;
        let status = unsafe { AXUIElementSetAttributeValue(element.0, name.0, kCFBooleanTrue) };
        if status != 0 {
            return Err(ax_error(status));
        }
        Ok(())
    }
    pub(super) fn act(
        snapshot: NativeSnapshot,
        index: usize,
        mutation: Mutation,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<serde_json::Value> {
        let _queries = QueryGuard::new(cancelled.clone());
        query_timeout()?;
        require_permission()?;
        let current = target(snapshot.target.window_id, snapshot.target.pid)?;
        if current != snapshot.target || !window(&current)?.equal(&snapshot.root) {
            return Err(anyhow!(
                "stale_accessibility_window: window changed since the snapshot"
            ));
        }
        let entry = snapshot.entries.get(index).ok_or_else(|| {
            anyhow!("stale_accessibility_element: element does not belong to this snapshot")
        })?;
        let description = Description::read(&entry.element)?;
        let secure = description.role == "AXSecureTextField"
            || description.subrole.as_deref() == Some("AXSecureTextField");
        let observed = ObservedState::read(&entry.element, secure, &mut (2 * 1024 * 1024))?;
        if !entry.observed.complete {
            return Err(anyhow!("accessibility_state_limit: element state could not be retained within snapshot limits"));
        }
        if description != entry.description || !entry.observed.matches(&observed) {
            return Err(anyhow!(
                "stale_accessibility_element: element state changed; take a new snapshot"
            ));
        }
        if description.enabled == Some(false) {
            return Err(anyhow!("accessibility_element_disabled"));
        }
        // Revalidate ownership and ancestry, not just a row number or label.
        let mut pid = 0;
        entry.element.prepare_query()?;
        let status = unsafe { AXUIElementGetPid(entry.element.0, &mut pid) };
        if status != 0 {
            return Err(ax_error(status));
        }
        if pid as u32 != snapshot.target.pid {
            return Err(anyhow!("stale_accessibility_element: process changed"));
        }
        let mut ancestor = entry.element.clone();
        let mut belongs = false;
        for _ in 0..64 {
            if ancestor.equal(&snapshot.root) {
                belongs = true;
                break;
            }
            let Some(parent) = ancestor.attr("AXParent")? else {
                break;
            };
            if unsafe { CFGetTypeID(parent.0) != AXUIElementGetTypeID() } {
                break;
            }
            ancestor = parent;
        }
        if !belongs {
            return Err(anyhow!(
                "stale_accessibility_element: element left the selected window"
            ));
        }
        if cancelled.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(anyhow!("accessibility_cancelled: mutation was not started"));
        }
        let status = match mutation {
            Mutation::Simple(action, value) => match action {
                ElementAction::SetValue => {
                    if !description.value_settable {
                        return Err(anyhow!(
                        "accessibility_action_unsupported: AXValue is not editable or is secure"
                    ));
                    }
                    if !observed
                        .values
                        .last()
                        .and_then(|value| value.as_ref())
                        .is_some_and(|value| unsafe { CFGetTypeID(value.0) == CFStringGetTypeID() })
                    {
                        return Err(anyhow!(
                            "accessibility_action_unsupported: set_value supports text fields only"
                        ));
                    }
                    let key = Object::string("AXValue")?;
                    let value = Object::string(value.as_deref().unwrap_or_default())?;
                    entry.element.prepare_query()?;
                    unsafe { AXUIElementSetAttributeValue(entry.element.0, key.0, value.0) }
                }
                ElementAction::Press | ElementAction::ShowMenu => {
                    let action_name = if matches!(action, ElementAction::Press) {
                        "AXPress"
                    } else {
                        "AXShowMenu"
                    };
                    if !description.actions.iter().any(|name| name == action_name) {
                        return Err(anyhow!("accessibility_action_unsupported: selected element does not advertise {action_name}"));
                    }
                    let action_name = Object::string(action_name)?;
                    entry.element.prepare_query()?;
                    unsafe { AXUIElementPerformAction(entry.element.0, action_name.0) }
                }
            },
            Mutation::ObservedAction(name) => {
                if !description.actions.contains(&name) {
                    return Err(anyhow!("accessibility_action_unsupported: action was not advertised by this exact observed element"));
                }
                let name = Object::string(&name)?;
                entry.element.prepare_query()?;
                unsafe { AXUIElementPerformAction(entry.element.0, name.0) }
            }
            Mutation::Select(selection) => {
                require_focused(&snapshot.root, &current)?;
                if secure {
                    return Err(anyhow!(
                        "accessibility_action_unsupported: secure field selection is not exposed"
                    ));
                }
                let text = entry
                    .element
                    .attr("AXValue")?
                    .and_then(|v| v.text_limit(65536))
                    .ok_or_else(|| {
                        anyhow!("text_selection_unavailable: text value is not exposed")
                    })?;
                let (start, length) = selection.range(&text)?;
                let attribute = Object::string("AXSelectedTextRange")?;
                let mut settable = 0;
                entry.element.prepare_query()?;
                let status = unsafe {
                    AXUIElementIsAttributeSettable(entry.element.0, attribute.0, &mut settable)
                };
                if status != 0 || settable == 0 {
                    return Err(anyhow!(
                        "text_selection_unsupported: native range is not writable"
                    ));
                }
                focus_element(&entry.element)?;
                let range = Range {
                    location: start as isize,
                    length: length as isize,
                };
                let value =
                    Object::owned(unsafe { AXValueCreate(4, (&range as *const Range).cast()) })?;
                entry.element.prepare_query()?;
                let status =
                    unsafe { AXUIElementSetAttributeValue(entry.element.0, attribute.0, value.0) };
                if status != 0 {
                    return Err(ax_error(status));
                }
                return Ok(
                    serde_json::json!({"ok":true,"window_id":current.window_id,"pid":current.pid,"selected_range_utf16":[start,length],"requires_fresh_snapshot":true,"snapshot_consumed":true}),
                );
            }
            Mutation::Input(input) => {
                input.validate()?;
                for coordinate in input.coordinate.iter().chain(input.to_coordinate.iter()) {
                    if coordinate[0] >= current.width as f64
                        || coordinate[1] >= current.height as f64
                    {
                        return Err(anyhow!("native_coordinate_outside_window"));
                    }
                }
                if !matches!(input.action, crate::advanced::InputAction::Focus) {
                    require_focused(&snapshot.root, &current)?;
                }
                let mut arguments = serde_json::to_value(&input)?;
                arguments["op"] = serde_json::json!("window_input");
                arguments["pid"] = serde_json::json!(current.pid);
                arguments["window_id"] = serde_json::json!(current.window_id);
                arguments["x"] = serde_json::json!(current.x);
                arguments["y"] = serde_json::json!(current.y);
                arguments["height"] = serde_json::json!(current.height);
                let mut result = unsafe {
                    crate::advanced::request_window(
                        arguments,
                        cancelled.clone(),
                        Some(remaining_budget()?),
                        snapshot.root.0,
                        if index == 0 {
                            std::ptr::null()
                        } else {
                            entry.element.0
                        },
                        if index == 0 {
                            std::ptr::null()
                        } else {
                            observed
                                .values
                                .last()
                                .and_then(|v| v.as_ref())
                                .map(|v| v.0)
                                .unwrap_or(std::ptr::null())
                        },
                    )
                }?;
                if matches!(input.action, crate::advanced::InputAction::Focus) {
                    if Description::read(&snapshot.root)?
                        .actions
                        .iter()
                        .any(|name| name == "AXRaise")
                    {
                        let raise = Object::string("AXRaise")?;
                        snapshot.root.prepare_query()?;
                        let status = unsafe { AXUIElementPerformAction(snapshot.root.0, raise.0) };
                        if status != 0 {
                            return Err(ax_error(status));
                        }
                    }
                    loop {
                        query_timeout()?;
                        match require_focused(&snapshot.root, &current) {
                            Ok(()) => break,
                            Err(error) if error.to_string().starts_with("native_target_not_focused:") => {},
                            Err(error) => return Err(error),
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    if index != 0 {
                        focus_element(&entry.element)?;
                    }
                }
                result["window_id"] = serde_json::json!(current.window_id);
                result["snapshot_consumed"] = serde_json::json!(true);
                return Ok(result);
            }
            Mutation::Paste(items) => {
                crate::advanced::validate_clipboard(&items)?;
                require_focused(&snapshot.root, &current)?;
                focus_element(&entry.element)?;
                let mut result = unsafe {
                    crate::advanced::request_window(
                        serde_json::json!({"op":"paste","pid":current.pid,"items":items}),
                        cancelled.clone(),
                        Some(remaining_budget()?),
                        snapshot.root.0,
                        if index == 0 {
                            std::ptr::null()
                        } else {
                            entry.element.0
                        },
                        if index == 0 {
                            std::ptr::null()
                        } else {
                            observed
                                .values
                                .last()
                                .and_then(|v| v.as_ref())
                                .map(|v| v.0)
                                .unwrap_or(std::ptr::null())
                        },
                    )
                }?;
                result["window_id"] = serde_json::json!(current.window_id);
                result["pid"] = serde_json::json!(current.pid);
                result["snapshot_consumed"] = serde_json::json!(true);
                return Ok(result);
            }
        };
        if status != 0 {
            return Err(ax_error(status));
        }
        Ok(
            serde_json::json!({"ok": true, "window_id": current.window_id, "pid": current.pid, "snapshot_consumed": true, "requires_fresh_snapshot": true}),
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        #[ignore] // Requires the compiled owned AppKit fixture and current AX grants.
        fn native_child_query_timeout_real_fixture() {
            struct OwnedFixture {
                child: std::process::Child,
                directory: std::path::PathBuf,
            }
            impl Drop for OwnedFixture {
                fn drop(&mut self) {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    let _ = std::fs::remove_dir_all(&self.directory);
                }
            }
            require_permission().unwrap();
            let token = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory =
                std::env::temp_dir().join(format!("openagent-owned-ax-timeout-{token}"));
            std::fs::create_dir(&directory).unwrap();
            let state = directory.join("state.json");
            let control = directory.join("control.txt");
            let title = format!("OpenAgent AX Timeout Fixture {token}");
            let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/native-accessibility-fixture");
            let child = std::process::Command::new(fixture)
                .arg(&title)
                .arg(&state)
                .arg(&control)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let fixture = OwnedFixture { child, directory };
            let start = Instant::now();
            while !state.is_file() && start.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(25));
            }
            assert!(state.is_file(), "owned fixture did not start");
            let mut current = None;
            let start = Instant::now();
            while current.is_none() && start.elapsed() < Duration::from_secs(5) {
                current = xcap::Window::all().unwrap().into_iter().find(|window| {
                    window.pid().ok() == Some(fixture.child.id())
                        && window.title().ok().as_deref() == Some(&title)
                });
                if current.is_none() {
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
            let current = current.expect("owned fixture window was not visible in OS inventory");
            let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let _queries = QueryGuard::new(cancel);
            let target = target(current.id().unwrap(), fixture.child.id()).unwrap();
            let root = window(&target).unwrap();
            let mut stack = vec![root];
            let mut button = None;
            while let Some(element) = stack.pop() {
                if element.text_attr("AXIdentifier").unwrap().as_deref() == Some("oa-fixture-apply")
                {
                    button = Some(element);
                    break;
                }
                if let Some(children) = element.attr("AXChildren").unwrap() {
                    stack.extend(
                        children
                            .array(unsafe { AXUIElementGetTypeID() }, 30)
                            .unwrap(),
                    );
                }
            }
            let button = button.expect("owned fixture button");
            std::fs::write(&control, "block").unwrap();
            let start = Instant::now();
            while !control.with_extension("txt.blocked").exists()
                && start.elapsed() < Duration::from_secs(2)
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(
                control.with_extension("txt.blocked").exists(),
                "fixture did not enter controlled busy state"
            );
            let start = Instant::now();
            let error = button.text_attr("AXTitle").unwrap_err();
            assert!(
                format!("{error:#}").contains("accessibility_timeout"),
                "{error:#}"
            );
            assert!(
                start.elapsed() < Duration::from_millis(900),
                "child AX query ignored its local timeout: {:?}",
                start.elapsed()
            );
            let receipt = serde_json::json!({"fixture_only": true, "passed": true, "child_query_elapsed_ms": start.elapsed().as_millis(), "per_object_timeout_ms": 250, "aggregate_request_budget_ms": 3000});
            std::fs::write(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("target/native-accessibility-timeout-evidence.json"),
                serde_json::to_vec_pretty(&receipt).unwrap(),
            )
            .unwrap();
            println!("{receipt}");
        }

        #[test]
        fn aggregate_query_budget_and_cancellation_apply_before_each_operation() {
            let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let _guard = QueryGuard::new(cancelled.clone());
            assert!(query_timeout().unwrap() <= MESSAGE_TIMEOUT_SECONDS);
            QUERY_CONTEXT.with(|slot| {
                slot.borrow_mut().as_mut().unwrap().deadline =
                    Instant::now() - Duration::from_millis(1)
            });
            assert!(query_timeout()
                .unwrap_err()
                .to_string()
                .contains("aggregate"));
            QUERY_CONTEXT.with(|slot| {
                slot.borrow_mut().as_mut().unwrap().deadline = Instant::now() + REQUEST_BUDGET
            });
            cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
            assert!(query_timeout()
                .unwrap_err()
                .to_string()
                .contains("cancelled"));
        }
        #[test]
        fn ax_window_binding_requires_matching_title_and_bounds() {
            let window = WindowTarget {
                window_id: 1,
                pid: 2,
                title: "Document A".into(),
                x: 20,
                y: 30,
                width: 400,
                height: 300,
                process_started: [1, 2],
            };
            assert!(window_matches(
                &window,
                [20., 30., 400., 300.],
                "Document A"
            ));
            assert!(!window_matches(
                &window,
                [20., 30., 400., 300.],
                "Document B"
            ));
            assert!(!window_matches(
                &window,
                [80., 30., 400., 300.],
                "Document A"
            ));
            assert!(!window_matches(
                &window,
                [f64::NAN, 30., 400., 300.],
                "Document A"
            ));
        }
        #[test]
        fn process_generation_is_verified_from_public_kernel_info() {
            assert_eq!(std::mem::size_of::<ProcessInfo>(), 136);
            let current = process_started(std::process::id()).unwrap();
            assert!(current[0] > 0);
            assert_eq!(current, process_started(std::process::id()).unwrap());
            assert!(process_started(u32::MAX).is_err());
        }
        #[test]
        fn native_scalar_comparison_does_not_use_the_truncated_display_value() {
            let before = Object::string(&("a".repeat(600) + "before")).unwrap();
            let after = Object::string(&("a".repeat(600) + "after")).unwrap();
            assert_eq!(before.text(), after.text());
            let left = ObservedState {
                values: vec![Some(before)],
                complete: true,
            };
            let right = ObservedState {
                values: vec![Some(after)],
                complete: true,
            };
            assert!(!left.matches(&right));
        }
        #[test]
        fn cf_unicode_text_roundtrip_and_type_validation() {
            let text = Object::string("Ciao, è già così 🌞").unwrap();
            assert_eq!(text.text().as_deref(), Some("Ciao, è già così 🌞"));
            assert_eq!(
                Object::string("a\0b").unwrap().text().as_deref(),
                Some("a\0b")
            );
            assert!(text.array(unsafe { AXUIElementGetTypeID() }, 1).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshots_expire_and_are_single_use() {
        let now = Instant::now();
        let mut store = SnapshotStore::default();
        let id = store.insert((1, 2), "first", now);
        assert_eq!(store.take(&id, now).unwrap(), "first");
        assert!(store.take(&id, now).is_err());
        let id = store.insert((1, 2), "second", now);
        assert!(store.take(&id, now + SNAPSHOT_TTL).is_err());
    }
    #[test]
    fn new_window_observation_invalidates_only_its_old_snapshot() {
        let now = Instant::now();
        let mut store = SnapshotStore::default();
        let first = store.insert((1, 2), 1, now);
        let other = store.insert((3, 4), 2, now);
        let fresh = store.insert((1, 2), 3, now);
        assert!(store.take(&first, now).is_err());
        assert_eq!(store.take(&other, now).unwrap(), 2);
        assert_eq!(store.take(&fresh, now).unwrap(), 3);
    }
    #[test]
    fn snapshot_capacity_evicts_oldest_and_cross_process_ids_differ() {
        let now = Instant::now();
        let mut store = SnapshotStore::default();
        let first = store.insert((0, 1), 0, now);
        for n in 1..=MAX_SNAPSHOTS {
            store.insert((n as u32, 1), n, now);
        }
        assert!(store.take(&first, now).is_err());
        assert_eq!(store.entries.len(), MAX_SNAPSHOTS);
        let mut other = SnapshotStore::default();
        assert_ne!(store.insert((1, 1), 1, now), other.insert((1, 1), 1, now));
    }
    #[test]
    fn invalid_element_ids_and_action_values_are_rejected() {
        let args = |id: &str, action, value| ActionArgs {
            snapshot_id: "snapshot".into(),
            element_id: id.into(),
            action,
            value,
        };
        assert_eq!(
            args("element-0", ElementAction::Press, None)
                .index()
                .unwrap(),
            0
        );
        for id in [
            "element-01",
            "element--1",
            "element-1000",
            "0",
            "element-18446744073709551616000000",
        ] {
            assert!(args(id, ElementAction::Press, None).index().is_err());
        }
        assert!(args("element-1", ElementAction::SetValue, None)
            .index()
            .is_err());
        assert!(args(
            "element-1",
            ElementAction::SetValue,
            Some("x".repeat(16385))
        )
        .index()
        .is_err());
        assert!(args("element-1", ElementAction::Press, Some("text".into()))
            .index()
            .is_err());
    }
    #[test]
    fn tree_limits_are_bounded() {
        let args = |depth, nodes| SnapshotArgs {
            window_id: 1,
            pid: 2,
            max_depth: depth,
            max_nodes: nodes,
        };
        assert_eq!(args(None, None).limits().unwrap(), (12, 300));
        assert!(args(Some(0), None).limits().is_err());
        assert!(args(Some(31), None).limits().is_err());
        assert!(args(None, Some(0)).limits().is_err());
        assert!(args(None, Some(1001)).limits().is_err());
    }
}
