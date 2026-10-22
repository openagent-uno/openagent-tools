//! Input actions (keyboard + mouse) backed by enigo.
//! enigo uses: CGEvent (macOS), XTest or Wayland portal (Linux), SendInput (Windows).

use anyhow::{anyhow, Context, Result};
use enigo::{Axis, Button, Coordinate, Direction, Enigo, Keyboard, Mouse, Settings};

#[cfg(target_os = "macos")]
pub const MAC_ACCESSIBILITY_HINT: &str =
    "macOS Accessibility permission required. A system prompt was requested — open System Settings → Privacy & Security → Accessibility, enable 'openagent-computer-control' (or add it via '+' at /usr/local/bin/openagent-computer-control or ~/.local/bin/openagent-computer-control), then retry.";

#[cfg(target_os = "macos")]
fn is_accessibility_error(e: &anyhow::Error) -> bool {
    let s = format!("{e:#}").to_lowercase();
    s.contains("accessibility")
        || s.contains("not trusted")
        || s.contains("axiserror")
        || s.contains("permission")
}

/// Ask macOS TCC for Accessibility permission, triggering the system
/// prompt if the permission hasn't been recorded yet.
///
/// enigo's ``Enigo::new()`` on macOS calls the **non-prompting**
/// ``AXIsProcessTrusted()`` API, so when the permission is missing it
/// silently returns ``NoPermission`` and no prompt ever fires — the
/// binary never lands in System Settings → Privacy & Security →
/// Accessibility, and the user has no way to grant it through the UI.
///
/// This helper calls ``AXIsProcessTrustedWithOptions`` with
/// ``kAXTrustedCheckOptionPrompt = true``, which:
///   - returns the current trust state (same as the non-prompting form), AND
///   - asynchronously shows the "openagent-computer-control wants to
///     control your computer" dialog the first time it's invoked by a
///     given code signature, AND
///   - registers the binary in the Accessibility list so the toggle
///     appears even if the user dismisses the prompt without clicking
///     "Open System Settings".
///
/// The registered TCC identity is whatever the binary is signed as —
/// ``com.openagent.computer-control`` with Team B4KWCQFY8V, per the
/// CI signing step. That identity is stable across releases (enforced
/// by ``codesign --identifier``), so a grant granted once persists.
#[cfg(target_os = "macos")]
fn request_accessibility() -> bool {
    macos_accessibility_client::accessibility::application_is_trusted_with_prompt()
}

#[cfg(not(target_os = "macos"))]
fn request_accessibility() -> bool {
    true
}

use crate::keys;

pub struct InputController {
    enigo: Enigo,
    // Enigo 0.5 caches the extra X11 keycodes it creates. Layout reloads can
    // remove those bindings while this MCP process remains alive. Keep text
    // transactions independent of that stale cache, without clipboard access.
    #[cfg(target_os = "linux")]
    text_connection: Option<Enigo>,
}

fn input_settings() -> Settings {
    #[allow(unused_mut)]
    let mut settings = Settings::default();
    #[cfg(target_os = "linux")]
    {
        settings.x11_display = nonempty_env("DISPLAY");
        settings.wayland_display = nonempty_env("WAYLAND_DISPLAY");
    }
    settings
}

#[cfg(any(target_os = "linux", test))]
fn fresh_text_connection<T, E>(
    current: &mut Option<T>,
    connect: impl FnOnce() -> std::result::Result<T, E>,
) -> std::result::Result<&mut T, E> {
    // Drop BEFORE taking the new keymap snapshot: the previous Enigo's Drop
    // releases its temporary mappings. Reversing this order invalidates the
    // replacement's freshly captured map. A connection error leaves no stale
    // instance that could report successful typing while dropping characters.
    *current = None;
    *current = Some(connect()?);
    Ok(current.as_mut().expect("connection just initialized"))
}

impl InputController {
    pub fn new() -> Result<Self> {
        // Trigger the TCC prompt FIRST on macOS. If permission is
        // missing, this both surfaces a user-visible dialog and
        // registers the binary in System Settings; the caller then
        // sees a clean MAC_ACCESSIBILITY_HINT error without enigo
        // ever being touched.
        #[cfg(target_os = "macos")]
        {
            if !request_accessibility() {
                return Err(anyhow!(MAC_ACCESSIBILITY_HINT));
            }
        }

        let settings = input_settings();
        let enigo = match Enigo::new(&settings) {
            Ok(e) => e,
            Err(e) => {
                #[cfg(target_os = "macos")]
                if matches!(e, enigo::NewConError::NoPermission) {
                    return Err(anyhow!(MAC_ACCESSIBILITY_HINT));
                }
                // Fallback: string heuristic for any other permission-related error message
                let err: anyhow::Error = e.into();
                #[cfg(target_os = "macos")]
                if is_accessibility_error(&err) {
                    return Err(anyhow!(MAC_ACCESSIBILITY_HINT));
                }
                return Err(err.context("enigo init failed"));
            }
        };
        Ok(Self {
            enigo,
            #[cfg(target_os = "linux")]
            text_connection: None,
        })
    }

    pub fn type_text(&mut self, text: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let connection = fresh_text_connection(&mut self.text_connection, || {
                Enigo::new(&input_settings()).context("text input connection failed")
            })?;
            connection.text(text).context("enigo.text")?;
        }
        #[cfg(not(target_os = "linux"))]
        self.enigo.text(text).context("enigo.text")?;
        Ok(())
    }

    pub fn key_chord(&mut self, spec: &str) -> Result<()> {
        let keys = keys::parse(spec).map_err(|e| anyhow!(e))?;
        if keys.is_empty() {
            return Err(anyhow!("empty key spec"));
        }
        // Press in order, release in reverse order.
        for k in &keys {
            self.enigo.key(*k, Direction::Press).context("key press")?;
        }
        for k in keys.iter().rev() {
            self.enigo
                .key(*k, Direction::Release)
                .context("key release")?;
        }
        Ok(())
    }

    pub fn mouse_move(&mut self, x: i32, y: i32) -> Result<()> {
        self.enigo
            .move_mouse(x, y, Coordinate::Abs)
            .context("move_mouse")?;
        Ok(())
    }

    pub fn cursor_position(&self) -> Result<(i32, i32)> {
        self.enigo.location().context("enigo.location")
    }

    pub fn left_click(&mut self, at: Option<(i32, i32)>) -> Result<()> {
        if let Some((x, y)) = at {
            self.mouse_move(x, y)?;
        }
        self.enigo
            .button(Button::Left, Direction::Click)
            .context("left click")?;
        Ok(())
    }

    pub fn right_click(&mut self, at: Option<(i32, i32)>) -> Result<()> {
        if let Some((x, y)) = at {
            self.mouse_move(x, y)?;
        }
        self.enigo
            .button(Button::Right, Direction::Click)
            .context("right click")?;
        Ok(())
    }

    pub fn middle_click(&mut self, at: Option<(i32, i32)>) -> Result<()> {
        if let Some((x, y)) = at {
            self.mouse_move(x, y)?;
        }
        self.enigo
            .button(Button::Middle, Direction::Click)
            .context("middle click")?;
        Ok(())
    }

    pub fn double_click(&mut self, at: Option<(i32, i32)>) -> Result<()> {
        if let Some((x, y)) = at {
            self.mouse_move(x, y)?;
        }
        self.enigo.button(Button::Left, Direction::Click)?;
        self.enigo.button(Button::Left, Direction::Click)?;
        Ok(())
    }

    pub fn left_click_drag(&mut self, to: (i32, i32)) -> Result<()> {
        self.enigo
            .button(Button::Left, Direction::Press)
            .context("drag press")?;
        self.mouse_move(to.0, to.1)?;
        self.enigo
            .button(Button::Left, Direction::Release)
            .context("drag release")?;
        Ok(())
    }

    /// Scroll with direction ("up"|"down"|"left"|"right") and optional amount (pixels).
    /// Default amount: 300 (matches TS behavior).
    pub fn scroll(&mut self, at: (i32, i32), direction: &str, amount: Option<u32>) -> Result<()> {
        self.mouse_move(at.0, at.1)?;
        let amt = amount.unwrap_or(300) as i32;
        match direction.to_ascii_lowercase().as_str() {
            "up" => self.enigo.scroll(-amt, Axis::Vertical)?,
            "down" => self.enigo.scroll(amt, Axis::Vertical)?,
            "left" => self.enigo.scroll(-amt, Axis::Horizontal)?,
            "right" => self.enigo.scroll(amt, Axis::Horizontal)?,
            other => return Err(anyhow!("invalid scroll direction: {other}")),
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Parse the scroll `text` argument from the MCP call, e.g. "down" or "down:500".
pub fn parse_scroll_text(text: &str) -> Result<(&str, Option<u32>)> {
    let mut parts = text.splitn(2, ':');
    let dir = parts
        .next()
        .ok_or_else(|| anyhow!("scroll direction required"))?;
    if dir.is_empty() {
        return Err(anyhow!("scroll direction required"));
    }
    let amount = match parts.next() {
        None => None,
        Some(s) => {
            let n: u32 = s
                .parse()
                .map_err(|_| anyhow!("invalid scroll amount: {s}"))?;
            if n == 0 {
                return Err(anyhow!("invalid scroll amount: {s}"));
            }
            Some(n)
        }
    };
    Ok((dir, amount))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_connection_drops_owned_mapping_before_refreshing_the_snapshot() {
        use std::{cell::RefCell, rc::Rc};
        struct OwnedMapping(Rc<RefCell<Vec<&'static str>>>);
        impl Drop for OwnedMapping {
            fn drop(&mut self) {
                self.0.borrow_mut().push("drop old mapping");
            }
        }
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut current = Some(OwnedMapping(events.clone()));
        let result: Result<_, ()> = fresh_text_connection(&mut current, || {
            events.borrow_mut().push("capture fresh map");
            Ok(OwnedMapping(events.clone()))
        });
        assert!(result.is_ok());
        assert_eq!(*events.borrow(), ["drop old mapping", "capture fresh map"]);
    }

    #[test]
    fn failed_text_refresh_cannot_reuse_the_stale_connection() {
        let mut current = Some("stale map");
        assert!(fresh_text_connection(&mut current, || Err::<&str, _>("disconnected")).is_err());
        assert!(current.is_none());
        assert_eq!(
            *fresh_text_connection(&mut current, || Ok::<_, &str>("fresh map")).unwrap(),
            "fresh map"
        );
    }

    #[test]
    fn scroll_text_parses_direction_only() {
        assert_eq!(parse_scroll_text("down").unwrap(), ("down", None));
        assert_eq!(parse_scroll_text("up").unwrap(), ("up", None));
    }

    #[test]
    fn scroll_text_parses_direction_and_amount() {
        assert_eq!(parse_scroll_text("down:500").unwrap(), ("down", Some(500)));
        assert_eq!(parse_scroll_text("left:1").unwrap(), ("left", Some(1)));
    }

    #[test]
    fn scroll_text_rejects_bad_amount() {
        assert!(parse_scroll_text("down:abc").is_err());
        assert!(parse_scroll_text("down:0").is_err());
        assert!(parse_scroll_text("down:-5").is_err());
    }

    #[test]
    fn scroll_text_rejects_empty_direction() {
        assert!(parse_scroll_text("").is_err());
        assert!(parse_scroll_text(":500").is_err());
    }
}
