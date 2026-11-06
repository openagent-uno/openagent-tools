//! Engine-free desktop protocol over bounded NDJSON. The caller owns grants.
use crate::{capture, input::InputController};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};
const MAX_REQUEST: usize = 1024 * 1024;
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing {key}"))
}
fn point(v: &Value, width: u32, height: u32, ox: i32, oy: i32) -> Result<(i32, i32)> {
    let x = v
        .get("x")
        .and_then(Value::as_f64)
        .ok_or_else(|| anyhow!("missing x"))?;
    let y = v
        .get("y")
        .and_then(Value::as_f64)
        .ok_or_else(|| anyhow!("missing y"))?;
    if !x.is_finite() || !y.is_finite() || !(0.0..=1.0).contains(&x) || !(0.0..=1.0).contains(&y) {
        bail!("coordinates outside monitor");
    }
    Ok((
        ox + (x * width.saturating_sub(1) as f64).round() as i32,
        oy + (y * height.saturating_sub(1) as f64).round() as i32,
    ))
}
fn execute(v: &Value, controller: &mut Option<InputController>) -> Result<Value> {
    let action = text(v, "action")?;
    if action == "hello" {
        return Ok(json!({"protocol":"openagent-desktop/1"}));
    }
    let monitors = xcap::Monitor::all()?;
    if action == "monitors" {
        let mut result = Vec::new();
        for m in monitors {
            result.push(json!({"id":m.id()?.to_string(),"name":m.name()?,"width":m.width()?,"height":m.height()?,"x":m.x()?,"y":m.y()?,"primary":m.is_primary()?}));
        }
        return Ok(json!({"monitors":result}));
    }
    let monitor_id = text(v, "monitorId")?;
    let monitor = monitors
        .into_iter()
        .find(|m| m.id().ok().map(|id| id.to_string()).as_deref() == Some(monitor_id))
        .ok_or_else(|| anyhow!("monitor unavailable"))?;
    if action == "screenshot" {
        let frame = capture::capture_display_region(monitor, None)?;
        return Ok(
            json!({"mimeType":"image/png","data":STANDARD.encode(frame.png_bytes),"width":frame.reported_width,"height":frame.reported_height,"monitorId":monitor_id}),
        );
    }
    let location = || {
        point(
            v,
            monitor.width()?,
            monitor.height()?,
            monitor.x()?,
            monitor.y()?,
        )
    };
    if controller.is_none() {
        *controller = Some(InputController::new()?);
    }
    let c = controller.as_mut().unwrap();
    match action {
        "move" => {
            let (x, y) = location()?;
            c.mouse_move(x, y)?;
        }
        "click" => {
            let at = Some(location()?);
            match v.get("button").and_then(Value::as_str).unwrap_or("left") {
                "left" => c.left_click(at)?,
                "right" => c.right_click(at)?,
                "middle" => c.middle_click(at)?,
                _ => bail!("invalid button"),
            }
        }
        "double_click" => c.double_click(Some(location()?))?,
        "drag" => c.left_click_drag(location()?)?,
        "scroll" => {
            let amount = v.get("amount").and_then(Value::as_u64).unwrap_or(3);
            if amount > 100 {
                bail!("invalid scroll amount");
            }
            c.scroll(location()?, text(v, "direction")?, Some(amount as u32))?;
        }
        "key" => {
            let key = text(v, "key")?;
            if key.len() > 128 {
                bail!("key too long");
            }
            c.key_chord(key)?;
        }
        "type" => {
            let value = text(v, "text")?;
            if value.len() > 65536 {
                bail!("text too long");
            }
            c.type_text(value)?;
        }
        _ => bail!("unknown action"),
    }
    Ok(json!({"ok":true}))
}
pub fn serve() -> Result<()> {
    let mut reader = io::stdin().lock();
    let mut writer = io::stdout().lock();
    let mut controller = None;
    loop {
        let mut line = String::new();
        if reader
            .by_ref()
            .take((MAX_REQUEST + 1) as u64)
            .read_line(&mut line)?
            == 0
        {
            break;
        }
        if line.len() > MAX_REQUEST {
            bail!("desktop request exceeds limit");
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(value) if value.is_object() => match execute(&value, &mut controller) {
                Ok(result) => json!({"id":value.get("id"),"ok":true,"result":result}),
                Err(error) => json!({"id":value.get("id"),"ok":false,"error":error.to_string()}),
            },
            _ => json!({"ok":false,"error":"invalid request"}),
        };
        writeln!(writer, "{response}").context("desktop response")?;
        writer.flush()?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalized_coordinates_are_display_relative_and_bounded() {
        assert_eq!(
            point(&json!({"x":1,"y":0}), 800, 600, -800, 100).unwrap(),
            (-1, 100)
        );
        assert!(point(&json!({"x":-0.1,"y":0}), 800, 600, 0, 0).is_err());
    }
}
