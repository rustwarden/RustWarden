//! Talks to Home Assistant's REST API with `curl.exe`, like the other web lookups.
//! The device registry itself is WebSocket-only, so a template asks Home Assistant to find the
//! one device whose MAC connection matches, and nothing about other devices leaves it.

use super::HaInfo;

use crate::util::json_escape as esc;

/// The Jinja template for one MAC; it renders "name<TAB>area<TAB>model<TAB>entity,entity" or nothing.
fn template(mac: &str) -> String {
    let mac: String = mac.to_lowercase().chars().filter(|c| c.is_ascii_hexdigit() || *c == ':').collect();
    format!(
        "{{%- set ns = namespace(r='') -%}}\
         {{%- for d in states | map(attribute='entity_id') | map('device_id') | select('string') | unique -%}}\
         {{%- if not ns.r -%}}{{%- for c in device_attr(d, 'connections') -%}}\
         {{%- if c[0] == 'mac' and c[1] | lower == '{mac}' -%}}\
         {{%- set ns.r = [device_attr(d, 'name_by_user') or device_attr(d, 'name') or '', area_name(d) or '', device_attr(d, 'model') or '', device_entities(d) | join(','), d] | join('\\t') -%}}\
         {{%- endif -%}}{{%- endfor -%}}{{%- endif -%}}{{%- endfor -%}}{{{{ ns.r }}}}"
    )
}

/// Runs curl; the token goes in on stdin so it never shows in the process list.
fn curl(url: &str, token: &str, body: Option<&str>) -> Result<String, String> {
    let out = crate::sys::curl::run(&crate::sys::curl::api_config(url, &format!("Authorization: Bearer {token}"), body), None)?;
    if !out.status.success() {
        return Err(format!("Can't reach Home Assistant: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", &text));
    match code.trim() {
        "200" => Ok(body.to_owned()),
        "401" | "403" => Err("Home Assistant rejected the access token.".into()),
        c => Err(format!("Home Assistant answered HTTP {c}.")),
    }
}

pub fn test(url: &str, token: &str) -> Result<(), String> {
    curl(&format!("{}/api/", url.trim_end_matches('/')), token, None).map(|_| ())
}

/// `Ok(None)`: Home Assistant answered and has no such device.
pub fn lookup(url: &str, token: &str, mac: &str) -> Result<Option<HaInfo>, String> {
    let body = format!("{{\"template\":\"{}\"}}", esc(&template(mac)));
    curl(&format!("{}/api/template", url.trim_end_matches('/')), token, Some(&body)).map(|t| parse(&t))
}

fn parse(text: &str) -> Option<HaInfo> {
    let mut f = text.trim_matches(['\r', '\n', ' ']).splitn(5, '\t'); // not trim(): an empty name leaves leading tabs
    let (name, area, model, entities) = (f.next()?.trim(), f.next()?.trim(), f.next()?.trim(), f.next()?);
    let device_id = f.next().unwrap_or("").trim();
    let has = |domain: &str| entities.split(',').any(|e| e.split('.').next() == Some(domain));
    let kind = ["camera", "lock", "light", "media_player", "switch", "sensor", "binary_sensor"].into_iter().find(|d| has(d)).map_or("other", |d| match d {
        "media_player" => "media",
        "binary_sensor" => "sensor",
        d => d,
    });
    let name = if name.is_empty() { model } else { name };
    (!name.is_empty()).then(|| HaInfo { name: name.into(), area: area.into(), model: model.into(), kind: kind.into(), device_id: device_id.into() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_match_and_picks_the_type() {
        let i = parse("Sonos Arc\tLiving Room\tArc\tmedia_player.arc,sensor.arc_battery\n").unwrap();
        assert_eq!((i.name.as_str(), i.area.as_str(), i.kind.as_str()), ("Sonos Arc", "Living Room", "media"));
        assert_eq!(parse("Plug\t\tP110\tswitch.plug,sensor.plug_power\tabc123").unwrap().device_id, "abc123");
        assert_eq!(parse("Plug\t\tP110\tswitch.plug,sensor.plug_power").unwrap().kind, "switch");
        assert_eq!(parse("Temp\tBackyard\t\tbinary_sensor.x").unwrap().kind, "sensor");
        assert_eq!(parse("\t\tModelX\t").unwrap().name, "ModelX");
    }

    #[test]
    fn no_match_is_none() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("  \n"), None);
    }

    #[test]
    fn template_embeds_only_a_clean_lowercase_mac() {
        let t = template("AA:BB:cc:01:02:03' }}");
        assert!(t.contains("== 'aa:bb:cc:01:02:03'"));
        assert!(esc(&t).contains("\\\\t")); // the tab escape survives JSON
    }
}
