pub mod clash_yaml;
pub mod shadowrocket_conf;
pub mod share_link;
pub mod singbox_json;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use maxq_core_model::{ImportFormat, RawImportBundle};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("empty input")]
    EmptyInput,
    #[error("unsupported protocol or share link: {0}")]
    UnsupportedScheme(String),
    #[error("malformed share link ({scheme}): {reason}")]
    MalformedLink { scheme: String, reason: String },
    #[error("invalid JSON profile: {0}")]
    InvalidJson(String),
    #[error("invalid YAML profile: {0}")]
    InvalidYaml(String),
    #[error("could not recognize import format")]
    UnrecognizedFormat,
}

/// Auto-detects and parses share links, Base64 subscriptions, Shadowrocket `.conf`,
/// Clash YAML, or `sing-box` JSON into a canonical `RawImportBundle`.
///
/// IMPORTANT: Always pass the returned `RawImportBundle` through `maxq_sanitizer::sanitize_import`
/// before persisting or compiling.
pub fn parse_input(raw: &str) -> Result<RawImportBundle, ParseError> {
    let trimmed = raw.trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return Err(ParseError::EmptyInput);
    }

    // 1. sing-box JSON
    if trimmed.starts_with('{') {
        return singbox_json::parse_singbox_json(trimmed);
    }

    // 2. Shadowrocket / Surge INI `.conf`
    if is_shadowrocket_conf(trimmed) {
        return shadowrocket_conf::parse_shadowrocket_conf(trimmed);
    }

    // 3. Direct share links (one or multiple lines)
    if contains_share_link_line(trimmed) {
        return parse_share_link_lines(trimmed, ImportFormat::ShareLinks);
    }

    // 4. Clash YAML (contains `proxies:` top-level key)
    if trimmed
        .lines()
        .any(|l| l.trim_start().starts_with("proxies:"))
    {
        return clash_yaml::parse_clash_yaml(trimmed);
    }

    // 5. Base64-encoded subscription bundle of share links
    if let Some(decoded) = try_decode_base64_utf8(trimmed) {
        if contains_share_link_line(&decoded) {
            return parse_share_link_lines(&decoded, ImportFormat::Base64ShareLinks);
        }
    }

    Err(ParseError::UnrecognizedFormat)
}

pub(crate) fn extract_conf_section_header(line: &str) -> Option<String> {
    let t = line.trim();
    if !t.starts_with('[') {
        return None;
    }
    let close = t.find(']')?;
    let after = t[close + 1..].trim();
    // Allow trailing inline comments after ']' (`[MITM] # comment`, `[Script] ; note`, `[MITM] // x`)
    if !after.is_empty()
        && !after.starts_with('#')
        && !after.starts_with(';')
        && !after.starts_with("//")
    {
        return None;
    }
    Some(t[1..close].trim().to_string())
}

pub(crate) fn normalize_section_key(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn is_shadowrocket_conf(input: &str) -> bool {
    let mut non_comment_checked = 0usize;
    for line in input.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with(';') || t.starts_with("//") {
            continue;
        }
        non_comment_checked += 1;
        if let Some(sec) = extract_conf_section_header(t) {
            let norm = normalize_section_key(&sec);
            if matches!(
                norm.as_str(),
                "general"
                    | "proxy"
                    | "proxygroup"
                    | "rule"
                    | "host"
                    | "urlrewrite"
                    | "headerrewrite"
                    | "bodyrewrite"
                    | "maplocal"
                    | "mitm"
                    | "script"
            ) {
                return true;
            }
        }
        if non_comment_checked >= 50 {
            break;
        }
    }
    false
}

fn contains_share_link_line(input: &str) -> bool {
    input.lines().any(|line| {
        let l = line.trim();
        share_link::is_supported_share_link(l)
    })
}

fn parse_share_link_lines(
    input: &str,
    format: ImportFormat,
) -> Result<RawImportBundle, ParseError> {
    let mut bundle = RawImportBundle {
        format_detected: format,
        ..Default::default()
    };

    for (idx, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        match share_link::parse_share_link(trimmed) {
            Ok(node) => bundle.nodes.push(node),
            Err(err) => {
                bundle
                    .parse_warnings
                    .push(format!("line {}: {}", idx + 1, err));
            }
        }
    }

    if bundle.nodes.is_empty() {
        return Err(ParseError::UnrecognizedFormat);
    }
    Ok(bundle)
}

/// Decodes standard or URL-safe Base64 with or without padding, stripping embedded whitespace.
pub(crate) fn decode_base64_lenient(input: &str) -> Option<Vec<u8>> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return None;
    }
    STANDARD
        .decode(&compact)
        .or_else(|_| STANDARD_NO_PAD.decode(&compact))
        .or_else(|_| URL_SAFE.decode(&compact))
        .or_else(|_| URL_SAFE_NO_PAD.decode(&compact))
        .ok()
}

pub(crate) fn try_decode_base64_utf8(input: &str) -> Option<String> {
    let bytes = decode_base64_lenient(input)?;
    String::from_utf8(bytes).ok()
}

pub(crate) fn percent_decode_str(input: &str) -> String {
    percent_encoding::percent_decode_str(input)
        .decode_utf8_lossy()
        .into_owned()
}

/// Normalizes a SHA-256 hex certificate pin (`pcs`, `pinSHA256`):
/// strips colons/whitespace, lowercases, and validates 64 hex digits (32 bytes).
pub(crate) fn normalize_hex_sha256_pin(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if cleaned.len() == 64 && cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(cleaned)
    } else {
        None
    }
}

/// Normalizes Hysteria2 `mport` / `ports` strings (e.g. `20000-30000,40000-50000`)
/// into `sing-box` canonical `start:end` ranges (`["20000:30000", "40000:50000"]`).
pub(crate) fn normalize_port_ranges(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .map(|part| {
            if let Some((start, end)) = part.split_once('-') {
                format!("{}:{}", start.trim(), end.trim())
            } else if part.contains(':') {
                part.to_string()
            } else {
                format!("{part}:{part}")
            }
        })
        .collect()
}
