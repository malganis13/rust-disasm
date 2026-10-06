//! Hex-Rays–style pseudocode view: syntax highlighting, clickable names
//! (double-click = jump), word under the pointer for context menus.

use std::collections::HashMap;

use egui::{text::LayoutJob, Color32, FontId, TextFormat};

const KEYWORDS: &[&str] = &[
    "if", "else", "while", "do", "for", "return", "break", "continue", "switch", "case", "default", "goto",
];
const TYPES: &[&str] = &[
    "void",
    "char",
    "int",
    "unsigned",
    "signed",
    "__int8",
    "__int16",
    "__int32",
    "__int64",
    "_BYTE",
    "_WORD",
    "_DWORD",
    "_QWORD",
    "__fastcall",
    "__cdecl",
    "__stdcall",
    "const",
];

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$' || c == '@' || c == '?'
}

/// Build a highlighted layout. `funcs` are names that navigate.
pub fn highlight(text: &str, funcs: &HashMap<String, u64>, wrap: f32) -> LayoutJob {
    let font = FontId::monospace(13.0);
    let fmt = |c: Color32| TextFormat {
        font_id: font.clone(),
        color: c,
        ..Default::default()
    };
    let mut job = LayoutJob::default();
    job.wrap.max_width = wrap;
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let start = i;
        let color;
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            color = Color32::from_rgb(110, 160, 110);
        } else if c == '"' {
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(chars.len());
            color = Color32::from_rgb(230, 200, 120);
        } else if c.is_ascii_digit() {
            while i < chars.len() && (chars[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            color = Color32::from_rgb(140, 200, 255);
        } else if is_ident(c) {
            while i < chars.len() && is_ident(chars[i]) {
                i += 1;
            }
            let w: String = chars[start..i].iter().collect();
            color = if KEYWORDS.contains(&w.as_str()) {
                Color32::from_rgb(220, 130, 220)
            } else if TYPES.contains(&w.as_str()) {
                Color32::from_rgb(90, 200, 200)
            } else if funcs.contains_key(&w) {
                Color32::from_rgb(110, 170, 255)
            } else if w.starts_with('a') && w.len() > 1 && w[1..].chars().all(|c| c.is_ascii_digit()) {
                Color32::from_rgb(230, 230, 230)
            } else if w.starts_with("dword_")
                || w.starts_with("qword_")
                || w.starts_with("byte_")
                || w.starts_with("word_")
                || w.starts_with("unk_")
            {
                Color32::from_rgb(230, 170, 110)
            } else {
                Color32::from_gray(215)
            };
        } else {
            i += 1;
            color = Color32::from_gray(170);
        }
        let s: String = chars[start..i].iter().collect();
        job.append(&s, 0.0, fmt(color));
    }
    job
}

/// Identifier around char index `idx`.
pub fn word_at(text: &str, idx: usize) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() {
        return None;
    }
    let mut s = idx.min(chars.len().saturating_sub(1));
    if !is_ident(chars[s]) && s > 0 && is_ident(chars[s - 1]) {
        s -= 1;
    }
    if !is_ident(chars[s]) {
        return None;
    }
    let mut e = s;
    while s > 0 && is_ident(chars[s - 1]) {
        s -= 1;
    }
    while e < chars.len() && is_ident(chars[e]) {
        e += 1;
    }
    Some(chars[s..e].iter().collect())
}

/// Resolve an identifier to an address: function names, `sub_XXXX`,
/// `loc_XXXX`, `dword_XXXX`, `unk_XXXX`, `LABEL_XXXX`.
pub fn resolve(word: &str, funcs: &HashMap<String, u64>) -> Option<u64> {
    if let Some(a) = funcs.get(word) {
        return Some(*a);
    }
    let (_, hex) = word.split_once('_')?;
    u64::from_str_radix(hex, 16).ok()
}
