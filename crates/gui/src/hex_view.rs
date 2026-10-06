//! Synchronised hex / ASCII memory inspector.

use disasm_core::loader::MemoryMap;
use egui::{Color32, RichText};

const ROW: u64 = 16;

/// Render a hex dump around `focus`, highlighting `[focus, focus+hl_len)`.
/// `jump` scrolls the view to the focus (only set when the focus changes, so
/// the user can scroll freely afterwards).
pub fn ui(ui: &mut egui::Ui, mem: &MemoryMap, focus: u64, hl_len: u64, jump: bool) {
    let Some(sec) = mem.section_at(focus) else {
        ui.label(format!("{focus:#x} is not mapped"));
        return;
    };
    ui.label(
        RichText::new(format!(
            "section {}  [{:#x} – {:#x}]  {}",
            sec.name,
            sec.vaddr,
            sec.end(),
            sec.perms
        ))
        .monospace()
        .color(Color32::from_gray(160)),
    );
    let start_row = sec.vaddr & !(ROW - 1);
    let total_rows = (sec.end() - start_row).div_ceil(ROW);
    let focus_row = (focus - start_row) / ROW;
    let row_h = ui.text_style_height(&egui::TextStyle::Monospace);

    let mut area = egui::ScrollArea::vertical()
        .id_source(("hex", sec.vaddr))
        .auto_shrink([false, false]);
    if jump {
        area = area.vertical_scroll_offset(
            focus_row.saturating_sub(4) as f32 * (row_h + ui.spacing().item_spacing.y),
        );
    }
    area.show_rows(ui, row_h, total_rows as usize, |ui, range| {
        for r in range {
            let base = start_row + r as u64 * ROW;
            let mut job = egui::text::LayoutJob::default();
            let mono = egui::FontId::monospace(12.5);
            let fmt = |c: Color32| egui::TextFormat {
                font_id: mono.clone(),
                color: c,
                ..Default::default()
            };
            job.append(
                &format!("{base:016x}  "),
                0.0,
                fmt(Color32::from_rgb(120, 170, 255)),
            );
            let bytes: Vec<Option<u8>> = (0..ROW)
                .map(|i| {
                    let a = base + i;
                    if sec.contains(a) {
                        Some(mem.read(a, 1).map(|b| b[0]).unwrap_or(0))
                    } else {
                        None
                    }
                })
                .collect();
            for (i, b) in bytes.iter().enumerate() {
                let a = base + i as u64;
                let hl = a >= focus && a < focus + hl_len.max(1);
                let mut f = fmt(if hl {
                    Color32::BLACK
                } else {
                    Color32::from_gray(210)
                });
                if hl {
                    f.background = Color32::from_rgb(255, 200, 60);
                }
                let s = b.map_or("  ".to_owned(), |b| format!("{b:02x}"));
                job.append(&s, 0.0, f);
                job.append(if i == 7 { "  " } else { " " }, 0.0, fmt(Color32::GRAY));
            }
            job.append(" ", 0.0, fmt(Color32::GRAY));
            let ascii: String = bytes
                .iter()
                .map(|b| match b {
                    Some(c) if (0x20..0x7f).contains(c) => *c as char,
                    Some(_) => '.',
                    None => ' ',
                })
                .collect();
            job.append(&ascii, 0.0, fmt(Color32::from_rgb(170, 220, 150)));
            ui.label(job);
        }
    });
}
