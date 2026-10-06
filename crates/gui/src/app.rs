//! Main application state and layout (IDA-style workflow).

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{mpsc, Arc},
    thread,
};

use disasm_core::{
    analysis::{Analysis, Function},
    disasm::{Flow, Insn},
    entry::EntryInfo,
    loader::Binary,
};
use egui::{Color32, RichText};

use crate::{
    graph_view::GraphView,
    hex_view,
    names::{InsnFormatter, NameDb},
};

struct Project {
    path: String,
    binary: Binary,
    analysis: Analysis,
    entry: EntryInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Graph,
    Listing,
    Hex,
    Strings,
    Xrefs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SideList {
    Functions,
    Imports,
    Exports,
    Sections,
}

/// A pending rename dialog.
struct Rename {
    addr: u64,
    text: String,
}

pub struct App {
    project: Option<Arc<Project>>,
    loading: Option<mpsc::Receiver<Result<Project, String>>>,
    file_dialog: Option<mpsc::Receiver<Option<PathBuf>>>,
    error: Option<String>,
    path_input: String,

    side: SideList,
    filter: String,
    str_filter: String,
    tab: Tab,
    current_fn: Option<u64>,
    cursor: Option<u64>,
    hex_jump: bool,
    goto_input: String,
    pending_goto: Option<String>,

    graph: GraphView,
    show_decompiler: bool,
    names: Arc<NameDb>,
    /// User-assigned names (addr → name), applied on top of analysis names.
    user_names: HashMap<u64, String>,
    rename: Option<Rename>,
    comments: HashMap<u64, String>,
    comment_edit: Option<Rename>,
    ctx: Option<Arc<decompiler::Context>>,
    decomp_cache: HashMap<u64, String>,
    history: Vec<u64>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, path: Option<String>, goto: Option<String>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let mut app = Self {
            project: None,
            loading: None,
            file_dialog: None,
            error: None,
            path_input: path.clone().unwrap_or_default(),
            side: SideList::Functions,
            filter: String::new(),
            str_filter: String::new(),
            tab: Tab::Graph,
            current_fn: None,
            cursor: None,
            hex_jump: false,
            goto_input: String::new(),
            pending_goto: goto,
            graph: GraphView::default(),
            show_decompiler: true,
            names: Arc::new(NameDb::default()),
            user_names: HashMap::new(),
            rename: None,
            comments: HashMap::new(),
            comment_edit: None,
            ctx: None,
            decomp_cache: HashMap::new(),
            history: Vec::new(),
        };
        if let Some(p) = path {
            app.open(p);
        }
        app
    }

    fn open(&mut self, path: String) {
        let (tx, rx) = mpsc::channel();
        self.loading = Some(rx);
        self.error = None;
        self.path_input = path.clone();
        thread::spawn(move || {
            let res = Binary::from_path(&path)
                .map(|binary| {
                    let analysis = Analysis::run(&binary);
                    let entry = analysis.entry.clone();
                    Project {
                        path,
                        binary,
                        analysis,
                        entry,
                    }
                })
                .map_err(|e| e.to_string());
            let _ = tx.send(res);
        });
    }

    /// Open a native file picker on a background thread.
    fn pick_file(&mut self) {
        let (tx, rx) = mpsc::channel();
        self.file_dialog = Some(rx);
        thread::spawn(move || {
            let file = rfd::FileDialog::new().set_title("Open binary").pick_file();
            let _ = tx.send(file);
        });
    }

    fn rebuild_names(&mut self) {
        if let Some(p) = &self.project {
            self.names = Arc::new(NameDb::new(&p.binary, &p.analysis, &self.user_names));
            let mut ctx = match &self.ctx {
                Some(c) => (**c).clone(),
                None => decompiler::Context::new(&p.binary, &p.analysis),
            };
            for (a, n) in &self.user_names {
                ctx.names.insert(*a, n.clone());
            }
            self.ctx = Some(Arc::new(ctx));
            self.decomp_cache.clear();
            self.graph.invalidate();
        }
    }

    fn apply_rename(&mut self, addr: u64, name: String) {
        let name = name.trim().to_owned();
        if name.is_empty() {
            self.user_names.remove(&addr);
        } else if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_@$?.:".contains(c))
        {
            self.error = Some(format!("invalid name `{name}`"));
            return;
        } else {
            self.user_names.insert(addr, name);
        }
        self.rebuild_names();
    }

    /// Current operand formatter (fresh per use; cheap).
    fn formatter(&self) -> InsnFormatter {
        InsnFormatter::new(self.names.clone())
    }

    fn display_name(&self, f: &Function) -> String {
        self.user_names
            .get(&f.entry)
            .cloned()
            .unwrap_or_else(|| f.name.clone())
    }

    fn poll(&mut self) {
        if let Some(rx) = &self.file_dialog {
            if let Ok(file) = rx.try_recv() {
                self.file_dialog = None;
                if let Some(p) = file {
                    self.open(p.display().to_string());
                }
            }
        }
        let Some(rx) = &self.loading else { return };
        if let Ok(res) = rx.try_recv() {
            self.loading = None;
            match res {
                Ok(p) => {
                    let start = p
                        .entry
                        .main
                        .or(p.entry.entry)
                        .or_else(|| p.analysis.functions().next().map(|f| f.entry));
                    self.project = Some(Arc::new(p));
                    self.user_names.clear();
                    self.comments.clear();
                    self.ctx = None;
                    self.decomp_cache.clear();
                    self.history.clear();
                    self.graph = GraphView::default();
                    self.current_fn = None;
                    self.cursor = None;
                    self.rebuild_names();
                    if let Some(f) = start {
                        self.navigate(f);
                    }
                    if let Some(g) = self.pending_goto.take() {
                        self.goto(g);
                    }
                }
                Err(e) => self.error = Some(e),
            }
        }
    }

    fn navigate(&mut self, addr: u64) {
        let Some(p) = self.project.clone() else { return };
        if let Some(cur) = self.cursor {
            if cur != addr {
                self.history.push(cur);
            }
        }
        self.cursor = Some(addr);
        self.hex_jump = true;
        if let Some(f) = p.analysis.function_containing(addr) {
            if self.current_fn != Some(f.entry) {
                self.current_fn = Some(f.entry);
            }
            self.graph.focus_on(addr);
        }
    }

    fn back(&mut self) {
        if let Some(prev) = self.history.pop() {
            self.cursor = None;
            self.navigate(prev);
            self.history.pop();
        }
    }

    fn goto(&mut self, s: String) {
        let Some(p) = self.project.clone() else { return };
        let s = s.trim().to_owned();
        let hex = s.trim_start_matches("0x").trim_start_matches("0X");
        if let Ok(a) = u64::from_str_radix(hex, 16) {
            if p.binary.memory.is_mapped(a) {
                self.navigate(a);
                return;
            }
        }
        if let Some(f) = p.analysis.functions().find(|f| self.display_name(f) == s) {
            self.navigate(f.entry);
            return;
        }
        if let Some(sym) = p.binary.symbols.iter().find(|y| y.name == s) {
            self.navigate(sym.addr);
            return;
        }
        self.error = Some(format!("cannot resolve `{s}`"));
    }

    /// Follow the branch / call / data target of an instruction.
    fn follow(&mut self, insn: &Insn) {
        let t = match insn.flow {
            Flow::Call(t) | Flow::CallNoReturn(t) | Flow::Jump(t) | Flow::CondJump(t) => Some(t),
            _ => insn.mem_refs.first().map(|r| r.addr),
        };
        if let Some(t) = t {
            self.navigate(t);
        }
    }

    fn rename_target(&self) -> Option<u64> {
        let p = self.project.as_ref()?;
        let c = self.cursor?;
        // Rename the function entry if the cursor is on it, else the data/func at the operand.
        if p.analysis.function(c).is_some() {
            Some(c)
        } else {
            p.analysis.function_containing(c).map(|f| f.entry)
        }
    }

    fn start_rename(&mut self, addr: u64) {
        let cur = self
            .project
            .as_ref()
            .and_then(|p| p.analysis.function(addr).map(|f| self.display_name(f)))
            .or_else(|| self.names.label(addr, 8))
            .unwrap_or_default();
        self.rename = Some(Rename { addr, text: cur });
    }

    fn decompiled(&mut self, p: &Project, f: &Function) -> String {
        if let Some(s) = self.decomp_cache.get(&f.entry) {
            return s.clone();
        }
        let ctx = match &self.ctx {
            Some(c) => c.clone(),
            None => Arc::new(decompiler::Context::new(&p.binary, &p.analysis)),
        };
        let mut f = f.clone();
        f.name = self.display_name(&f);
        let s =
            decompiler::decompile_with(&f, &ctx).unwrap_or_else(|e| format!("// decompilation failed: {e}"));
        self.decomp_cache.insert(f.entry, s.clone());
        s
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        // egui is reactive: keep polling while background work is running,
        // otherwise a finished load (e.g. after drag & drop) is never shown.
        if self.loading.is_some() || self.file_dialog.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }

        self.handle_drop(ctx);
        self.hotkeys(ctx);
        self.top_bar(ctx);
        self.status_bar(ctx);
        self.dialogs(ctx);

        let Some(p) = self.project.clone() else {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.centered_and_justified(|ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(ui.available_height() / 3.0);
                        if self.loading.is_some() {
                            ui.spinner();
                            ui.label("Analysing…");
                        } else {
                            ui.label(RichText::new("Drop a PE / ELF / Mach-O file here").size(20.0));
                            ui.add_space(8.0);
                            if ui
                                .button(RichText::new("📂  Open file…  (Ctrl+O)").size(16.0))
                                .clicked()
                            {
                                self.pick_file();
                            }
                        }
                    });
                });
            });
            self.drop_overlay(ctx);
            return;
        };

        self.side_panel(ctx, &p);
        if self.show_decompiler {
            self.decompiler_panel(ctx, &p);
        }
        egui::CentralPanel::default().show(ctx, |ui| self.central(ui, &p));
        self.drop_overlay(ctx);
    }
}

impl App {
    fn handle_drop(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if let Some(f) = dropped.first() {
            if let Some(path) = &f.path {
                self.open(path.display().to_string());
            } else if let Some(bytes) = &f.bytes {
                // Platforms that only deliver bytes: spool to a temp file.
                let tmp = std::env::temp_dir().join(if f.name.is_empty() { "dropped.bin" } else { &f.name });
                match std::fs::write(&tmp, bytes) {
                    Ok(()) => self.open(tmp.display().to_string()),
                    Err(e) => self.error = Some(format!("drop failed: {e}")),
                }
            }
        }
    }

    fn drop_overlay(&self, ctx: &egui::Context) {
        if ctx.input(|i| i.raw.hovered_files.is_empty()) {
            return;
        }
        let painter = ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("drop")));
        let r = ctx.screen_rect();
        painter.rect_filled(r, 0.0, Color32::from_black_alpha(170));
        painter.text(
            r.center(),
            egui::Align2::CENTER_CENTER,
            "Drop to open",
            egui::FontId::proportional(32.0),
            Color32::WHITE,
        );
    }

    fn hotkeys(&mut self, ctx: &egui::Context) {
        use egui::{Key, Modifiers};
        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::O)) {
            self.pick_file();
        }
        // Ignore single-key shortcuts while typing in a text field.
        if ctx.wants_keyboard_input() || self.rename.is_some() || self.comment_edit.is_some() {
            return;
        }
        let (esc, n, x, g, space, f5, tab, semi, enter, e_key) = ctx.input(|i| {
            (
                i.key_pressed(Key::Escape),
                i.key_pressed(Key::N),
                i.key_pressed(Key::X),
                i.key_pressed(Key::G),
                i.key_pressed(Key::Space),
                i.key_pressed(Key::F5),
                i.key_pressed(Key::Tab),
                i.key_pressed(Key::Semicolon),
                i.key_pressed(Key::Enter),
                i.key_pressed(Key::E) && i.modifiers.command,
            )
        });
        if esc {
            self.back();
        }
        if n {
            if let Some(a) = self.rename_target() {
                self.start_rename(a);
            }
        }
        if x {
            self.tab = Tab::Xrefs;
        }
        if g {
            self.goto_input.clear();
            ctx.memory_mut(|m| m.request_focus(egui::Id::new("goto")));
        }
        if space {
            self.tab = if self.tab == Tab::Graph {
                Tab::Listing
            } else {
                Tab::Graph
            };
        }
        if f5 || tab {
            self.show_decompiler = !self.show_decompiler || f5;
        }
        if semi {
            if let Some(c) = self.cursor {
                self.comment_edit = Some(Rename {
                    addr: c,
                    text: self.comments.get(&c).cloned().unwrap_or_default(),
                });
            }
        }
        if e_key {
            self.jump_entry(false);
        }
        if enter {
            if let (Some(p), Some(c)) = (self.project.clone(), self.cursor) {
                if let Some(i) = p.analysis.function_containing(c).and_then(|f| f.insns.get(&c)) {
                    let i = i.clone();
                    self.follow(&i);
                }
            }
        }
    }

    fn jump_entry(&mut self, main: bool) {
        let Some(p) = self.project.clone() else { return };
        let t = if main { p.entry.main } else { p.entry.entry };
        match t {
            Some(a) => self.navigate(a),
            None => {
                self.error = Some(
                    if main {
                        "main() was not found"
                    } else {
                        "no entry point"
                    }
                    .into(),
                )
            }
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        if let Some(mut r) = self.rename.take() {
            let mut open = true;
            let mut done = None;
            egui::Window::new(format!("Rename address {:X}", r.addr))
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Name:");
                    let te = ui.add(egui::TextEdit::singleline(&mut r.text).desired_width(320.0));
                    te.request_focus();
                    ui.horizontal(|ui| {
                        if ui.button("OK").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            done = Some(true);
                        }
                        if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                            done = Some(false);
                        }
                    });
                    ui.small("empty name = restore default");
                });
            match done {
                Some(true) => self.apply_rename(r.addr, r.text),
                Some(false) => {}
                None if open => self.rename = Some(r),
                None => {}
            }
        }
        if let Some(mut r) = self.comment_edit.take() {
            let mut done = None;
            egui::Window::new(format!("Comment at {:X}", r.addr))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    let te = ui.add(egui::TextEdit::singleline(&mut r.text).desired_width(360.0));
                    te.request_focus();
                    ui.horizontal(|ui| {
                        if ui.button("OK").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            done = Some(true);
                        }
                        if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                            done = Some(false);
                        }
                    });
                });
            match done {
                Some(true) => {
                    if r.text.trim().is_empty() {
                        self.comments.remove(&r.addr);
                    } else {
                        self.comments.insert(r.addr, r.text);
                    }
                    self.graph.invalidate();
                }
                Some(false) => {}
                None => self.comment_edit = Some(r),
            }
        }
    }

    /// IDA-style right-click menu for an instruction. Shared by graph and listing.
    fn insn_menu(&mut self, ui: &mut egui::Ui, p: &Arc<Project>, addr: u64) {
        let Some(f) = p.analysis.function_containing(addr) else {
            ui.label("no instruction");
            return;
        };
        let Some(insn) = f.insns.get(&addr).cloned() else {
            ui.label(format!("{addr:X}"));
            return;
        };
        let text = self.formatter().format(&insn);
        ui.label(RichText::new(format!("{addr:X}  {text}")).monospace().weak());
        ui.separator();

        let target = match insn.flow {
            Flow::Call(t) | Flow::CallNoReturn(t) | Flow::Jump(t) | Flow::CondJump(t) => Some(t),
            _ => None,
        };
        if let Some(t) = target {
            let name = self.names.label(t, 0).unwrap_or_else(|| format!("{t:X}"));
            if ui.button(format!("➡  Jump to {name}            Enter")).clicked() {
                self.navigate(t);
                ui.close_menu();
            }
        }
        for r in insn.mem_refs.iter().take(2) {
            let name = self
                .names
                .label(r.addr, 8)
                .unwrap_or_else(|| format!("{:X}", r.addr));
            if ui.button(format!("➡  Jump to operand {name}")).clicked() {
                self.navigate(r.addr);
                self.tab = if self.names.is_code(r.addr) {
                    self.tab
                } else {
                    Tab::Hex
                };
                ui.close_menu();
            }
        }
        if let Flow::IndirectJump(ts) = &insn.flow {
            ui.menu_button(format!("Switch targets ({})", ts.len()), |ui| {
                egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                    for (i, t) in ts.iter().enumerate() {
                        if ui.button(format!("case {i}: loc_{t:X}")).clicked() {
                            self.navigate(*t);
                            ui.close_menu();
                        }
                    }
                });
            });
        }
        if ui.button("⤴  Jump to function start").clicked() {
            self.navigate(f.entry);
            ui.close_menu();
        }
        ui.separator();
        if ui.button("✏  Rename…                            N").clicked() {
            let a = target
                .filter(|t| p.analysis.function(*t).is_some())
                .unwrap_or(f.entry);
            self.start_rename(a);
            ui.close_menu();
        }
        if ui.button("💬  Comment…                           ;").clicked() {
            self.comment_edit = Some(Rename {
                addr,
                text: self.comments.get(&addr).cloned().unwrap_or_default(),
            });
            ui.close_menu();
        }
        ui.separator();
        if ui.button("🔗  Xrefs to this address          X").clicked() {
            self.cursor = Some(addr);
            self.tab = Tab::Xrefs;
            ui.close_menu();
        }
        if ui.button("🔗  Xrefs to function").clicked() {
            self.cursor = Some(f.entry);
            self.tab = Tab::Xrefs;
            ui.close_menu();
        }
        if ui.button("🔢  Show in hex view").clicked() {
            self.cursor = Some(addr);
            self.hex_jump = true;
            self.tab = Tab::Hex;
            ui.close_menu();
        }
        if ui.button("📝  Decompile function          F5").clicked() {
            self.show_decompiler = true;
            ui.close_menu();
        }
        ui.separator();
        ui.menu_button("📋  Copy", |ui| {
            if ui.button("Address").clicked() {
                ui.output_mut(|o| o.copied_text = format!("{addr:X}"));
                ui.close_menu();
            }
            if ui.button("Instruction").clicked() {
                ui.output_mut(|o| o.copied_text = text.clone());
                ui.close_menu();
            }
            if ui.button("Bytes").clicked() {
                let b = p.binary.memory.read(addr, insn.len as usize).unwrap_or_default();
                ui.output_mut(|o| {
                    o.copied_text = b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")
                });
                ui.close_menu();
            }
            if ui.button("Whole function (asm)").clicked() {
                let mut fm = self.formatter();
                let s: String = f
                    .insns
                    .values()
                    .map(|i| format!("{:X}  {}\n", i.addr, fm.format(i)))
                    .collect();
                ui.output_mut(|o| o.copied_text = s);
                ui.close_menu();
            }
            if ui.button("Pseudocode").clicked() {
                let s = self.decompiled(p, f);
                ui.output_mut(|o| o.copied_text = s);
                ui.close_menu();
            }
        });
    }

    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open…            Ctrl+O").clicked() {
                        self.pick_file();
                        ui.close_menu();
                    }
                    if ui
                        .add_enabled(
                            self.project.is_some(),
                            egui::Button::new("Export pseudocode (.c)…"),
                        )
                        .clicked()
                    {
                        self.export_c();
                        ui.close_menu();
                    }
                    if ui.button("Quit").clicked() {
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Jump", |ui| {
                    if ui.button("Entry point          Ctrl+E").clicked() {
                        self.jump_entry(false);
                        ui.close_menu();
                    }
                    if ui.button("main()").clicked() {
                        self.jump_entry(true);
                        ui.close_menu();
                    }
                    if ui.button("Address / name…   G").clicked() {
                        ui.ctx().memory_mut(|m| m.request_focus(egui::Id::new("goto")));
                        ui.close_menu();
                    }
                    if ui.button("Back                    Esc").clicked() {
                        self.back();
                        ui.close_menu();
                    }
                });
                ui.menu_button("View", |ui| {
                    ui.selectable_value(&mut self.tab, Tab::Graph, "Graph");
                    ui.selectable_value(&mut self.tab, Tab::Listing, "Listing (text)");
                    ui.selectable_value(&mut self.tab, Tab::Hex, "Hex");
                    ui.selectable_value(&mut self.tab, Tab::Strings, "Strings");
                    ui.selectable_value(&mut self.tab, Tab::Xrefs, "Xrefs");
                    ui.checkbox(&mut self.show_decompiler, "Pseudocode  (F5)");
                    if ui.button("Reset graph zoom").clicked() {
                        self.graph.reset_view();
                    }
                });
                ui.separator();
                if ui.button("📂 Open").clicked() {
                    self.pick_file();
                }
                if let Some(p) = &self.project {
                    let has_main = p.entry.main.is_some();
                    if ui
                        .button("⏵ Entry")
                        .on_hover_text(format!("{:X?}", p.entry.entry))
                        .clicked()
                    {
                        self.jump_entry(false);
                    }
                    if ui.add_enabled(has_main, egui::Button::new("⏵ main")).clicked() {
                        self.jump_entry(true);
                    }
                }
                if !self.history.is_empty() && ui.button("← Back").clicked() {
                    self.back();
                }
                ui.separator();
                ui.label("Go to:");
                let g = ui.add(
                    egui::TextEdit::singleline(&mut self.goto_input)
                        .id(egui::Id::new("goto"))
                        .hint_text("address or name  (G)")
                        .desired_width(200.0),
                );
                if g.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.goto(self.goto_input.clone());
                }
            });
        });
    }

    fn export_c(&mut self) {
        let Some(p) = self.project.clone() else { return };
        let Some(path) = rfd::FileDialog::new().set_file_name("decompiled.c").save_file() else {
            return;
        };
        let ctx = self
            .ctx
            .clone()
            .unwrap_or_else(|| Arc::new(decompiler::Context::new(&p.binary, &p.analysis)));
        let mut out = String::from("// Generated by rdisasm\n#include <defs.h>\n\n");
        for f in p.analysis.functions() {
            out += &decompiler::decompile_with(f, &ctx).unwrap_or_else(|e| format!("// {}: {e}\n", f.name));
            out.push('\n');
        }
        if let Err(e) = std::fs::write(&path, out) {
            self.error = Some(e.to_string());
        }
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(e) = self.error.clone() {
                    ui.colored_label(Color32::from_rgb(240, 90, 90), &e);
                    if ui.small_button("✖").clicked() {
                        self.error = None;
                    }
                    ui.separator();
                }
                if self.loading.is_some() {
                    ui.spinner();
                    ui.label("analysing…");
                }
                if let Some(p) = &self.project {
                    ui.label(format!(
                        "{}  ·  {:?} {:?}  ·  base {:X}  ·  entry {}  ·  main {}  ·  {} functions  ·  {} xrefs",
                        p.path,
                        p.binary.format,
                        p.binary.arch,
                        p.binary.image_base,
                        p.entry.entry.map_or("-".into(), |a| format!("{a:X}")),
                        p.entry.main.map_or("not found".into(), |a| format!("{a:X} ({:?})", p.entry.source.unwrap_or(disasm_core::entry::MainSource::Symbol))),
                        p.analysis.function_count(),
                        p.analysis.xrefs.len(),
                    ));
                }
                if let Some(c) = self.cursor {
                    ui.separator();
                    ui.monospace(format!("{c:X}"));
                }
            });
        });
    }

    fn side_panel(&mut self, ctx: &egui::Context, p: &Arc<Project>) {
        egui::SidePanel::left("side")
            .default_width(300.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.selectable_value(&mut self.side, SideList::Functions, "Functions");
                    ui.selectable_value(&mut self.side, SideList::Imports, "Imports");
                    ui.selectable_value(&mut self.side, SideList::Exports, "Exports");
                    ui.selectable_value(&mut self.side, SideList::Sections, "Segments");
                });
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text("🔍 filter…")
                        .desired_width(f32::INFINITY),
                );
                ui.separator();
                let needle = self.filter.to_lowercase();
                let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 4.0;
                let mut target = None;
                let mut rename = None;
                let mut xrefs = None;
                match self.side {
                    SideList::Functions => {
                        let funcs: Vec<(u64, String, usize)> = p
                            .analysis
                            .functions()
                            .map(|f| (f.entry, self.display_name(f), f.size as usize))
                            .filter(|(e, n, _)| {
                                needle.is_empty()
                                    || n.to_lowercase().contains(&needle)
                                    || format!("{e:x}").contains(&needle)
                            })
                            .collect();
                        ui.small(format!("{} functions", funcs.len()));
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show_rows(ui, row_h, funcs.len(), |ui, range| {
                                for (entry, name, size) in &funcs[range] {
                                    let sel = self.current_fn == Some(*entry);
                                    let special =
                                        Some(*entry) == p.entry.main || Some(*entry) == p.entry.entry;
                                    let mut t =
                                        RichText::new(format!("{name:<28} {entry:X}  {size}")).monospace();
                                    if special {
                                        t = t.color(Color32::from_rgb(255, 190, 80)).strong();
                                    } else if name.starts_with("sub_") {
                                        t = t.color(Color32::from_gray(200));
                                    } else {
                                        t = t.color(Color32::from_rgb(150, 210, 255));
                                    }
                                    let r = ui.selectable_label(sel, t);
                                    if r.clicked() {
                                        target = Some(*entry);
                                    }
                                    r.context_menu(|ui| {
                                        if ui.button("Jump").clicked() {
                                            target = Some(*entry);
                                            ui.close_menu();
                                        }
                                        if ui.button("Rename…").clicked() {
                                            rename = Some(*entry);
                                            ui.close_menu();
                                        }
                                        if ui.button("Xrefs to").clicked() {
                                            xrefs = Some(*entry);
                                            ui.close_menu();
                                        }
                                        if ui.button("Copy name").clicked() {
                                            ui.output_mut(|o| o.copied_text = name.clone());
                                            ui.close_menu();
                                        }
                                    });
                                }
                            });
                    }
                    SideList::Imports | SideList::Exports => {
                        let want = if self.side == SideList::Imports {
                            disasm_core::loader::SymbolKind::Import
                        } else {
                            disasm_core::loader::SymbolKind::Export
                        };
                        let syms: Vec<_> = p
                            .binary
                            .symbols
                            .iter()
                            .filter(|s| {
                                s.kind == want
                                    || (want == disasm_core::loader::SymbolKind::Export
                                        && s.kind == disasm_core::loader::SymbolKind::Function)
                            })
                            .filter(|s| needle.is_empty() || s.name.to_lowercase().contains(&needle))
                            .collect();
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show_rows(ui, row_h, syms.len(), |ui, range| {
                                for s in &syms[range] {
                                    let r = ui.selectable_label(
                                        false,
                                        RichText::new(format!("{:X}  {}", s.addr, s.name)).monospace(),
                                    );
                                    if r.clicked() {
                                        if want == disasm_core::loader::SymbolKind::Import {
                                            xrefs = Some(s.addr);
                                        } else {
                                            target = Some(s.addr);
                                        }
                                    }
                                    r.on_hover_text("click: imports → xrefs, exports → jump");
                                }
                            });
                    }
                    SideList::Sections => {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                for s in p.binary.memory.sections() {
                                    let label =
                                        format!("{:<16} {:X}-{:X} {}", s.name, s.vaddr, s.end(), s.perms);
                                    if ui
                                        .selectable_label(false, RichText::new(label).monospace())
                                        .clicked()
                                    {
                                        self.cursor = Some(s.vaddr);
                                        self.hex_jump = true;
                                        self.tab = Tab::Hex;
                                    }
                                }
                            });
                    }
                }
                if let Some(t) = target {
                    self.navigate(t);
                }
                if let Some(a) = rename {
                    self.start_rename(a);
                }
                if let Some(a) = xrefs {
                    self.cursor = Some(a);
                    self.tab = Tab::Xrefs;
                }
            });
    }

    fn name_index(&self, p: &Project) -> HashMap<String, u64> {
        let mut m: HashMap<String, u64> = p
            .analysis
            .functions()
            .map(|f| (self.display_name(f), f.entry))
            .collect();
        for (a, n) in &self.names.imports {
            m.entry(n.clone()).or_insert(*a);
        }
        m
    }

    fn decompiler_panel(&mut self, ctx: &egui::Context, p: &Arc<Project>) {
        egui::SidePanel::right("decomp")
            .default_width(560.0)
            .resizable(true)
            .show(ctx, |ui| {
                let Some(f) = self.current_fn.and_then(|e| p.analysis.function(e)) else {
                    ui.heading("Pseudocode");
                    ui.label("no function selected");
                    return;
                };
                ui.horizontal(|ui| {
                    ui.heading(format!("Pseudocode-A: {}", self.display_name(f)));
                    if ui.small_button("⟳").on_hover_text("re-decompile").clicked() {
                        self.decomp_cache.remove(&f.entry);
                    }
                });
                ui.separator();
                let text = self.decompiled(p, f);
                let names = self.name_index(p);
                let mut layouter = |ui: &egui::Ui, s: &str, wrap: f32| {
                    ui.fonts(|fo| fo.layout_job(crate::pseudo::highlight(s, &names, wrap)))
                };
                let mut action: Option<(bool, String)> = None; // (is_double_click, word)
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let mut ro: &str = text.as_str();
                        let out = egui::TextEdit::multiline(&mut ro)
                            .code_editor()
                            .desired_width(f32::INFINITY)
                            .layouter(&mut layouter)
                            .show(ui);
                        let word_under = |pos: Option<egui::Pos2>| {
                            let pos = pos?;
                            let c = out.galley.cursor_from_pos(pos - out.galley_pos);
                            crate::pseudo::word_at(&text, c.ccursor.index)
                        };
                        let pointer = ui.input(|i| i.pointer.interact_pos());
                        if out.response.double_clicked() {
                            if let Some(w) = word_under(pointer) {
                                action = Some((true, w));
                            }
                        }
                        if out.response.secondary_clicked() {
                            if let Some(w) = word_under(pointer) {
                                ui.memory_mut(|m| m.data.insert_temp(egui::Id::new("pseudo_word"), w));
                            }
                        }
                        let word: Option<String> =
                            ui.memory(|m| m.data.get_temp(egui::Id::new("pseudo_word")));
                        out.response.context_menu(|ui| {
                            let target = word.as_deref().and_then(|w| crate::pseudo::resolve(w, &names));
                            if let Some(w) = &word {
                                ui.label(RichText::new(w).monospace().weak());
                                ui.separator();
                            }
                            if ui
                                .add_enabled(target.is_some(), egui::Button::new("➡  Jump to definition"))
                                .clicked()
                            {
                                action = Some((true, word.clone().unwrap_or_default()));
                                ui.close_menu();
                            }
                            if ui
                                .add_enabled(target.is_some(), egui::Button::new("🔗  Xrefs to"))
                                .clicked()
                            {
                                if let Some(t) = target {
                                    self.cursor = Some(t);
                                    self.tab = Tab::Xrefs;
                                }
                                ui.close_menu();
                            }
                            let is_func = target.is_some_and(|t| p.analysis.function(t).is_some());
                            if ui.add_enabled(is_func, egui::Button::new("✏  Rename…")).clicked() {
                                if let Some(t) = target {
                                    self.start_rename(t);
                                }
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui.button("📋  Copy word").clicked() {
                                ui.output_mut(|o| o.copied_text = word.clone().unwrap_or_default());
                                ui.close_menu();
                            }
                            if ui.button("📋  Copy all").clicked() {
                                ui.output_mut(|o| o.copied_text = text.clone());
                                ui.close_menu();
                            }
                        });
                    });
                if let Some((_, w)) = action {
                    if let Some(t) = crate::pseudo::resolve(&w, &names) {
                        if p.binary.memory.is_mapped(t) {
                            self.navigate(t);
                        }
                    }
                }
            });
    }

    fn central(&mut self, ui: &mut egui::Ui, p: &Arc<Project>) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Graph, "Graph");
            ui.selectable_value(&mut self.tab, Tab::Listing, "Listing");
            ui.selectable_value(&mut self.tab, Tab::Hex, "Hex");
            ui.selectable_value(&mut self.tab, Tab::Strings, "Strings");
            ui.selectable_value(&mut self.tab, Tab::Xrefs, "Xrefs");
            if let Some(f) = self.current_fn.and_then(|e| p.analysis.function(e)) {
                ui.separator();
                ui.monospace(self.display_name(f));
            }
        });
        ui.separator();
        let func = self.current_fn.and_then(|e| p.analysis.function(e));
        match self.tab {
            Tab::Graph => match func {
                Some(f) => self.graph_tab(ui, p, f),
                None => {
                    ui.label("select a function");
                }
            },
            Tab::Listing => match func {
                Some(f) => self.listing(ui, p, f),
                None => {
                    ui.label("no function at cursor");
                }
            },
            Tab::Hex => {
                let focus = self.cursor.unwrap_or(p.binary.image_base);
                let len = func
                    .and_then(|f| f.insns.get(&focus))
                    .map_or(1, |i| u64::from(i.len));
                hex_view::ui(ui, &p.binary.memory, focus, len, self.hex_jump);
                self.hex_jump = false;
            }
            Tab::Strings => self.strings(ui, p),
            Tab::Xrefs => self.xrefs(ui, p),
        }
    }

    fn graph_tab(&mut self, ui: &mut egui::Ui, p: &Arc<Project>, f: &Function) {
        let mut fm = self.formatter();
        let comments = self.comments.clone();
        let title = self.display_name(f);
        let mut render = |insn: &Insn| {
            let mut s = format!("{:08X} {}", insn.addr, fm.format(insn));
            if let Some(c) = comments.get(&insn.addr) {
                s.push_str(&format!("  ; {c}"));
            }
            s
        };
        let out = self.graph.ui(ui, f, &title, &mut render);
        if let Some(a) = out.clicked {
            self.cursor = Some(a);
            self.hex_jump = true;
        }
        if let Some(a) = out.activated {
            if let Some(insn) = f.insns.get(&a).cloned() {
                self.follow(&insn);
            }
        }
        for (resp, addr) in out.nodes {
            resp.context_menu(|ui| self.insn_menu(ui, p, addr));
        }
    }

    fn listing(&mut self, ui: &mut egui::Ui, p: &Arc<Project>, f: &Function) {
        let insns: Vec<&Insn> = f.insns.values().collect();
        let mut fm = self.formatter();
        let mut nav = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for insn in &insns {
                    let leader = f.cfg.node_at(insn.addr).is_some();
                    if leader {
                        let lbl = if insn.addr == f.entry {
                            format!("{}:", self.display_name(f))
                        } else {
                            format!("loc_{:X}:", insn.addr)
                        };
                        ui.label(
                            RichText::new(lbl)
                                .monospace()
                                .color(Color32::from_rgb(120, 190, 255)),
                        );
                    }
                    let sel = self.cursor == Some(insn.addr);
                    let arrow = match insn.flow {
                        Flow::Jump(_) | Flow::CondJump(_) => "→ ",
                        Flow::Call(_) | Flow::CallNoReturn(_) => "⤷ ",
                        Flow::Return => "⏎ ",
                        _ => "  ",
                    };
                    let bytes = p
                        .binary
                        .memory
                        .read(insn.addr, insn.len as usize)
                        .map(|b| b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" "))
                        .unwrap_or_default();
                    let mut label = format!("{arrow}{:08X}  {bytes:<24} {}", insn.addr, fm.format(insn));
                    if let Some(c) = self.comments.get(&insn.addr) {
                        label.push_str(&format!("   ; {c}"));
                    } else if let Some(c) = self.names.auto_comment(insn) {
                        label.push_str(&format!("   ; {c}"));
                    }
                    let mut rt = RichText::new(label).monospace();
                    if matches!(insn.flow, Flow::Call(_) | Flow::CallNoReturn(_)) {
                        rt = rt.color(Color32::from_rgb(230, 200, 140));
                    }
                    let r = ui.selectable_label(sel, rt);
                    if self.hex_jump && sel {
                        r.scroll_to_me(Some(egui::Align::Center));
                    }
                    if r.clicked() || r.secondary_clicked() {
                        self.cursor = Some(insn.addr);
                        self.graph.selected_addr = Some(insn.addr);
                    }
                    if r.double_clicked() {
                        nav = Some((*insn).clone());
                    }
                    let addr = insn.addr;
                    r.context_menu(|ui| self.insn_menu(ui, p, addr));
                }
            });
        if let Some(insn) = nav {
            self.follow(&insn);
        }
    }

    fn strings(&mut self, ui: &mut egui::Ui, p: &Arc<Project>) {
        ui.add(egui::TextEdit::singleline(&mut self.str_filter).hint_text("🔍 filter strings…"));
        let needle = self.str_filter.to_lowercase();
        let list: Vec<_> = p
            .analysis
            .strings
            .iter()
            .filter(|s| needle.is_empty() || s.value.to_lowercase().contains(&needle))
            .collect();
        ui.small(format!("{} strings · click = xrefs", list.len()));
        let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 4.0;
        let mut target = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_h, list.len(), |ui, range| {
                for s in &list[range] {
                    let refs = p.analysis.xrefs.refs_to(s.addr).len();
                    let label = format!(
                        "{:X}  {:<24} ({refs}) {:?}",
                        s.addr,
                        crate::names::string_label(&s.value),
                        s.value
                    );
                    if ui
                        .selectable_label(false, RichText::new(label).monospace())
                        .clicked()
                    {
                        target = Some(s.addr);
                    }
                }
            });
        if let Some(t) = target {
            self.cursor = Some(t);
            self.hex_jump = true;
            self.tab = Tab::Xrefs;
        }
    }

    fn xrefs(&mut self, ui: &mut egui::Ui, p: &Arc<Project>) {
        let Some(c) = self.cursor else {
            ui.label("place the cursor on an address (X)");
            return;
        };
        let name = self.names.label(c, 8).unwrap_or_else(|| format!("{c:X}"));
        ui.heading(format!("Cross-references · {name} ({c:X})"));
        ui.separator();
        let mut target = None;
        let to = p.analysis.xrefs.refs_to(c);
        let from = p.analysis.xrefs.refs_from(c);
        ui.columns(2, |cols| {
            cols[0].label(RichText::new(format!("To ({})", to.len())).strong());
            egui::ScrollArea::vertical()
                .id_source("to")
                .auto_shrink([false, false])
                .show(&mut cols[0], |ui| {
                    for x in &to {
                        let owner = p
                            .analysis
                            .function_containing(x.from)
                            .map_or_else(|| "?".into(), |f| self.display_name(f));
                        if ui
                            .link(RichText::new(format!("{:X}  {:?}  {}", x.from, x.kind, owner)).monospace())
                            .clicked()
                        {
                            target = Some(x.from);
                        }
                    }
                });
            cols[1].label(RichText::new(format!("From ({})", from.len())).strong());
            egui::ScrollArea::vertical()
                .id_source("from")
                .auto_shrink([false, false])
                .show(&mut cols[1], |ui| {
                    for x in &from {
                        let n = self.names.label(x.to, 8).unwrap_or_else(|| format!("{:X}", x.to));
                        if ui
                            .link(RichText::new(format!("{:X}  {:?}  {}", x.to, x.kind, n)).monospace())
                            .clicked()
                        {
                            target = Some(x.to);
                        }
                    }
                });
        });
        if let Some(t) = target {
            self.navigate(t);
            if p.analysis.function_containing(t).is_some() {
                self.tab = Tab::Graph;
            }
        }
    }
}
