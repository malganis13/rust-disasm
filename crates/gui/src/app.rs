//! Main application state and layout.

use std::{
    collections::HashMap,
    sync::{mpsc, Arc},
    thread,
};

use disasm_core::{
    analysis::{Analysis, Function},
    loader::Binary,
};
use egui::{Color32, RichText};

use crate::{graph_view::GraphView, hex_view};

/// A fully loaded + analysed project.
struct Project {
    path: String,
    binary: Binary,
    analysis: Analysis,
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
    Symbols,
    Sections,
}

pub struct App {
    project: Option<Arc<Project>>,
    loading: Option<mpsc::Receiver<Result<Project, String>>>,
    error: Option<String>,
    path_input: String,

    side: SideList,
    filter: String,
    tab: Tab,
    current_fn: Option<u64>,
    cursor: Option<u64>,
    hex_jump: bool,
    goto_input: String,

    graph: GraphView,
    show_decompiler: bool,
    decomp_cache: HashMap<u64, String>,
    history: Vec<u64>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, path: Option<String>, goto: Option<String>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let mut app = Self {
            project: None,
            loading: None,
            error: None,
            path_input: path.clone().unwrap_or_default(),
            side: SideList::Functions,
            filter: String::new(),
            tab: Tab::Graph,
            current_fn: None,
            cursor: None,
            hex_jump: false,
            goto_input: goto.unwrap_or_default(),
            graph: GraphView::default(),
            show_decompiler: true,
            decomp_cache: HashMap::new(),
            history: Vec::new(),
        };
        if let Some(p) = path {
            app.open(p);
        }
        app
    }

    /// Load and analyse a binary on a background thread.
    fn open(&mut self, path: String) {
        let (tx, rx) = mpsc::channel();
        self.loading = Some(rx);
        self.error = None;
        thread::spawn(move || {
            let res = Binary::from_path(&path)
                .map(|binary| {
                    let analysis = Analysis::run(&binary);
                    Project {
                        path,
                        binary,
                        analysis,
                    }
                })
                .map_err(|e| e.to_string());
            let _ = tx.send(res);
        });
    }

    fn poll_loading(&mut self) {
        let Some(rx) = &self.loading else { return };
        if let Ok(res) = rx.try_recv() {
            self.loading = None;
            match res {
                Ok(p) => {
                    let first = p
                        .binary
                        .entry_points
                        .iter()
                        .copied()
                        .find(|e| p.analysis.function(*e).is_some())
                        .or_else(|| p.analysis.functions().next().map(|f| f.entry));
                    self.project = Some(Arc::new(p));
                    self.decomp_cache.clear();
                    self.history.clear();
                    self.graph = GraphView::default();
                    self.current_fn = None;
                    if let Some(f) = first {
                        self.navigate(f);
                    }
                    if !self.goto_input.is_empty() {
                        self.goto(self.goto_input.clone());
                    }
                }
                Err(e) => self.error = Some(e),
            }
        }
    }

    /// Jump to an address: selects the containing function and syncs all views.
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
            self.current_fn = Some(f.entry);
            self.graph.selected_addr = Some(addr);
        }
    }

    fn decompiled(&mut self, p: &Project, f: &Function) -> &str {
        self.decomp_cache.entry(f.entry).or_insert_with(|| {
            let mut s = decompiler::decompile(f, p.binary.arch)
                .unwrap_or_else(|e| format!("// decompilation failed: {e}"));
            // Resolve call names.
            for c in &f.calls {
                if let Some(cf) = p.analysis.function(*c) {
                    s = s.replace(&format!("sub_{c:x}("), &format!("{}(", cf.name));
                }
            }
            s
        })
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_loading();

        // Drag & drop a file to open it.
        let dropped = ctx.input(|i| i.raw.dropped_files.first().and_then(|f| f.path.clone()));
        if let Some(path) = dropped {
            let s = path.display().to_string();
            self.path_input = s.clone();
            self.open(s);
        }
        // Esc = back (IDA-style).
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            if let Some(prev) = self.history.pop() {
                self.cursor = None;
                self.navigate(prev);
                self.history.pop();
            }
        }

        self.top_bar(ctx);
        self.status_bar(ctx);

        let Some(p) = self.project.clone() else {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.centered_and_justified(|ui| {
                    if self.loading.is_some() {
                        ui.spinner();
                        ui.label("Analysing…");
                    } else {
                        ui.label(
                            RichText::new("Open a PE / ELF / Mach-O binary (path above or drag & drop)")
                                .size(18.0),
                        );
                    }
                });
            });
            if self.loading.is_some() {
                ctx.request_repaint();
            }
            return;
        };

        self.side_panel(ctx, &p);
        if self.show_decompiler {
            self.decompiler_panel(ctx, &p);
        }
        egui::CentralPanel::default().show(ctx, |ui| self.central(ui, &p));
    }
}

impl App {
    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("rdisasm")
                        .strong()
                        .color(Color32::from_rgb(255, 160, 60)),
                );
                ui.separator();
                ui.label("File:");
                let r = ui.add(egui::TextEdit::singleline(&mut self.path_input).desired_width(380.0));
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.button("Open").clicked() || enter {
                    let p = self.path_input.trim().to_owned();
                    if !p.is_empty() {
                        self.open(p);
                    }
                }
                ui.separator();
                ui.label("Go to:");
                let g = ui.add(
                    egui::TextEdit::singleline(&mut self.goto_input)
                        .hint_text("0x401000 / name")
                        .desired_width(160.0),
                );
                if g.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.goto(self.goto_input.trim().to_owned());
                }
                ui.separator();
                ui.toggle_value(&mut self.show_decompiler, "Decompiler");
                if ui.button("⟲ Reset view").clicked() {
                    self.graph.reset_view();
                }
                if !self.history.is_empty() && ui.button("← Back").clicked() {
                    if let Some(prev) = self.history.pop() {
                        self.cursor = None;
                        self.navigate(prev);
                        self.history.pop();
                    }
                }
            });
        });
    }

    fn goto(&mut self, s: String) {
        let Some(p) = self.project.clone() else { return };
        let hex = s.trim_start_matches("0x").trim_start_matches("0X");
        if let Ok(a) = u64::from_str_radix(hex, 16) {
            if p.binary.memory.is_mapped(a) {
                self.navigate(a);
                return;
            }
        }
        if let Some(f) = p.analysis.functions().find(|f| f.name == s) {
            self.navigate(f.entry);
            return;
        }
        self.error = Some(format!("cannot resolve `{s}`"));
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(e) = &self.error {
                    ui.colored_label(Color32::from_rgb(240, 90, 90), e);
                    ui.separator();
                }
                if self.loading.is_some() {
                    ui.spinner();
                    ui.label("analysing…");
                }
                if let Some(p) = &self.project {
                    ui.label(format!(
                        "{}  ·  {:?} {:?}  ·  base {:#x}  ·  {} functions  ·  {} insns  ·  {} xrefs  ·  {} strings",
                        p.path,
                        p.binary.format,
                        p.binary.arch,
                        p.binary.image_base,
                        p.analysis.function_count(),
                        p.analysis.insn_count(),
                        p.analysis.xrefs.len(),
                        p.analysis.strings.len()
                    ));
                }
                if let Some(c) = self.cursor {
                    ui.separator();
                    ui.monospace(format!("cursor {c:#x}"));
                }
            });
        });
    }

    fn side_panel(&mut self, ctx: &egui::Context, p: &Arc<Project>) {
        egui::SidePanel::left("side")
            .default_width(300.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.side, SideList::Functions, "Functions");
                    ui.selectable_value(&mut self.side, SideList::Symbols, "Symbols");
                    ui.selectable_value(&mut self.side, SideList::Sections, "Sections");
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
                match self.side {
                    SideList::Functions => {
                        let funcs: Vec<&Function> = p
                            .analysis
                            .functions()
                            .filter(|f| {
                                needle.is_empty()
                                    || f.name.to_lowercase().contains(&needle)
                                    || format!("{:x}", f.entry).contains(&needle)
                            })
                            .collect();
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show_rows(ui, row_h, funcs.len(), |ui, range| {
                                for f in &funcs[range] {
                                    let sel = self.current_fn == Some(f.entry);
                                    let label =
                                        format!("{:08x}  {}  ({})", f.entry, f.name, f.cfg.block_count());
                                    if ui
                                        .selectable_label(sel, RichText::new(label).monospace())
                                        .clicked()
                                    {
                                        target = Some(f.entry);
                                    }
                                }
                            });
                    }
                    SideList::Symbols => {
                        let syms: Vec<_> = p
                            .binary
                            .symbols
                            .iter()
                            .filter(|s| needle.is_empty() || s.name.to_lowercase().contains(&needle))
                            .collect();
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show_rows(ui, row_h, syms.len(), |ui, range| {
                                for s in &syms[range] {
                                    let label = format!("{:08x}  {:?}  {}", s.addr, s.kind, s.name);
                                    if ui
                                        .selectable_label(false, RichText::new(label).monospace())
                                        .clicked()
                                    {
                                        target = Some(s.addr);
                                    }
                                }
                            });
                    }
                    SideList::Sections => {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                for s in p.binary.memory.sections() {
                                    let label =
                                        format!("{:<20} {:08x}-{:08x} {}", s.name, s.vaddr, s.end(), s.perms);
                                    if ui
                                        .selectable_label(false, RichText::new(label).monospace())
                                        .clicked()
                                    {
                                        target = Some(s.vaddr);
                                        self.tab = Tab::Hex;
                                    }
                                }
                            });
                    }
                }
                if let Some(t) = target {
                    self.navigate(t);
                }
            });
    }

    fn decompiler_panel(&mut self, ctx: &egui::Context, p: &Arc<Project>) {
        egui::SidePanel::right("decomp")
            .default_width(520.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.heading("Pseudocode");
                ui.separator();
                let Some(f) = self.current_fn.and_then(|e| p.analysis.function(e)) else {
                    ui.label("no function selected");
                    return;
                };
                let mut text = self.decompiled(p, f).to_owned();
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut text)
                                .code_editor()
                                .desired_width(f32::INFINITY)
                                .desired_rows(40),
                        );
                    });
                // User edits to the pseudocode are kept as annotations.
                if let Some(e) = self.current_fn {
                    self.decomp_cache.insert(e, text);
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
        });
        ui.separator();
        let func = self.current_fn.and_then(|e| p.analysis.function(e));
        match self.tab {
            Tab::Graph => match func {
                Some(f) => {
                    if let Some(a) = self.graph.ui(ui, f) {
                        self.cursor = Some(a);
                        self.hex_jump = true;
                    }
                }
                None => {
                    ui.label("no function at cursor");
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

    fn listing(&mut self, ui: &mut egui::Ui, p: &Arc<Project>, f: &Function) {
        let insns: Vec<_> = f.insns.values().collect();
        let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
        let mut target = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_h, insns.len(), |ui, range| {
                for insn in &insns[range] {
                    let sel = self.cursor == Some(insn.addr);
                    let bytes = p
                        .binary
                        .memory
                        .read(insn.addr, insn.len as usize)
                        .map(|b| b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" "))
                        .unwrap_or_default();
                    let leader = f.cfg.node_at(insn.addr).is_some();
                    let label = format!(
                        "{}{:016x}  {:<30} {}",
                        if leader { "▶ " } else { "  " },
                        insn.addr,
                        bytes,
                        insn.text
                    );
                    let r = ui.selectable_label(sel, RichText::new(label).monospace());
                    if r.clicked() {
                        self.cursor = Some(insn.addr);
                        self.graph.selected_addr = Some(insn.addr);
                        self.hex_jump = true;
                    }
                    if r.double_clicked() {
                        if let disasm_core::disasm::Flow::Call(t)
                        | disasm_core::disasm::Flow::CallNoReturn(t)
                        | disasm_core::disasm::Flow::Jump(t) = insn.flow
                        {
                            target = Some(t);
                        }
                    }
                }
            });
        if let Some(t) = target {
            self.navigate(t);
        }
    }

    fn strings(&mut self, ui: &mut egui::Ui, p: &Arc<Project>) {
        ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("🔍 filter strings…"));
        let needle = self.filter.to_lowercase();
        let list: Vec<_> = p
            .analysis
            .strings
            .iter()
            .filter(|s| needle.is_empty() || s.value.to_lowercase().contains(&needle))
            .collect();
        let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 4.0;
        let mut target = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_h, list.len(), |ui, range| {
                for s in &list[range] {
                    let refs = p.analysis.xrefs.refs_to(s.addr).len();
                    let label = format!(
                        "{:016x}  {:?}  [{} xrefs]  {:?}",
                        s.addr, s.encoding, refs, s.value
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
            ui.label("place the cursor on an address");
            return;
        };
        let mut target = None;
        ui.columns(2, |cols| {
            cols[0].heading(format!("References to {c:#x}"));
            for x in p.analysis.xrefs.refs_to(c).iter().chain(
                // also show refs to the current function entry
                self.current_fn
                    .filter(|e| *e != c)
                    .map(|e| p.analysis.xrefs.refs_to(e))
                    .unwrap_or_default()
                    .iter(),
            ) {
                let owner = p
                    .analysis
                    .function_containing(x.from)
                    .map_or("?".to_owned(), |f| f.name.clone());
                if cols[0]
                    .link(
                        RichText::new(format!("{:#x}  {:?}  in {} → {:#x}", x.from, x.kind, owner, x.to))
                            .monospace(),
                    )
                    .clicked()
                {
                    target = Some(x.from);
                }
            }
            cols[1].heading(format!("References from {c:#x}"));
            for x in p.analysis.xrefs.refs_from(c) {
                if cols[1]
                    .link(RichText::new(format!("{:#x}  {:?}", x.to, x.kind)).monospace())
                    .clicked()
                {
                    target = Some(x.to);
                }
            }
        });
        if let Some(t) = target {
            self.navigate(t);
        }
    }
}
