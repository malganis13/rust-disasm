//! Interactive control-flow graph (IDA "graph view").
//!
//! * layered layout, draggable nodes, pan (drag background) and zoom (wheel)
//! * edges: green = taken, red = not taken, blue = unconditional, purple = switch
//! * **edges are clickable**: hover highlights, click jumps to the other end
//! * the view can be centred on any address (navigation sync)

use std::collections::{HashMap, HashSet, VecDeque};

use disasm_core::{analysis::Function, cfg::EdgeKind, disasm::Insn};
use egui::{Color32, FontId, Pos2, Rect, Response, Sense, Stroke, Vec2};
use petgraph::{graph::NodeIndex, visit::EdgeRef};

const LINE_H: f32 = 15.0;
const CHAR_W: f32 = 7.4;
const PAD: f32 = 8.0;
const H_GAP: f32 = 50.0;
const V_GAP: f32 = 60.0;

pub fn edge_color(k: EdgeKind) -> Color32 {
    match k {
        EdgeKind::True => Color32::from_rgb(60, 200, 90),
        EdgeKind::False => Color32::from_rgb(230, 70, 70),
        EdgeKind::Unconditional => Color32::from_rgb(80, 140, 255),
        EdgeKind::Fallthrough => Color32::from_rgb(140, 140, 150),
        EdgeKind::Switch => Color32::from_rgb(190, 110, 230),
    }
}

/// What happened in the graph this frame.
#[derive(Default)]
pub struct GraphOut {
    /// Instruction clicked (single click).
    pub clicked: Option<u64>,
    /// Instruction double-clicked (follow operand).
    pub activated: Option<u64>,
    /// Node responses with the instruction under the pointer (for context menus).
    pub nodes: Vec<(Response, u64)>,
}

#[derive(Debug, Default)]
pub struct GraphView {
    func: Option<u64>,
    pos: HashMap<NodeIndex, Pos2>,
    size: HashMap<NodeIndex, Vec2>,
    lines: HashMap<NodeIndex, Vec<String>>,
    pan: Vec2,
    zoom: f32,
    pub selected_addr: Option<u64>,
    focus: Option<u64>,
    /// Last instruction under the pointer per node (for context menus).
    hover_insn: HashMap<NodeIndex, u64>,
    dirty: bool,
}

fn seg_dist(p: Pos2, a: Pos2, b: Pos2) -> f32 {
    let ab = b - a;
    let t = ((p - a).dot(ab) / ab.length_sq().max(1e-6)).clamp(0.0, 1.0);
    (a + ab * t - p).length()
}

impl GraphView {
    /// Force a rebuild (e.g. after a rename changed operand text).
    pub fn invalidate(&mut self) {
        self.dirty = true;
    }

    /// Centre the view on the block containing `addr` on the next frame.
    pub fn focus_on(&mut self, addr: u64) {
        self.focus = Some(addr);
        self.selected_addr = Some(addr);
    }

    pub fn reset_view(&mut self) {
        self.zoom = 1.0;
        self.pan = Vec2::new(40.0, 40.0);
    }

    fn rebuild(&mut self, f: &Function, title: &str, fmt: &mut dyn FnMut(&Insn) -> String) {
        self.dirty = false;
        let same = self.func == Some(f.entry);
        self.func = Some(f.entry);
        self.size.clear();
        self.lines.clear();
        if !same {
            self.pos.clear();
            self.zoom = 1.0;
            self.pan = Vec2::new(40.0, 40.0);
        }
        let g = &f.cfg.graph;
        for n in g.node_indices() {
            let bb = &g[n];
            let mut lines = vec![if bb.start == f.entry {
                format!("{title}:")
            } else {
                format!("loc_{:X}:", bb.start)
            }];
            lines.extend(bb.insns.iter().map(|a| fmt(&f.insns[a])));
            let w = lines.iter().map(|l| l.chars().count()).max().unwrap_or(10) as f32 * CHAR_W + 2.0 * PAD;
            let h = lines.len() as f32 * LINE_H + 2.0 * PAD;
            self.size.insert(n, Vec2::new(w, h));
            self.lines.insert(n, lines);
        }
        if same && !self.pos.is_empty() {
            return;
        }
        self.layout(f);
    }

    fn layout(&mut self, f: &Function) {
        let g = &f.cfg.graph;
        let Some(entry) = f.cfg.entry else { return };
        let back: HashSet<(NodeIndex, NodeIndex)> = f.cfg.back_edges().into_iter().collect();
        let mut indeg: HashMap<NodeIndex, usize> = HashMap::new();
        for e in g.edge_references() {
            if !back.contains(&(e.source(), e.target())) && e.source() != e.target() {
                *indeg.entry(e.target()).or_default() += 1;
            }
        }
        let mut layer: HashMap<NodeIndex, usize> = HashMap::from([(entry, 0)]);
        let mut q = VecDeque::from([entry]);
        while let Some(n) = q.pop_front() {
            let ln = layer[&n];
            for e in g.edges(n) {
                let t = e.target();
                if back.contains(&(n, t)) || t == n {
                    continue;
                }
                let l = layer.entry(t).or_insert(0);
                *l = (*l).max(ln + 1);
                if let Some(r) = indeg.get_mut(&t) {
                    *r -= 1;
                    if *r == 0 {
                        q.push_back(t);
                    }
                }
            }
        }
        let max_layer = layer.values().copied().max().unwrap_or(0);
        for n in g.node_indices() {
            layer.entry(n).or_insert(max_layer + 1);
        }
        let mut rows: Vec<Vec<NodeIndex>> = vec![Vec::new(); max_layer + 2];
        let mut order: Vec<NodeIndex> = g.node_indices().collect();
        order.sort_by_key(|n| g[*n].start);
        for n in order {
            rows[layer[&n]].push(n);
        }
        let mut y = 0.0;
        for row in rows.iter().filter(|r| !r.is_empty()) {
            let total: f32 = row.iter().map(|n| self.size[n].x).sum::<f32>()
                + H_GAP * (row.len().saturating_sub(1)) as f32;
            let mut x = -total / 2.0;
            let mut row_h: f32 = 0.0;
            for n in row {
                self.pos.insert(*n, Pos2::new(x, y));
                x += self.size[n].x + H_GAP;
                row_h = row_h.max(self.size[n].y);
            }
            y += row_h + V_GAP;
        }
    }

    /// Polyline of an edge in graph space.
    fn edge_points(&self, s: NodeIndex, t: NodeIndex) -> Option<Vec<Pos2>> {
        let (ps, pt) = (*self.pos.get(&s)?, *self.pos.get(&t)?);
        let (ss, st) = (self.size[&s], self.size[&t]);
        let a = Pos2::new(ps.x + ss.x / 2.0, ps.y + ss.y);
        let b = Pos2::new(pt.x + st.x / 2.0, pt.y);
        Some(if pt.y > ps.y {
            let mid = (a.y + b.y) / 2.0;
            vec![a, Pos2::new(a.x, mid), Pos2::new(b.x, mid), b]
        } else {
            let right = ps.x.max(pt.x) + ss.x.max(st.x) + 20.0;
            vec![
                a,
                Pos2::new(a.x, a.y + 12.0),
                Pos2::new(right, a.y + 12.0),
                Pos2::new(right, b.y - 12.0),
                Pos2::new(b.x, b.y - 12.0),
                b,
            ]
        })
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        f: &Function,
        title: &str,
        fmt: &mut dyn FnMut(&Insn) -> String,
    ) -> GraphOut {
        if self.func != Some(f.entry) || self.lines.is_empty() || self.dirty {
            self.rebuild(f, title, fmt);
        }
        let mut out = GraphOut::default();
        let (canvas, resp) = ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());
        let painter = ui.painter_at(canvas);
        painter.rect_filled(canvas, 0.0, Color32::from_rgb(24, 26, 31));

        if resp.dragged() {
            self.pan += resp.drag_delta();
        }
        if resp.hovered() {
            let (scroll, pinch, hover) =
                ui.input(|i| (i.raw_scroll_delta, i.zoom_delta(), i.pointer.hover_pos()));
            let factor = if pinch != 1.0 {
                pinch
            } else {
                (1.0 + scroll.y * 0.0015).clamp(0.8, 1.25)
            };
            if factor != 1.0 {
                if let Some(h) = hover {
                    let old = self.zoom;
                    self.zoom = (self.zoom * factor).clamp(0.1, 4.0);
                    let anchor = h - canvas.min;
                    self.pan = anchor - (anchor - self.pan) * (self.zoom / old);
                }
            }
        }

        // Centre on a requested address.
        if let Some(a) = self.focus.take() {
            if let Some(n) = f.cfg.node_containing(a) {
                if let (Some(p), Some(s)) = (self.pos.get(&n), self.size.get(&n)) {
                    let c = *p + *s / 2.0;
                    self.pan = canvas.center()
                        - canvas.min
                        - Vec2::new(canvas.width() / 2.0, 0.0)
                        - c.to_vec2() * self.zoom;
                }
            }
        }

        let origin = canvas.min + self.pan + Vec2::new(canvas.width() / 2.0, 0.0);
        let z = self.zoom;
        let to_screen = |p: Pos2| origin + p.to_vec2() * z;
        let pointer = ui.input(|i| i.pointer.hover_pos());

        // Edges: find hovered one first.
        let mut hovered_edge: Option<(NodeIndex, NodeIndex)> = None;
        let mut edges = Vec::new();
        for e in f.cfg.graph.edge_references() {
            let Some(pts) = self.edge_points(e.source(), e.target()) else {
                continue;
            };
            let pts: Vec<Pos2> = pts.into_iter().map(to_screen).collect();
            if let Some(p) = pointer.filter(|p| canvas.contains(*p)) {
                if pts.windows(2).any(|w| seg_dist(p, w[0], w[1]) < 5.0) {
                    hovered_edge = Some((e.source(), e.target()));
                }
            }
            edges.push((e.source(), e.target(), *e.weight(), pts));
        }
        for (s, t, k, pts) in &edges {
            let hot = hovered_edge == Some((*s, *t));
            let color = if hot {
                Color32::from_rgb(255, 220, 90)
            } else {
                edge_color(*k)
            };
            let stroke = Stroke::new(if hot { 3.0_f32 } else { 1.6 * z.max(0.5) }, color);
            for w in pts.windows(2) {
                painter.line_segment([w[0], w[1]], stroke);
            }
            let b = *pts.last().expect("edge has points");
            let h = 6.0 * z.max(0.5);
            painter.add(egui::Shape::convex_polygon(
                vec![
                    b,
                    Pos2::new(b.x - h, b.y - h * 1.5),
                    Pos2::new(b.x + h, b.y - h * 1.5),
                ],
                color,
                Stroke::NONE,
            ));
        }
        if let Some((s, t)) = hovered_edge {
            let (from, to) = (f.cfg.graph[s].start, f.cfg.graph[t].start);
            let resp = resp.clone().on_hover_text(format!(
                "loc_{from:X} → loc_{to:X}\nclick: jump to target · shift+click: jump to source"
            ));
            if resp.clicked() {
                let shift = ui.input(|i| i.modifiers.shift);
                let dst = if shift { from } else { to };
                self.focus_on(dst);
                out.clicked = Some(dst);
            }
        }

        // Nodes.
        let font = FontId::monospace(12.0 * z);
        for n in f.cfg.graph.node_indices() {
            let (Some(&p), Some(&sz)) = (self.pos.get(&n), self.size.get(&n)) else {
                continue;
            };
            let rect = Rect::from_min_size(to_screen(p), sz * z);
            if !canvas.intersects(rect) {
                continue;
            }
            let r = ui.interact(
                rect,
                ui.id().with(("cfg_node", f.entry, n.index())),
                Sense::click_and_drag(),
            );
            if r.dragged() {
                if let Some(pp) = self.pos.get_mut(&n) {
                    *pp += r.drag_delta() / z;
                }
            }
            let bb = &f.cfg.graph[n];
            let selected = self.selected_addr.is_some_and(|a| bb.contains(a));
            let fill = if bb.start == f.entry {
                Color32::from_rgb(44, 52, 70)
            } else {
                Color32::from_rgb(38, 41, 48)
            };
            let border = if selected {
                Stroke::new(2.0_f32, Color32::from_rgb(255, 200, 60))
            } else if r.hovered() {
                Stroke::new(1.5_f32, Color32::from_gray(200))
            } else {
                Stroke::new(1.0_f32, Color32::from_gray(90))
            };
            painter.rect(rect, 4.0 * z, fill, border);

            // Instruction under the pointer.
            let line_at = |y: f32| -> Option<u64> {
                let idx = (((y - rect.min.y) / z - PAD) / LINE_H).floor() as isize - 1;
                if idx < 0 {
                    Some(bb.start)
                } else {
                    bb.insns.get(idx as usize).copied()
                }
            };
            if let Some(pp) = pointer.filter(|pp| rect.contains(*pp)) {
                if let Some(a) = line_at(pp.y) {
                    self.hover_insn.insert(n, a);
                }
            }
            if z > 0.25 {
                for (i, line) in self.lines[&n].iter().enumerate() {
                    let pos = rect.min + Vec2::new(PAD, PAD + i as f32 * LINE_H) * z;
                    let addr = if i == 0 {
                        None
                    } else {
                        bb.insns.get(i - 1).copied()
                    };
                    if addr.is_some() && addr == self.selected_addr {
                        painter.rect_filled(
                            Rect::from_min_size(pos - Vec2::new(2.0, 0.0), Vec2::new(sz.x - PAD, LINE_H) * z),
                            0.0,
                            Color32::from_rgb(60, 70, 95),
                        );
                    }
                    let col = if i == 0 {
                        Color32::from_rgb(120, 190, 255)
                    } else {
                        Color32::from_gray(215)
                    };
                    painter.text(pos, egui::Align2::LEFT_TOP, line, font.clone(), col);
                }
            }
            let under = self.hover_insn.get(&n).copied().unwrap_or(bb.start);
            if r.clicked() || r.secondary_clicked() {
                self.selected_addr = Some(under);
                out.clicked = Some(under);
            }
            if r.double_clicked() {
                out.activated = Some(under);
            }
            out.nodes.push((r, under));
        }

        painter.rect_filled(
            Rect::from_min_max(
                canvas.left_bottom() + Vec2::new(0.0, -26.0),
                canvas.right_bottom(),
            ),
            0.0,
            Color32::from_rgba_unmultiplied(18, 19, 23, 235),
        );
        painter.text(
            canvas.left_bottom() + Vec2::new(8.0, -8.0),
            egui::Align2::LEFT_BOTTOM,
            format!(
                "{} blocks · {} edges · {:.0}%   drag = pan · wheel = zoom · click edge = follow · dbl-click = jump · RMB = menu · Space = text view",
                f.cfg.block_count(),
                f.cfg.edge_count(),
                self.zoom * 100.0
            ),
            FontId::proportional(12.0),
            Color32::from_gray(150),
        );
        out
    }
}
