//! Interactive control-flow graph canvas: layered layout, draggable nodes,
//! smooth pan / zoom and colour-coded edges
//! (True = green, False = red, Unconditional = blue).

use std::collections::{HashMap, VecDeque};

use disasm_core::{analysis::Function, cfg::EdgeKind};
use egui::{Color32, FontId, Pos2, Rect, Sense, Stroke, Vec2};
use petgraph::{graph::NodeIndex, visit::EdgeRef};

const LINE_H: f32 = 15.0;
const CHAR_W: f32 = 7.4;
const PAD: f32 = 8.0;
const H_GAP: f32 = 50.0;
const V_GAP: f32 = 60.0;

/// Per-function graph view state.
#[derive(Debug, Default)]
pub struct GraphView {
    pub func: Option<u64>,
    /// Node top-left positions in graph space.
    pos: HashMap<NodeIndex, Pos2>,
    size: HashMap<NodeIndex, Vec2>,
    lines: HashMap<NodeIndex, Vec<String>>,
    pan: Vec2,
    zoom: f32,
    pub selected_addr: Option<u64>,
}

pub fn edge_color(k: EdgeKind) -> Color32 {
    match k {
        EdgeKind::True => Color32::from_rgb(60, 200, 90),
        EdgeKind::False => Color32::from_rgb(230, 70, 70),
        EdgeKind::Unconditional => Color32::from_rgb(80, 140, 255),
        EdgeKind::Fallthrough => Color32::from_rgb(140, 140, 150),
        EdgeKind::Switch => Color32::from_rgb(190, 110, 230),
    }
}

impl GraphView {
    /// (Re)build the layout for `f` if it changed.
    pub fn set_function(&mut self, f: &Function) {
        if self.func == Some(f.entry) {
            return;
        }
        self.func = Some(f.entry);
        self.pos.clear();
        self.size.clear();
        self.lines.clear();
        self.zoom = 1.0;
        self.pan = Vec2::new(40.0, 40.0);

        let g = &f.cfg.graph;
        for n in g.node_indices() {
            let bb = &g[n];
            let mut lines = vec![format!("loc_{:x}:", bb.start)];
            lines.extend(bb.insns.iter().map(|a| format!("{a:08x}  {}", f.insns[a].text)));
            let w = lines.iter().map(|l| l.len()).max().unwrap_or(10) as f32 * CHAR_W + 2.0 * PAD;
            let h = lines.len() as f32 * LINE_H + 2.0 * PAD;
            self.size.insert(n, Vec2::new(w, h));
            self.lines.insert(n, lines);
        }

        // Layer assignment: BFS depth from the entry, ignoring back edges.
        let Some(entry) = f.cfg.entry else { return };
        let back: std::collections::HashSet<(NodeIndex, NodeIndex)> =
            f.cfg.back_edges().into_iter().collect();
        let mut layer: HashMap<NodeIndex, usize> = HashMap::new();
        let mut indeg: HashMap<NodeIndex, usize> = HashMap::new();
        for e in g.edge_references() {
            if !back.contains(&(e.source(), e.target())) && e.source() != e.target() {
                *indeg.entry(e.target()).or_default() += 1;
            }
        }
        // Longest-path layering over the DAG (Kahn order).
        let mut q = VecDeque::from([entry]);
        layer.insert(entry, 0);
        let mut remaining = indeg.clone();
        while let Some(n) = q.pop_front() {
            let ln = layer[&n];
            for e in g.edges(n) {
                let t = e.target();
                if back.contains(&(n, t)) || t == n {
                    continue;
                }
                let l = layer.entry(t).or_insert(0);
                *l = (*l).max(ln + 1);
                if let Some(r) = remaining.get_mut(&t) {
                    *r -= 1;
                    if *r == 0 {
                        q.push_back(t);
                    }
                }
            }
        }
        // Unreached nodes (irreducible regions) go to the bottom.
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
            let total_w: f32 = row.iter().map(|n| self.size[n].x).sum::<f32>()
                + H_GAP * (row.len().saturating_sub(1)) as f32;
            let mut x = -total_w / 2.0;
            let mut row_h: f32 = 0.0;
            for n in row {
                self.pos.insert(*n, Pos2::new(x, y));
                x += self.size[n].x + H_GAP;
                row_h = row_h.max(self.size[n].y);
            }
            y += row_h + V_GAP;
        }
    }

    pub fn reset_view(&mut self) {
        self.zoom = 1.0;
        self.pan = Vec2::new(40.0, 40.0);
    }

    /// Draw the graph. Returns an instruction address the user clicked, if any.
    pub fn ui(&mut self, ui: &mut egui::Ui, f: &Function) -> Option<u64> {
        self.set_function(f);
        let (canvas, resp) = ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());
        let painter = ui.painter_at(canvas);
        painter.rect_filled(canvas, 0.0, Color32::from_rgb(24, 26, 31));

        // Pan with background drag; zoom with ctrl/cmd + wheel or pinch around cursor.
        if resp.dragged() {
            self.pan += resp.drag_delta();
        }
        if resp.hovered() {
            let (scroll, pinch, hover) =
                ui.input(|i| (i.raw_scroll_delta, i.zoom_delta(), i.pointer.hover_pos()));
            // Mouse wheel zooms (IDA-style); pinch gestures are honoured too.
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
        let origin = canvas.min + self.pan + Vec2::new(canvas.width() / 2.0, 0.0);
        let z = self.zoom;
        let to_screen = |p: Pos2| origin + p.to_vec2() * z;

        // Edges first (behind nodes): orthogonal-ish polyline with an arrow head.
        for e in f.cfg.graph.edge_references() {
            let (s, t) = (e.source(), e.target());
            let (Some(&ps), Some(&pt)) = (self.pos.get(&s), self.pos.get(&t)) else {
                continue;
            };
            let (ss, st) = (self.size[&s], self.size[&t]);
            let a = to_screen(Pos2::new(ps.x + ss.x / 2.0, ps.y + ss.y));
            let b = to_screen(Pos2::new(pt.x + st.x / 2.0, pt.y));
            let color = edge_color(*e.weight());
            let stroke = Stroke::new(1.6 * z.max(0.5), color);
            if pt.y > ps.y {
                let mid = (a.y + b.y) / 2.0;
                painter.line_segment([a, Pos2::new(a.x, mid)], stroke);
                painter.line_segment([Pos2::new(a.x, mid), Pos2::new(b.x, mid)], stroke);
                painter.line_segment([Pos2::new(b.x, mid), b], stroke);
            } else {
                // Back edge: route around the right side.
                let right = to_screen(Pos2::new(ps.x.max(pt.x) + ss.x.max(st.x) + 20.0, 0.0)).x;
                let a2 = Pos2::new(a.x, a.y + 12.0 * z);
                let b2 = Pos2::new(b.x, b.y - 12.0 * z);
                for seg in [
                    [a, a2],
                    [a2, Pos2::new(right, a2.y)],
                    [Pos2::new(right, a2.y), Pos2::new(right, b2.y)],
                    [Pos2::new(right, b2.y), b2],
                    [b2, b],
                ] {
                    painter.line_segment(seg, stroke);
                }
            }
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

        // Nodes.
        let mut clicked = None;
        let font = FontId::monospace(12.0 * z);
        let nodes: Vec<NodeIndex> = f.cfg.graph.node_indices().collect();
        for n in nodes {
            let (Some(&p), Some(&sz)) = (self.pos.get(&n), self.size.get(&n)) else {
                continue;
            };
            let rect = Rect::from_min_size(to_screen(p), sz * z);
            if !canvas.intersects(rect) {
                continue;
            }
            let id = ui.id().with(("cfg_node", f.entry, n.index()));
            let r = ui.interact(rect, id, Sense::click_and_drag());
            if r.dragged() {
                if let Some(pp) = self.pos.get_mut(&n) {
                    *pp += r.drag_delta() / z;
                }
            }
            let is_entry = Some(n) == f.cfg.entry;
            let bb = &f.cfg.graph[n];
            let selected = self.selected_addr.is_some_and(|a| bb.contains(a));
            let fill = if is_entry {
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
            if z > 0.25 {
                for (i, line) in self.lines[&n].iter().enumerate() {
                    let pos = rect.min + Vec2::new(PAD, PAD + i as f32 * LINE_H) * z;
                    let col = if i == 0 {
                        Color32::from_rgb(120, 190, 255)
                    } else {
                        Color32::from_gray(215)
                    };
                    painter.text(pos, egui::Align2::LEFT_TOP, line, font.clone(), col);
                }
            }
            if r.clicked() {
                // Map click height to an instruction line.
                if let Some(ptr) = r.interact_pointer_pos() {
                    let line = ((ptr.y - rect.min.y) / z - PAD) / LINE_H;
                    let idx = line.floor() as isize - 1;
                    let a = if idx >= 0 {
                        bb.insns.get(idx as usize).copied()
                    } else {
                        None
                    };
                    clicked = Some(a.unwrap_or(bb.start));
                }
            }
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
                "{} blocks · {} edges · zoom {:.0}%  (drag = pan, wheel = zoom, drag node = move)",
                f.cfg.block_count(),
                f.cfg.edge_count(),
                self.zoom * 100.0
            ),
            FontId::proportional(12.0),
            Color32::from_gray(150),
        );
        if clicked.is_some() {
            self.selected_addr = clicked;
        }
        clicked
    }
}
