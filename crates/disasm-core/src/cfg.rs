//! Basic-block construction and control-flow graphs (`petgraph::DiGraph`).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use petgraph::{
    algo::dominators::{self, Dominators},
    graph::{DiGraph, NodeIndex},
    visit::EdgeRef,
    Direction,
};
use serde::Serialize;

use crate::disasm::{Flow, Insn};

/// Kind of a CFG edge (drives GUI colouring: True=green, False=red, Unconditional=blue).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum EdgeKind {
    /// Conditional branch taken.
    True,
    /// Conditional branch not taken (fall-through).
    False,
    /// Unconditional jump.
    Unconditional,
    /// Implicit fall-through into a leader.
    Fallthrough,
    /// Edge out of an indirect jump / switch.
    Switch,
}

/// A maximal straight-line instruction sequence.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start: u64,
    /// Exclusive end address.
    pub end: u64,
    /// Instruction addresses in this block (index into the function's insn map).
    pub insns: Vec<u64>,
}

impl BasicBlock {
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

/// A function control-flow graph.
#[derive(Debug, Clone, Default)]
pub struct Cfg {
    pub graph: DiGraph<BasicBlock, EdgeKind>,
    pub entry: Option<NodeIndex>,
    index: HashMap<u64, NodeIndex>,
}

impl Cfg {
    /// Build a CFG from a function's instruction map.
    pub fn build(entry: u64, insns: &BTreeMap<u64, Insn>) -> Self {
        let leaders = Self::leaders(entry, insns);
        let mut cfg = Cfg::default();

        // 1. Carve blocks.
        let mut cur: Option<BasicBlock> = None;
        for (&addr, insn) in insns {
            let contiguous = cur.as_ref().is_some_and(|b| b.end == addr);
            if leaders.contains(&addr) || !contiguous {
                if let Some(b) = cur.take() {
                    cfg.push_block(b);
                }
                cur = Some(BasicBlock {
                    start: addr,
                    end: addr,
                    insns: Vec::new(),
                });
            }
            let b = cur.as_mut().expect("block opened above");
            b.insns.push(addr);
            b.end = insn.end();
            if insn.flow.ends_block() {
                cfg.push_block(cur.take().expect("current block"));
            }
        }
        if let Some(b) = cur.take() {
            cfg.push_block(b);
        }

        // 2. Wire edges.
        let nodes: Vec<NodeIndex> = cfg.graph.node_indices().collect();
        for n in nodes {
            let bb = &cfg.graph[n];
            let last = *bb.insns.last().expect("non-empty block");
            let end = bb.end;
            let flow = insns[&last].flow.clone();
            let mut edges: Vec<(u64, EdgeKind)> = Vec::new();
            match flow {
                Flow::CondJump(t) => {
                    edges.push((t, EdgeKind::True));
                    edges.push((end, EdgeKind::False));
                }
                Flow::Jump(t) => edges.push((t, EdgeKind::Unconditional)),
                Flow::IndirectJump(ts) => edges.extend(ts.into_iter().map(|t| (t, EdgeKind::Switch))),
                Flow::Return | Flow::Halt | Flow::CallNoReturn(_) => {}
                Flow::Sequential | Flow::Call(_) | Flow::IndirectCall => {
                    edges.push((end, EdgeKind::Fallthrough))
                }
            }
            for (to, kind) in edges {
                if let Some(&m) = cfg.index.get(&to) {
                    cfg.graph.add_edge(n, m, kind);
                }
            }
        }
        cfg.entry = cfg.index.get(&entry).copied();
        cfg
    }

    fn leaders(entry: u64, insns: &BTreeMap<u64, Insn>) -> BTreeSet<u64> {
        let mut l = BTreeSet::from([entry]);
        for insn in insns.values() {
            match &insn.flow {
                Flow::CondJump(t) => {
                    l.insert(*t);
                    l.insert(insn.end());
                }
                Flow::Jump(t) => {
                    l.insert(*t);
                    l.insert(insn.end());
                }
                Flow::IndirectJump(ts) => {
                    l.extend(ts.iter().copied());
                    l.insert(insn.end());
                }
                Flow::Return | Flow::Halt | Flow::CallNoReturn(_) => {
                    l.insert(insn.end());
                }
                _ => {}
            }
        }
        l
    }

    fn push_block(&mut self, b: BasicBlock) {
        let start = b.start;
        let n = self.graph.add_node(b);
        self.index.insert(start, n);
    }

    pub fn block_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Node whose block starts at `addr`.
    pub fn node_at(&self, addr: u64) -> Option<NodeIndex> {
        self.index.get(&addr).copied()
    }

    /// Node whose block contains `addr`.
    pub fn node_containing(&self, addr: u64) -> Option<NodeIndex> {
        self.graph.node_indices().find(|&n| self.graph[n].contains(addr))
    }

    pub fn block(&self, n: NodeIndex) -> &BasicBlock {
        &self.graph[n]
    }

    pub fn successors(&self, n: NodeIndex) -> impl Iterator<Item = (NodeIndex, EdgeKind)> + '_ {
        self.graph
            .edges_directed(n, Direction::Outgoing)
            .map(|e| (e.target(), *e.weight()))
    }

    pub fn predecessors(&self, n: NodeIndex) -> impl Iterator<Item = NodeIndex> + '_ {
        self.graph.neighbors_directed(n, Direction::Incoming)
    }

    /// Dominator tree rooted at the entry block.
    pub fn dominators(&self) -> Option<Dominators<NodeIndex>> {
        self.entry.map(|e| dominators::simple_fast(&self.graph, e))
    }

    /// Back edges `(latch, header)` — the target dominates the source.
    pub fn back_edges(&self) -> Vec<(NodeIndex, NodeIndex)> {
        let Some(dom) = self.dominators() else {
            return Vec::new();
        };
        self.graph
            .edge_references()
            .filter(|e| {
                dom.dominators(e.source())
                    .is_some_and(|mut it| it.any(|d| d == e.target()))
            })
            .map(|e| (e.source(), e.target()))
            .collect()
    }

    /// Cyclomatic complexity `E - N + 2`.
    pub fn cyclomatic_complexity(&self) -> usize {
        (self.edge_count() + 2).saturating_sub(self.block_count())
    }

    /// Graphviz DOT export.
    pub fn to_dot(&self, insns: &BTreeMap<u64, Insn>) -> String {
        use std::fmt::Write;
        let mut s = String::from("digraph cfg {\n  node [shape=box fontname=\"monospace\"];\n");
        for n in self.graph.node_indices() {
            let b = &self.graph[n];
            let mut label = format!("{:#x}:\\l", b.start);
            for a in &b.insns {
                let t = insns[a].text.replace('"', "\\\"");
                let _ = write!(label, "{a:#x}  {t}\\l");
            }
            let _ = writeln!(s, "  n{} [label=\"{}\"];", n.index(), label);
        }
        for e in self.graph.edge_references() {
            let color = match e.weight() {
                EdgeKind::True => "green",
                EdgeKind::False => "red",
                EdgeKind::Unconditional => "blue",
                EdgeKind::Fallthrough => "gray",
                EdgeKind::Switch => "purple",
            };
            let _ = writeln!(
                s,
                "  n{} -> n{} [color={color}];",
                e.source().index(),
                e.target().index()
            );
        }
        s.push_str("}\n");
        s
    }
}
