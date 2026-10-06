// Rhai plugin example: report the most complex functions and their callers.
//   rdisasm script <binary> examples/hotspots.rhai

let funcs = bin.functions();
funcs.sort(|a, b| b.complexity - a.complexity);

print(`${bin.format} ${bin.arch}  entry=${hex(bin.entry)}  functions=${funcs.len()}`);
print("top 10 by cyclomatic complexity:");
for f in funcs.extract(0, 10) {
    let callers = bin.xrefs_to(f.entry).len();
    print(`  ${hex(f.entry)}  cc=${f.complexity}  blocks=${f.blocks}  callers=${callers}  ${f.name}`);
}
