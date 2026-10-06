// Find strings mentioning a keyword and list the code that references them.
let needle = "error";
for s in bin.strings() {
    if s.value.to_lower().contains(needle) {
        for x in bin.xrefs_to(s.addr) {
            print(`${hex(x.from)} -> ${hex(s.addr)}  "${s.value}"`);
        }
    }
}
