//#LinkerDriver:clang

// Tests linking with large __data section (many vtables, string constants,
// and data pointers). This exercises chained fixup rebase entries across
// multiple pages of the DATA segment.

use std::collections::HashMap;
use std::io::Write;

fn build_map() -> HashMap<String, Vec<u8>> {
    let mut map = HashMap::new();
    for i in 0..50 {
        let key = format!("key_{i:04}");
        let val: Vec<u8> = (0..100).map(|j| ((i * 7 + j * 3) % 256) as u8).collect();
        map.insert(key, val);
    }
    map
}

fn format_output(map: &HashMap<String, Vec<u8>>) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    for key in keys {
        let val = &map[key];
        writeln!(buf, "{}: {} bytes, sum={}", key, val.len(),
                 val.iter().map(|&b| b as u64).sum::<u64>()).unwrap();
    }
    buf
}

fn main() {
    let map = build_map();
    assert_eq!(map.len(), 50);

    let output = format_output(&map);
    assert!(output.len() > 1000);

    // Verify specific entries
    assert!(map.contains_key("key_0042"));
    assert_eq!(map["key_0000"].len(), 100);

    std::process::exit(42);
}
