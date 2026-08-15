//! Builds a Mach-O exports trie.

use leb128::write::unsigned_len as uleb128_size;
use object::macho;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Symbol<'data> {
    pub(crate) name: &'data [u8],
    pub(crate) address: u64,
    pub(crate) flags: macho::ExportSymbolFlags,
}

#[derive(Debug, Default)]
struct Node {
    address: Option<u64>,
    flags: macho::ExportSymbolFlags,
    first_edge: usize,
    num_edges: usize,
    offset: usize,
    size: usize,
}

#[derive(Debug, Default)]
struct Edge<'data> {
    label: &'data [u8],
    child: usize,
    child_offset_size: usize,
}

#[derive(Debug, Default)]
struct UncompressedNode {
    symbol: Option<usize>,
    representative: usize,
    depth: usize,
    children: Vec<usize>,
}

/// Build a Mach-O exports trie for `symbols`. `symbols` is sorted in place.
pub(crate) fn build(symbols: &mut [Symbol<'_>]) -> Vec<u8> {
    if symbols.is_empty() {
        return Vec::new();
    }

    symbols.sort_unstable_by(|a, b| a.name.cmp(b.name));
    debug_assert!(
        symbols.windows(2).all(|w| w[0].name != w[1].name),
        "duplicate Mach-O export symbol names"
    );

    let mut builder = Builder {
        symbols,
        nodes: Vec::with_capacity(symbols.len() + 1),
        edges: Vec::with_capacity(symbols.len()),
    };
    builder.build_nodes();
    builder.layout_until_stable();
    builder.encode()
}

struct Builder<'data, 'symbols> {
    symbols: &'symbols [Symbol<'data>],
    nodes: Vec<Node>,
    edges: Vec<Edge<'data>>,
}

impl<'data> Builder<'data, '_> {
    fn build_nodes(&mut self) {
        let mut uncompressed = vec![UncompressedNode::default()];
        let mut previous_name = &[][..];
        let mut previous_path = vec![0];

        for (symbol_index, symbol) in self.symbols.iter().enumerate() {
            let common_prefix = previous_name
                .iter()
                .zip(symbol.name)
                .take_while(|(a, b)| a == b)
                .count();

            previous_path.truncate(common_prefix + 1);
            let mut parent = *previous_path.last().unwrap();

            for depth in common_prefix + 1..=symbol.name.len() {
                let child = uncompressed.len();

                uncompressed.push(UncompressedNode {
                    representative: symbol_index,
                    depth,
                    ..Default::default()
                });

                uncompressed[parent].children.push(child);
                previous_path.push(child);
                parent = child;
            }

            uncompressed[parent].symbol.replace(symbol_index);
            previous_name = symbol.name;
        }

        let mut pending: Vec<(usize, Option<usize>)> = vec![(0, None)];
        while let Some((uncompressed_index, parent_edge)) = pending.pop() {
            let source = &uncompressed[uncompressed_index];
            let node_index = self.nodes.len();
            if let Some(edge_index) = parent_edge {
                self.edges[edge_index].child = node_index;
            }

            let (address, flags) = source
                .symbol
                .map_or((None, macho::ExportSymbolFlags(0)), |i| {
                    (Some(self.symbols[i].address), self.symbols[i].flags)
                });

            let first_edge = self.edges.len();
            debug_assert!(
                u8::try_from(source.children.len()).is_ok(),
                "Mach-O exports trie node has too many children"
            );

            self.nodes.push(Node {
                address,
                flags,
                first_edge,
                num_edges: source.children.len(),
                ..Default::default()
            });

            for &first_child in &source.children {
                let mut child = first_child;

                while uncompressed[child].symbol.is_none()
                    && uncompressed[child].children.len() == 1
                {
                    child = uncompressed[child].children[0];
                }

                let child_node = &uncompressed[child];

                self.edges.push(Edge {
                    label: &self.symbols[child_node.representative].name
                        [source.depth..child_node.depth],
                    child: usize::MAX,
                    child_offset_size: 1,
                });
            }
            for (edge_offset, &first_child) in source.children.iter().enumerate().rev() {
                let mut child = first_child;

                while uncompressed[child].symbol.is_none()
                    && uncompressed[child].children.len() == 1
                {
                    child = uncompressed[child].children[0];
                }

                pending.push((child, Some(first_edge + edge_offset)));
            }
        }
    }

    fn layout_until_stable(&mut self) {
        loop {
            let mut offset = 0;

            for index in 0..self.nodes.len() {
                self.nodes[index].offset = offset;
                self.nodes[index].size = self.node_size(index);
                offset += self.nodes[index].size;
            }

            let mut changed = false;

            for edge in &mut self.edges {
                let offset_size = uleb128_size(self.nodes[edge.child].offset as u64);
                if edge.child_offset_size != offset_size {
                    edge.child_offset_size = offset_size;
                    changed = true;
                }
            }

            if !changed {
                break;
            }
        }
    }

    fn node_size(&self, node_index: usize) -> usize {
        let node = &self.nodes[node_index];
        let terminal_size = node
            .address
            .map_or(0, |address| regular_export_size(node.flags, address));
        uleb128_size(terminal_size as u64)
            + terminal_size
            + 1
            + self
                .node_edges(node_index)
                .map(|edge| edge.label.len() + 1 + edge.child_offset_size)
                .sum::<usize>()
    }

    fn encode(&self) -> Vec<u8> {
        let total_size = self.nodes.last().map_or(0, |node| node.offset + node.size);
        let mut out = Vec::with_capacity(total_size);

        for (node_index, node) in self.nodes.iter().enumerate() {
            debug_assert_eq!(out.len(), node.offset);

            if let Some(address) = node.address {
                write_uleb128(&mut out, regular_export_size(node.flags, address) as u64);
                write_regular_export(&mut out, node.flags, address);
            } else {
                write_uleb128(&mut out, 0);
            }

            out.push(node.num_edges as u8);

            for edge in self.node_edges(node_index) {
                out.extend_from_slice(edge.label);
                out.push(0);
                write_uleb128(&mut out, self.nodes[edge.child].offset as u64);
            }
        }

        debug_assert_eq!(out.len(), total_size);
        out
    }

    fn node_edges(&self, node_index: usize) -> impl Iterator<Item = &Edge<'data>> {
        let node = &self.nodes[node_index];
        self.edges[node.first_edge..node.first_edge + node.num_edges].iter()
    }
}

fn regular_export_size(flags: macho::ExportSymbolFlags, address: u64) -> usize {
    uleb128_size(flags.0) + uleb128_size(address)
}

fn write_regular_export(out: &mut Vec<u8>, flags: macho::ExportSymbolFlags, address: u64) {
    write_uleb128(out, flags.0);
    write_uleb128(out, address);
}

fn write_uleb128(out: &mut Vec<u8>, value: u64) {
    leb128::write::unsigned(out, value).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use object::LittleEndian;
    use object::macho;
    use object::read::macho::ExportData;

    #[derive(Debug, PartialEq, Eq)]
    struct ParsedSymbol {
        name: Vec<u8>,
        address: u64,
        flags: macho::ExportSymbolFlags,
    }

    fn check(symbols: &mut [Symbol]) {
        let trie = build(symbols);

        assert_eq!(
            parse_exports(&trie),
            symbols
                .iter()
                .map(|s| ParsedSymbol {
                    name: s.name.to_owned(),
                    address: s.address,
                    flags: s.flags,
                })
                .collect_vec()
        );
    }

    fn parse_exports(data: &[u8]) -> Vec<ParsedSymbol> {
        if data.is_empty() {
            return Vec::new();
        }

        let command = macho::LinkeditDataCommand {
            cmd: macho::LC_DYLD_EXPORTS_TRIE.into(),
            cmdsize: (size_of::<macho::LinkeditDataCommand<object::Endianness>>() as u32).into(),
            dataoff: 0.into(),
            datasize: (data.len() as u32).into(),
        };

        command
            .exports_trie(LittleEndian, data)
            .unwrap()
            .map(|symbol| {
                let symbol = symbol.unwrap();
                let ExportData::Regular { address } = symbol.data() else {
                    panic!("expected regular export");
                };
                ParsedSymbol {
                    name: symbol.name().to_vec(),
                    address: *address,
                    flags: symbol.flags(),
                }
            })
            .collect()
    }

    #[test]
    fn empty_input_produces_empty_trie() {
        let mut symbols = [];
        assert_eq!(build(&mut symbols), []);
    }

    #[test]
    fn builds_single_symbol_trie() {
        check(&mut [Symbol {
            name: b"_main",
            address: 0x1234,
            flags: macho::ExportSymbolFlags(0),
        }]);
    }

    #[test]
    fn builds_absolute_symbol() {
        let mut symbols = [Symbol {
            name: b"_absolute",
            address: 42,
            flags: macho::EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE.into(),
        }];

        check(&mut symbols);
    }

    #[test]
    fn builds_weak_symbol() {
        let mut symbols = [Symbol {
            name: b"_weak",
            address: 42,
            flags: macho::EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION,
        }];

        check(&mut symbols);
    }

    #[test]
    fn builds_shared_prefix_trie() {
        check(&mut [
            Symbol {
                name: b"_foobar",
                address: 1,
                flags: macho::ExportSymbolFlags(0),
            },
            Symbol {
                name: b"_foo",
                address: 2,
                flags: macho::ExportSymbolFlags(0),
            },
            Symbol {
                name: b"_fop",
                address: 3,
                flags: macho::ExportSymbolFlags(0),
            },
        ]);
    }

    #[test]
    fn builds_deeply_nested_prefixes() {
        let names = (1..=1024).map(|len| vec![b'a'; len]).collect_vec();
        let mut symbols = names
            .iter()
            .enumerate()
            .map(|(address, name)| Symbol {
                name,
                address: address as u64,
                flags: macho::ExportSymbolFlags(0),
            })
            .collect_vec();

        check(&mut symbols);
    }

    #[test]
    fn every_non_zero_byte() {
        let names: Vec<Vec<u8>> = (1..=255).map(|n| vec![n]).collect();
        let mut symbols: Vec<_> = names
            .iter()
            .enumerate()
            .map(|(index, name)| Symbol {
                name,
                address: index as u64,
                flags: macho::ExportSymbolFlags(0),
            })
            .collect();

        check(&mut symbols);
    }

    #[test]
    fn maximum_addresses_give_a_conservative_size() {
        let names = (0..512)
            .map(|index| format!("_shared_prefix_{index:04x}").into_bytes())
            .collect_vec();

        let mut actual = names
            .iter()
            .enumerate()
            .map(|(index, name)| Symbol {
                name,
                address: 1_u64 << (index % 63),
                flags: macho::ExportSymbolFlags(0),
            })
            .collect_vec();

        let mut maximum = names
            .iter()
            .map(|name| Symbol {
                name,
                address: u64::MAX,
                flags: macho::ExportSymbolFlags(0),
            })
            .collect_vec();

        assert!(build(&mut actual).len() <= build(&mut maximum).len());
    }
}
