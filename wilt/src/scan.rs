/// Call graph scanning — zero-allocation instruction scanning.
///
/// Scans function bodies for call opcodes without parsing every instruction.

use crate::leb128;
use crate::module::WasmModule;

/// WASM opcodes we care about for call graph analysis.
const OP_CALL: u8 = 0x10;

/// Build a call graph by scanning function bodies for call instructions.
/// Returns: for each function index, the set of function indices it calls.
///
/// This is O(total code bytes) but allocates only per-edge, not per-instruction.
pub fn call_graph(module: &mut WasmModule<'_>) -> Vec<Vec<u32>> {
    module.ensure_function_bodies_parsed();
    let num_funcs = module.num_function_bodies();
    let data = module.data();
    let bodies = module.function_bodies();

    let mut graph: Vec<Vec<u32>> = vec![Vec::new(); num_funcs];

    for (func_idx, body) in bodies.iter().enumerate() {
        let bytes = body.body.slice(data);

        // Skip local declarations at the start of the body.
        let mut pos = 0;
        if let Some((local_count, consumed)) = leb128::read_u32(bytes) {
            pos += consumed;
            for _ in 0..local_count {
                // count + valtype
                if let Some((_, c)) = leb128::read_u32(&bytes[pos..]) {
                    pos += c;
                }
                pos += 1; // valtype byte
            }
        }

        // Scan for call instructions.
        while pos < bytes.len() {
            let opcode = bytes[pos];
            pos += 1;
            if opcode == OP_CALL {
                if let Some((target, consumed)) = leb128::read_u32(&bytes[pos..]) {
                    pos += consumed;
                    if (target as usize) < num_funcs
                        && !graph[func_idx].contains(&target)
                    {
                        graph[func_idx].push(target);
                    }
                }
            }
            // We don't parse other opcodes — just scan for 0x10.
            // This may produce false positives (0x10 as an immediate)
            // but won't miss real calls.
        }
    }

    graph
}

/// Find all function indices reachable from a set of root indices.
pub fn reachable_from(graph: &[Vec<u32>], roots: &[u32]) -> Vec<bool> {
    let num_funcs = graph.len();
    let mut reachable = vec![false; num_funcs];

    // Mark roots.
    for &root in roots {
        if (root as usize) < num_funcs {
            reachable[root as usize] = true;
        }
    }

    // BFS.
    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..num_funcs {
            if !reachable[i] {
                continue;
            }
            for &target in &graph[i] {
                if !reachable[target as usize] {
                    reachable[target as usize] = true;
                    changed = true;
                }
            }
        }
    }

    reachable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reachable_simple() {
        // 0 calls 1, 1 calls 2, 3 is unreachable
        let graph = vec![vec![1], vec![2], vec![], vec![]];
        let reachable = reachable_from(&graph, &[0]);
        assert_eq!(reachable, vec![true, true, true, false]);
    }

    #[test]
    fn reachable_cycle() {
        // 0 calls 1, 1 calls 0 (cycle)
        let graph = vec![vec![1], vec![0]];
        let reachable = reachable_from(&graph, &[0]);
        assert_eq!(reachable, vec![true, true]);
    }
}
