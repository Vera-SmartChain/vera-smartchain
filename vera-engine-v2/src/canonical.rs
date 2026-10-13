use std::collections::{BTreeSet, HashMap};
use crate::graph::{ComputationGraph, Node, NodeId, Op};

/// Normalizes a ComputationGraph by applying:
/// 1. Constant Folding (compile-time literal evaluation)
/// 2. Canonical Commutative Ordering (bottom-up content hash based)
/// 3. Common Subexpression Elimination (CSE / Hash Consing)
/// 4. Dead Code Elimination (DCE - eliminates disconnected nodes from output)
/// 5. Deterministic contiguous re-indexing of NodeIds (0..N)
pub fn normalize(graph: &ComputationGraph) -> ComputationGraph {
    if graph.nodes.is_empty() {
        return ComputationGraph::new();
    }

    // Identify output node (must have at least one)
    let output_target = match graph.output_node() {
        Some(Node {
            op: Op::Output(target),
            ..
        }) => *target,
        _ => return graph.clone(),
    };

    // Steps 1, 2, and 3: Bottom-up processing with Constant Folding, Ordering, and CSE
    // Mapping of original NodeId -> simplified NodeId in intermediate graph
    let mut remap: HashMap<NodeId, NodeId> = HashMap::new();
    // Cache of known constants: new NodeId -> i64
    let mut const_values: HashMap<NodeId, i64> = HashMap::new();
    // Cache of local hashes for deterministic commutative sorting
    let mut node_hashes: HashMap<NodeId, [u8; 32]> = HashMap::new();
    // CSE: Mapping of canonical Op -> existing NodeId in new graph
    let mut cse_cache: HashMap<Op, NodeId> = HashMap::new();

    let mut intermediate_nodes: Vec<Node> = Vec::new();

    for original_node in &graph.nodes {
        let op = &original_node.op;

        let simplified_op: Op = match op {
            Op::Input(idx) => Op::Input(*idx),
            Op::ConstI64(val) => Op::ConstI64(*val),
            Op::Add(a, b) => {
                let mapped_a = remap.get(a).copied().unwrap_or(*a);
                let mapped_b = remap.get(b).copied().unwrap_or(*b);

                // Constant folding
                if let (Some(&va), Some(&vb)) = (const_values.get(&mapped_a), const_values.get(&mapped_b)) {
                    Op::ConstI64(va.wrapping_add(vb))
                } else {
                    // Deterministic commutative ordering by subgraph hash
                    canonicalize_commutative(Op::Add(mapped_a, mapped_b), &node_hashes)
                }
            }
            Op::Sub(a, b) => {
                let mapped_a = remap.get(a).copied().unwrap_or(*a);
                let mapped_b = remap.get(b).copied().unwrap_or(*b);

                if let (Some(&va), Some(&vb)) = (const_values.get(&mapped_a), const_values.get(&mapped_b)) {
                    Op::ConstI64(va.wrapping_sub(vb))
                } else {
                    Op::Sub(mapped_a, mapped_b)
                }
            }
            Op::Mul(a, b) => {
                let mapped_a = remap.get(a).copied().unwrap_or(*a);
                let mapped_b = remap.get(b).copied().unwrap_or(*b);

                if let (Some(&va), Some(&vb)) = (const_values.get(&mapped_a), const_values.get(&mapped_b)) {
                    Op::ConstI64(va.wrapping_mul(vb))
                } else {
                    canonicalize_commutative(Op::Mul(mapped_a, mapped_b), &node_hashes)
                }
            }
            Op::Div(a, b) => {
                let mapped_a = remap.get(a).copied().unwrap_or(*a);
                let mapped_b = remap.get(b).copied().unwrap_or(*b);

                if let (Some(&va), Some(&vb)) = (const_values.get(&mapped_a), const_values.get(&mapped_b)) {
                    if vb == 0 {
                        Op::ConstI64(0) // Deterministic guard: division by zero is 0
                    } else if va == i64::MIN && vb == -1 {
                        Op::ConstI64(i64::MAX) // Guard against x86 #DE overflow
                    } else {
                        Op::ConstI64(va.wrapping_div(vb))
                    }
                } else {
                    Op::Div(mapped_a, mapped_b)
                }
            }
            Op::SaturatingAdd(a, b) => {
                let mapped_a = remap.get(a).copied().unwrap_or(*a);
                let mapped_b = remap.get(b).copied().unwrap_or(*b);

                if let (Some(&va), Some(&vb)) = (const_values.get(&mapped_a), const_values.get(&mapped_b)) {
                    Op::ConstI64(va.saturating_add(vb))
                } else {
                    canonicalize_commutative(Op::SaturatingAdd(mapped_a, mapped_b), &node_hashes)
                }
            }
            Op::SaturatingSub(a, b) => {
                let mapped_a = remap.get(a).copied().unwrap_or(*a);
                let mapped_b = remap.get(b).copied().unwrap_or(*b);

                if let (Some(&va), Some(&vb)) = (const_values.get(&mapped_a), const_values.get(&mapped_b)) {
                    Op::ConstI64(va.saturating_sub(vb))
                } else {
                    Op::SaturatingSub(mapped_a, mapped_b)
                }
            }
            Op::RotL(a, shift) => {
                let mapped_a = remap.get(a).copied().unwrap_or(*a);
                let s = *shift % 64;
                if let Some(&va) = const_values.get(&mapped_a) {
                    Op::ConstI64(va.rotate_left(s))
                } else {
                    Op::RotL(mapped_a, s)
                }
            }
            Op::RotR(a, shift) => {
                let mapped_a = remap.get(a).copied().unwrap_or(*a);
                let s = *shift % 64;
                if let Some(&va) = const_values.get(&mapped_a) {
                    Op::ConstI64(va.rotate_right(s))
                } else {
                    Op::RotR(mapped_a, s)
                }
            }
            Op::And(a, b) => {
                let mapped_a = remap.get(a).copied().unwrap_or(*a);
                let mapped_b = remap.get(b).copied().unwrap_or(*b);

                if let (Some(&va), Some(&vb)) = (const_values.get(&mapped_a), const_values.get(&mapped_b)) {
                    Op::ConstI64(va & vb)
                } else {
                    canonicalize_commutative(Op::And(mapped_a, mapped_b), &node_hashes)
                }
            }
            Op::Or(a, b) => {
                let mapped_a = remap.get(a).copied().unwrap_or(*a);
                let mapped_b = remap.get(b).copied().unwrap_or(*b);

                if let (Some(&va), Some(&vb)) = (const_values.get(&mapped_a), const_values.get(&mapped_b)) {
                    Op::ConstI64(va | vb)
                } else {
                    canonicalize_commutative(Op::Or(mapped_a, mapped_b), &node_hashes)
                }
            }
            Op::Xor(a, b) => {
                let mapped_a = remap.get(a).copied().unwrap_or(*a);
                let mapped_b = remap.get(b).copied().unwrap_or(*b);

                if let (Some(&va), Some(&vb)) = (const_values.get(&mapped_a), const_values.get(&mapped_b)) {
                    Op::ConstI64(va ^ vb)
                } else {
                    canonicalize_commutative(Op::Xor(mapped_a, mapped_b), &node_hashes)
                }
            }
            Op::Select {
                cond,
                if_true,
                if_false,
            } => {
                let mapped_cond = remap.get(cond).copied().unwrap_or(*cond);
                let mapped_true = remap.get(if_true).copied().unwrap_or(*if_true);
                let mapped_false = remap.get(if_false).copied().unwrap_or(*if_false);

                if let Some(&c_val) = const_values.get(&mapped_cond) {
                    if c_val != 0 {
                        // Directly unrolls to if_true
                        remap.insert(original_node.id, mapped_true);
                        continue;
                    } else {
                        // Directly unrolls to if_false
                        remap.insert(original_node.id, mapped_false);
                        continue;
                    }
                } else {
                    Op::Select {
                        cond: mapped_cond,
                        if_true: mapped_true,
                        if_false: mapped_false,
                    }
                }
            }
            Op::FusedARX { a, b, d, m, rot } => {
                let mapped_a = remap.get(a).copied().unwrap_or(*a);
                let mapped_b = remap.get(b).copied().unwrap_or(*b);
                let mapped_d = remap.get(d).copied().unwrap_or(*d);
                let mapped_m = remap.get(m).copied().unwrap_or(*m);

                if let (Some(&va), Some(&vb), Some(&vd), Some(&vm)) = (
                    const_values.get(&mapped_a),
                    const_values.get(&mapped_b),
                    const_values.get(&mapped_d),
                    const_values.get(&mapped_m),
                ) {
                    let sum = va.wrapping_add(vb).wrapping_add(vm);
                    Op::ConstI64((vd ^ sum).rotate_right(*rot % 64))
                } else {
                    Op::FusedARX {
                        a: mapped_a,
                        b: mapped_b,
                        d: mapped_d,
                        m: mapped_m,
                        rot: *rot,
                    }
                }
            }
            Op::Output(target) => {
                let mapped_target = remap.get(target).copied().unwrap_or(*target);
                Op::Output(mapped_target)
            }
        };

        // CSE check (Common Subexpression Elimination)
        // Output nodes are ignored as Output is unique at the end
        if !matches!(simplified_op, Op::Output(_)) {
            if let Some(&existing_id) = cse_cache.get(&simplified_op) {
                remap.insert(original_node.id, existing_id);
                continue;
            }
        }

        // Create new node in intermediate graph
        let new_id = NodeId(intermediate_nodes.len());
        if let Op::ConstI64(v) = simplified_op {
            const_values.insert(new_id, v);
        }

        // Compute content hash for this node
        let h = compute_node_hash(&simplified_op, &node_hashes);
        node_hashes.insert(new_id, h);

        if !matches!(simplified_op, Op::Output(_)) {
            cse_cache.insert(simplified_op.clone(), new_id);
        }

        intermediate_nodes.push(Node {
            id: new_id,
            op: simplified_op,
        });
        remap.insert(original_node.id, new_id);
    }

    // Identify final remapped output node
    let final_output_source = remap.get(&output_target).copied().unwrap_or(output_target);

    // Step 4: Dead Code Elimination (DCE)
    // Collect all reachable nodes from final_output_source
    let mut live_nodes: BTreeSet<NodeId> = BTreeSet::new();
    let mut stack = vec![final_output_source];

    while let Some(current_id) = stack.pop() {
        if live_nodes.insert(current_id) {
            if let Some(node) = intermediate_nodes.get(current_id.0) {
                match &node.op {
                    Op::Input(_) | Op::ConstI64(_) => {}
                    Op::Add(a, b)
                    | Op::Sub(a, b)
                    | Op::Mul(a, b)
                    | Op::Div(a, b)
                    | Op::SaturatingAdd(a, b)
                    | Op::SaturatingSub(a, b)
                    | Op::And(a, b)
                    | Op::Or(a, b)
                    | Op::Xor(a, b) => {
                        stack.push(*a);
                        stack.push(*b);
                    }
                    Op::RotL(a, _) | Op::RotR(a, _) => {
                        stack.push(*a);
                    }
                    Op::Select {
                        cond,
                        if_true,
                        if_false,
                    } => {
                        stack.push(*cond);
                        stack.push(*if_true);
                        stack.push(*if_false);
                    }
                    Op::FusedARX { a, b, d, m, .. } => {
                        stack.push(*a);
                        stack.push(*b);
                        stack.push(*d);
                        stack.push(*m);
                    }
                    Op::Output(target) => {
                        stack.push(*target);
                    }
                }
            }
        }
    }

    // Step 5: Canonical Topological Sorting by (Depth, Content Hash)
    // Guarantees NodeId assignment (0..N) is invariant to the order in which
    // different AI agents instantiated independent nodes or declarations.
    let mut depths: HashMap<NodeId, usize> = HashMap::new();
    let mut sorted_live_nodes: Vec<NodeId> = live_nodes.into_iter().collect();

    sorted_live_nodes.sort_by(|&id_a, &id_b| {
        let da = compute_depth(id_a, &intermediate_nodes, &mut depths);
        let db = compute_depth(id_b, &intermediate_nodes, &mut depths);
        let depth_cmp = da.cmp(&db);
        if depth_cmp != std::cmp::Ordering::Equal {
            return depth_cmp;
        }

        let ha = node_hashes.get(&id_a).copied().unwrap_or([0u8; 32]);
        let hb = node_hashes.get(&id_b).copied().unwrap_or([0u8; 32]);
        ha.cmp(&hb)
    });

    let mut final_graph = ComputationGraph::new();
    let mut dce_remap: HashMap<NodeId, NodeId> = HashMap::new();

    for old_id in sorted_live_nodes {
        if let Some(old_node) = intermediate_nodes.get(old_id.0) {
            let remapped_op = match old_node.op {
                Op::Input(idx) => Op::Input(idx),
                Op::ConstI64(v) => Op::ConstI64(v),
                Op::Add(a, b) => Op::Add(dce_remap[&a], dce_remap[&b]),
                Op::Sub(a, b) => Op::Sub(dce_remap[&a], dce_remap[&b]),
                Op::Mul(a, b) => Op::Mul(dce_remap[&a], dce_remap[&b]),
                Op::Div(a, b) => Op::Div(dce_remap[&a], dce_remap[&b]),
                Op::SaturatingAdd(a, b) => Op::SaturatingAdd(dce_remap[&a], dce_remap[&b]),
                Op::SaturatingSub(a, b) => Op::SaturatingSub(dce_remap[&a], dce_remap[&b]),
                Op::RotL(a, s) => Op::RotL(dce_remap[&a], s),
                Op::RotR(a, s) => Op::RotR(dce_remap[&a], s),
                Op::And(a, b) => Op::And(dce_remap[&a], dce_remap[&b]),
                Op::Or(a, b) => Op::Or(dce_remap[&a], dce_remap[&b]),
                Op::Xor(a, b) => Op::Xor(dce_remap[&a], dce_remap[&b]),
                Op::Select {
                    cond,
                    if_true,
                    if_false,
                } => Op::Select {
                    cond: dce_remap[&cond],
                    if_true: dce_remap[&if_true],
                    if_false: dce_remap[&if_false],
                },
                Op::FusedARX { a, b, d, m, rot } => Op::FusedARX {
                    a: dce_remap[&a],
                    b: dce_remap[&b],
                    d: dce_remap[&d],
                    m: dce_remap[&m],
                    rot,
                },
                Op::Output(_) => unreachable!("Output nodes were not included in reverse traversal"),
            };

            let new_id = final_graph.add_node(remapped_op);
            dce_remap.insert(old_id, new_id);
        }
    }

    // Add unique canonical output node
    let final_target = dce_remap[&final_output_source];
    final_graph.set_output(final_target);

    final_graph
}

/// Computes depth (topological level) of a node from inputs
fn compute_depth(id: NodeId, nodes: &[Node], depths: &mut HashMap<NodeId, usize>) -> usize {
    if let Some(&d) = depths.get(&id) {
        return d;
    }
    let node = &nodes[id.0];
    let d = match &node.op {
        Op::Input(_) | Op::ConstI64(_) => 0,
        Op::Add(a, b)
        | Op::Sub(a, b)
        | Op::Mul(a, b)
        | Op::Div(a, b)
        | Op::SaturatingAdd(a, b)
        | Op::SaturatingSub(a, b)
        | Op::And(a, b)
        | Op::Or(a, b)
        | Op::Xor(a, b) => {
            1 + std::cmp::max(
                compute_depth(*a, nodes, depths),
                compute_depth(*b, nodes, depths),
            )
        }
        Op::RotL(a, _) | Op::RotR(a, _) => 1 + compute_depth(*a, nodes, depths),
        Op::Select {
            cond,
            if_true,
            if_false,
        } => {
            1 + [
                compute_depth(*cond, nodes, depths),
                compute_depth(*if_true, nodes, depths),
                compute_depth(*if_false, nodes, depths),
            ]
            .into_iter()
            .max()
            .unwrap_or(0)
        }
        Op::FusedARX { a, b, d, m, .. } => {
            1 + [
                compute_depth(*a, nodes, depths),
                compute_depth(*b, nodes, depths),
                compute_depth(*d, nodes, depths),
                compute_depth(*m, nodes, depths),
            ]
            .into_iter()
            .max()
            .unwrap_or(0)
        }
        Op::Output(target) => 1 + compute_depth(*target, nodes, depths),
    };
    depths.insert(id, d);
    d
}

/// Sorts commutative operands by canonical hash of subgraphs (smaller hash on left)
fn canonicalize_commutative(op: Op, hashes: &HashMap<NodeId, [u8; 32]>) -> Op {
    match op {
        Op::Add(a, b) => {
            let ha = hashes.get(&a).copied().unwrap_or([0u8; 32]);
            let hb = hashes.get(&b).copied().unwrap_or([0u8; 32]);
            if ha > hb || (ha == hb && a.0 > b.0) {
                Op::Add(b, a)
            } else {
                Op::Add(a, b)
            }
        }
        Op::Mul(a, b) => {
            let ha = hashes.get(&a).copied().unwrap_or([0u8; 32]);
            let hb = hashes.get(&b).copied().unwrap_or([0u8; 32]);
            if ha > hb || (ha == hb && a.0 > b.0) {
                Op::Mul(b, a)
            } else {
                Op::Mul(a, b)
            }
        }
        Op::SaturatingAdd(a, b) => {
            let ha = hashes.get(&a).copied().unwrap_or([0u8; 32]);
            let hb = hashes.get(&b).copied().unwrap_or([0u8; 32]);
            if ha > hb || (ha == hb && a.0 > b.0) {
                Op::SaturatingAdd(b, a)
            } else {
                Op::SaturatingAdd(a, b)
            }
        }
        Op::And(a, b) => {
            let ha = hashes.get(&a).copied().unwrap_or([0u8; 32]);
            let hb = hashes.get(&b).copied().unwrap_or([0u8; 32]);
            if ha > hb || (ha == hb && a.0 > b.0) {
                Op::And(b, a)
            } else {
                Op::And(a, b)
            }
        }
        Op::Or(a, b) => {
            let ha = hashes.get(&a).copied().unwrap_or([0u8; 32]);
            let hb = hashes.get(&b).copied().unwrap_or([0u8; 32]);
            if ha > hb || (ha == hb && a.0 > b.0) {
                Op::Or(b, a)
            } else {
                Op::Or(a, b)
            }
        }
        Op::Xor(a, b) => {
            let ha = hashes.get(&a).copied().unwrap_or([0u8; 32]);
            let hb = hashes.get(&b).copied().unwrap_or([0u8; 32]);
            if ha > hb || (ha == hb && a.0 > b.0) {
                Op::Xor(b, a)
            } else {
                Op::Xor(a, b)
            }
        }
        other => other,
    }
}

/// Computes deterministic VERA hash for a node based on operation and child node hashes
fn compute_node_hash(op: &Op, hashes: &HashMap<NodeId, [u8; 32]>) -> [u8; 32] {
    let mut hasher = crate::vera_hash::VeraHasher::new();
    match op {
        Op::Input(idx) => {
            hasher.update(&[0x01]);
            hasher.update(&idx.to_le_bytes());
        }
        Op::ConstI64(v) => {
            hasher.update(&[0x02]);
            hasher.update(&v.to_le_bytes());
        }
        Op::Add(a, b) => {
            hasher.update(&[0x03]);
            hasher.update(&hashes.get(a).copied().unwrap_or([0u8; 32]));
            hasher.update(&hashes.get(b).copied().unwrap_or([0u8; 32]));
        }
        Op::Sub(a, b) => {
            hasher.update(&[0x04]);
            hasher.update(&hashes.get(a).copied().unwrap_or([0u8; 32]));
            hasher.update(&hashes.get(b).copied().unwrap_or([0u8; 32]));
        }
        Op::Mul(a, b) => {
            hasher.update(&[0x05]);
            hasher.update(&hashes.get(a).copied().unwrap_or([0u8; 32]));
            hasher.update(&hashes.get(b).copied().unwrap_or([0u8; 32]));
        }
        Op::Div(a, b) => {
            hasher.update(&[0x06]);
            hasher.update(&hashes.get(a).copied().unwrap_or([0u8; 32]));
            hasher.update(&hashes.get(b).copied().unwrap_or([0u8; 32]));
        }
        Op::And(a, b) => {
            hasher.update(&[0x07]);
            hasher.update(&hashes.get(a).copied().unwrap_or([0u8; 32]));
            hasher.update(&hashes.get(b).copied().unwrap_or([0u8; 32]));
        }
        Op::Or(a, b) => {
            hasher.update(&[0x08]);
            hasher.update(&hashes.get(a).copied().unwrap_or([0u8; 32]));
            hasher.update(&hashes.get(b).copied().unwrap_or([0u8; 32]));
        }
        Op::Xor(a, b) => {
            hasher.update(&[0x09]);
            hasher.update(&hashes.get(a).copied().unwrap_or([0u8; 32]));
            hasher.update(&hashes.get(b).copied().unwrap_or([0u8; 32]));
        }
        Op::Select {
            cond,
            if_true,
            if_false,
        } => {
            hasher.update(&[0x0A]);
            hasher.update(&hashes.get(cond).copied().unwrap_or([0u8; 32]));
            hasher.update(&hashes.get(if_true).copied().unwrap_or([0u8; 32]));
            hasher.update(&hashes.get(if_false).copied().unwrap_or([0u8; 32]));
        }
        Op::Output(target) => {
            hasher.update(&[0x0B]);
            hasher.update(&hashes.get(target).copied().unwrap_or([0u8; 32]));
        }
        Op::SaturatingAdd(a, b) => {
            hasher.update(&[0x0C]);
            hasher.update(&hashes.get(a).copied().unwrap_or([0u8; 32]));
            hasher.update(&hashes.get(b).copied().unwrap_or([0u8; 32]));
        }
        Op::SaturatingSub(a, b) => {
            hasher.update(&[0x0D]);
            hasher.update(&hashes.get(a).copied().unwrap_or([0u8; 32]));
            hasher.update(&hashes.get(b).copied().unwrap_or([0u8; 32]));
        }
        Op::RotL(a, shift) => {
            hasher.update(&[0x0E]);
            hasher.update(&hashes.get(a).copied().unwrap_or([0u8; 32]));
            hasher.update(&shift.to_le_bytes());
        }
        Op::RotR(a, shift) => {
            hasher.update(&[0x0F]);
            hasher.update(&hashes.get(a).copied().unwrap_or([0u8; 32]));
            hasher.update(&shift.to_le_bytes());
        }
        Op::FusedARX { a, b, d, m, rot } => {
            hasher.update(&[0x10]);
            hasher.update(&hashes.get(a).copied().unwrap_or([0u8; 32]));
            hasher.update(&hashes.get(b).copied().unwrap_or([0u8; 32]));
            hasher.update(&hashes.get(d).copied().unwrap_or([0u8; 32]));
            hasher.update(&hashes.get(m).copied().unwrap_or([0u8; 32]));
            hasher.update(&rot.to_le_bytes());
        }
    }
    hasher.finalize()
}

/// Generates native 32-byte VERA Canonical Hash for any ComputationGraph.
/// Performs direct in-memory binary topological encoding of normalized DAG,
/// completely eliminating human JSON or text string serialization.
/// Guarantees that isomorphic representations converge to the exact same 256-bit identity.
pub fn canonical_hash(graph: &ComputationGraph) -> [u8; 32] {
    let normalized = normalize(graph);
    let mut hasher = crate::vera_hash::VeraHasher::new();

    // VERA Canonical Header: magic identifier and node count
    hasher.update(b"VERA_DAG_V2");
    hasher.update(&(normalized.nodes.len() as u32).to_le_bytes());

    // Direct in-memory binary topological encoding
    for node in &normalized.nodes {
        match &node.op {
            Op::Input(idx) => {
                hasher.update(&[0x01]);
                hasher.update(&idx.to_le_bytes());
            }
            Op::ConstI64(v) => {
                hasher.update(&[0x02]);
                hasher.update(&v.to_le_bytes());
            }
            Op::Add(a, b) => {
                hasher.update(&[0x03]);
                hasher.update(&(a.0 as u32).to_le_bytes());
                hasher.update(&(b.0 as u32).to_le_bytes());
            }
            Op::Sub(a, b) => {
                hasher.update(&[0x04]);
                hasher.update(&(a.0 as u32).to_le_bytes());
                hasher.update(&(b.0 as u32).to_le_bytes());
            }
            Op::Mul(a, b) => {
                hasher.update(&[0x05]);
                hasher.update(&(a.0 as u32).to_le_bytes());
                hasher.update(&(b.0 as u32).to_le_bytes());
            }
            Op::Div(a, b) => {
                hasher.update(&[0x06]);
                hasher.update(&(a.0 as u32).to_le_bytes());
                hasher.update(&(b.0 as u32).to_le_bytes());
            }
            Op::And(a, b) => {
                hasher.update(&[0x07]);
                hasher.update(&(a.0 as u32).to_le_bytes());
                hasher.update(&(b.0 as u32).to_le_bytes());
            }
            Op::Or(a, b) => {
                hasher.update(&[0x08]);
                hasher.update(&(a.0 as u32).to_le_bytes());
                hasher.update(&(b.0 as u32).to_le_bytes());
            }
            Op::Xor(a, b) => {
                hasher.update(&[0x09]);
                hasher.update(&(a.0 as u32).to_le_bytes());
                hasher.update(&(b.0 as u32).to_le_bytes());
            }
            Op::Select {
                cond,
                if_true,
                if_false,
            } => {
                hasher.update(&[0x0A]);
                hasher.update(&(cond.0 as u32).to_le_bytes());
                hasher.update(&(if_true.0 as u32).to_le_bytes());
                hasher.update(&(if_false.0 as u32).to_le_bytes());
            }
            Op::Output(target) => {
                hasher.update(&[0x0B]);
                hasher.update(&(target.0 as u32).to_le_bytes());
            }
            Op::SaturatingAdd(a, b) => {
                hasher.update(&[0x0C]);
                hasher.update(&(a.0 as u32).to_le_bytes());
                hasher.update(&(b.0 as u32).to_le_bytes());
            }
            Op::SaturatingSub(a, b) => {
                hasher.update(&[0x0D]);
                hasher.update(&(a.0 as u32).to_le_bytes());
                hasher.update(&(b.0 as u32).to_le_bytes());
            }
            Op::RotL(a, shift) => {
                hasher.update(&[0x0E]);
                hasher.update(&(a.0 as u32).to_le_bytes());
                hasher.update(&shift.to_le_bytes());
            }
            Op::RotR(a, shift) => {
                hasher.update(&[0x0F]);
                hasher.update(&(a.0 as u32).to_le_bytes());
                hasher.update(&shift.to_le_bytes());
            }
            Op::FusedARX { a, b, d, m, rot } => {
                hasher.update(&[0x10]);
                hasher.update(&(a.0 as u32).to_le_bytes());
                hasher.update(&(b.0 as u32).to_le_bytes());
                hasher.update(&(d.0 as u32).to_le_bytes());
                hasher.update(&(m.0 as u32).to_le_bytes());
                hasher.update(&rot.to_le_bytes());
            }
        }
    }

    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commutativity_normalization() {
        // Graph 1: in0 + in1
        let mut g1 = ComputationGraph::new();
        let a1 = g1.add_input(0);
        let b1 = g1.add_input(1);
        let sum1 = g1.add_add(a1, b1);
        g1.set_output(sum1);

        // Graph 2: in1 + in0
        let mut g2 = ComputationGraph::new();
        let a2 = g2.add_input(0);
        let b2 = g2.add_input(1);
        let sum2 = g2.add_add(b2, a2); // Reversed operand order
        g2.set_output(sum2);

        let h1 = canonical_hash(&g1);
        let h2 = canonical_hash(&g2);
        assert_eq!(h1, h2, "Commutativity of addition must generate identical canonical hash");
    }

    #[test]
    fn test_constant_folding() {
        let mut g = ComputationGraph::new();
        let c3 = g.add_const(3);
        let c5 = g.add_const(5);
        let sum = g.add_add(c3, c5);
        g.set_output(sum);

        let normalized = normalize(&g);
        assert_eq!(normalized.nodes.len(), 2); // ConstI64(8) and Output
        assert_eq!(normalized.nodes[0].op, Op::ConstI64(8));
        assert_eq!(normalized.nodes[1].op, Op::Output(NodeId(0)));
    }

    #[test]
    fn test_dead_code_elimination() {
        let mut g = ComputationGraph::new();
        let in0 = g.add_input(0);
        let _dead_const = g.add_const(999);
        let _dead_add = g.add_add(in0, _dead_const);
        let c10 = g.add_const(10);
        let alive_sum = g.add_add(in0, c10);
        g.set_output(alive_sum);

        let normalized = normalize(&g);
        // Must contain only in0, c10, alive_sum and Output
        assert_eq!(normalized.nodes.len(), 4);
        assert!(!normalized.nodes.iter().any(|n| n.op == Op::ConstI64(999)));
    }

    #[test]
    fn test_cse() {
        let mut g = ComputationGraph::new();
        let in0 = g.add_input(0);
        let in1 = g.add_input(1);
        // Duplicate subexpressions: in0 + in1 computed twice
        let sum1 = g.add_add(in0, in1);
        let sum2 = g.add_add(in0, in1);
        let total = g.add_mul(sum1, sum2);
        g.set_output(total);

        let normalized = normalize(&g);
        // Must have: Input(0), Input(1), Add(0, 1), Mul(2, 2), Output(3) -> 5 nodes
        assert_eq!(normalized.nodes.len(), 5);
        assert_eq!(normalized.nodes[3].op, Op::Mul(NodeId(2), NodeId(2)));
    }

    #[test]
    fn test_isomorphism_different_construction_order() {
        // AI A constructs: P * R * (1 + T) / 12
        let mut g_a = ComputationGraph::new();
        let p_a = g_a.add_input(0);
        let r_a = g_a.add_input(1);
        let t_a = g_a.add_input(2);
        let one_a = g_a.add_const(1);
        let twelve_a = g_a.add_const(12);
        let term_a = g_a.add_add(t_a, one_a); // (t + 1)
        let pr_a = g_a.add_mul(p_a, r_a);     // (p * r)
        let num_a = g_a.add_mul(pr_a, term_a);
        let res_a = g_a.add_div(num_a, twelve_a);
        g_a.set_output(res_a);

        // AI B constructs in completely different node order and inverted commutative order:
        let mut g_b = ComputationGraph::new();
        let twelve_b = g_b.add_const(12);
        let one_b = g_b.add_const(1);
        let t_b = g_b.add_input(2);
        let r_b = g_b.add_input(1);
        let p_b = g_b.add_input(0);
        let term_b = g_b.add_add(one_b, t_b); // (1 + t) instead of (t + 1)
        let pr_b = g_b.add_mul(r_b, p_b);     // (r * p) instead of (p * r)
        let num_b = g_b.add_mul(term_b, pr_b); // (term * pr) instead of (pr * term)
        let res_b = g_b.add_div(num_b, twelve_b);
        g_b.set_output(res_b);

        let hash_a = canonical_hash(&g_a);
        let hash_b = canonical_hash(&g_b);

        assert_eq!(
            hash_a, hash_b,
            "AI agents with different generation orders must converge to the exact same canonical hash"
        );
    }
}
