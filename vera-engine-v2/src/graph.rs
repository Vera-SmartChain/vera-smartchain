use serde::{Deserialize, Serialize};

/// Node identifier in SSA graph. Strictly corresponds to positional index in Vec<Node>.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub usize);

/// Deterministic maximum complexity threshold of nodes per SSA graph for DoS and Stack Overflow protection
pub const MAX_GRAPH_NODES: usize = 4096;

/// Pure computation operations in SSA graph — side-effect free.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Op {
    /// Positional input parameter (0-based)
    Input(u32),
    /// 64-bit integer constant
    ConstI64(i64),
    /// Basic arithmetic
    Add(NodeId, NodeId),
    Sub(NodeId, NodeId),
    Mul(NodeId, NodeId),
    Div(NodeId, NodeId),
    /// Overflow-protected saturating arithmetic for DeFi and financial contracts
    SaturatingAdd(NodeId, NodeId),
    SaturatingSub(NodeId, NodeId),
    /// Native bit rotation (ARX) for cryptographic primitives (Keccak, Blake3, SHA)
    RotL(NodeId, u32),
    RotR(NodeId, u32),
    /// Bitwise logic
    And(NodeId, NodeId),
    Or(NodeId, NodeId),
    Xor(NodeId, NodeId),
    /// Branchless control flow (conditional multiplexer: if cond != 0 selects if_true, else if_false)
    Select {
        cond: NodeId,
        if_true: NodeId,
        if_false: NodeId,
    },
    /// Fused ARX Super-OpCode: computes ((a + b + m) ^ d) >>> rot
    /// Eliminates 3 intermediate nodes and fuses execution in high-speed x86 pipeline
    FusedARX {
        a: NodeId,
        b: NodeId,
        d: NodeId,
        m: NodeId,
        rot: u32,
    },
    /// Marker for final return result of computation
    Output(NodeId),
}

/// Individual node in SSA Graph
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub op: Op,
}

/// Computation Graph — Immutable or construction-stage SSA DAG
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputationGraph {
    pub nodes: Vec<Node>,
}

impl ComputationGraph {
    /// Creates a new empty graph
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Adds a node with the given operation and returns its NodeId
    pub fn add_node(&mut self, op: Op) -> NodeId {
        let id = NodeId(self.nodes.len());
        self.nodes.push(Node { id, op });
        id
    }

    /// Helper for positional input
    pub fn add_input(&mut self, index: u32) -> NodeId {
        self.add_node(Op::Input(index))
    }

    /// Helper for 64-bit integer constant
    pub fn add_const(&mut self, value: i64) -> NodeId {
        self.add_node(Op::ConstI64(value))
    }

    /// Helper for addition
    pub fn add_add(&mut self, a: NodeId, b: NodeId) -> NodeId {
        self.add_node(Op::Add(a, b))
    }

    /// Helper for subtraction
    pub fn add_sub(&mut self, a: NodeId, b: NodeId) -> NodeId {
        self.add_node(Op::Sub(a, b))
    }

    /// Helper for multiplication
    pub fn add_mul(&mut self, a: NodeId, b: NodeId) -> NodeId {
        self.add_node(Op::Mul(a, b))
    }

    /// Helper for safe division
    pub fn add_div(&mut self, a: NodeId, b: NodeId) -> NodeId {
        self.add_node(Op::Div(a, b))
    }

    /// Helper for anti-overflow saturating addition (clamps at i64::MAX / i64::MIN)
    pub fn add_saturating_add(&mut self, a: NodeId, b: NodeId) -> NodeId {
        self.add_node(Op::SaturatingAdd(a, b))
    }

    /// Helper for anti-underflow saturating subtraction
    pub fn add_saturating_sub(&mut self, a: NodeId, b: NodeId) -> NodeId {
        self.add_node(Op::SaturatingSub(a, b))
    }

    /// Helper for bitwise rotate left
    pub fn add_rotl(&mut self, a: NodeId, shift: u32) -> NodeId {
        self.add_node(Op::RotL(a, shift))
    }

    /// Helper for bitwise rotate right
    pub fn add_rotr(&mut self, a: NodeId, shift: u32) -> NodeId {
        self.add_node(Op::RotR(a, shift))
    }

    /// Helper for bitwise AND
    pub fn add_and(&mut self, a: NodeId, b: NodeId) -> NodeId {
        self.add_node(Op::And(a, b))
    }

    /// Helper for bitwise OR
    pub fn add_or(&mut self, a: NodeId, b: NodeId) -> NodeId {
        self.add_node(Op::Or(a, b))
    }

    /// Helper for bitwise XOR
    pub fn add_xor(&mut self, a: NodeId, b: NodeId) -> NodeId {
        self.add_node(Op::Xor(a, b))
    }

    /// Helper for branchless conditional multiplexer
    pub fn add_select(&mut self, cond: NodeId, if_true: NodeId, if_false: NodeId) -> NodeId {
        self.add_node(Op::Select {
            cond,
            if_true,
            if_false,
        })
    }

    /// Helper for Fused ARX Super-OpCode: ((a + b + m) ^ d) >>> rot
    pub fn add_fused_arx(&mut self, a: NodeId, b: NodeId, d: NodeId, m: NodeId, rot: u32) -> NodeId {
        self.add_node(Op::FusedARX { a, b, d, m, rot })
    }

    /// Marks a node as program return output
    pub fn set_output(&mut self, node: NodeId) -> NodeId {
        self.add_node(Op::Output(node))
    }

    /// Gets reference to a node by its ID
    pub fn get_node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(id.0)
    }

    /// Finds first Output node in graph
    pub fn output_node(&self) -> Option<&Node> {
        self.nodes.iter().find(|n| matches!(n.op, Op::Output(_)))
    }

    /// Serializes graph into compact deterministic JSON string
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("Failed to serialize ComputationGraph to JSON")
    }

    /// Deserializes a graph from a JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Validates DAG structural invariants and complexity bounds
    pub fn validate_invariants(&self) -> Result<(), String> {
        if self.nodes.len() > MAX_GRAPH_NODES {
            return Err(format!(
                "Security: graph exceeds maximum allowed complexity ({} nodes > limit of {})",
                self.nodes.len(),
                MAX_GRAPH_NODES
            ));
        }

        let mut output_count = 0;
        for (i, node) in self.nodes.iter().enumerate() {
            if node.id.0 != i {
                return Err(format!(
                    "Invariant violated: node at position {} has id {}",
                    i, node.id.0
                ));
            }

            match node.op {
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
                    if a.0 >= i || b.0 >= i {
                        return Err(format!(
                            "Invariant violated: node {} references subsequent node or self (a: {}, b: {})",
                            i, a.0, b.0
                        ));
                    }
                }
                Op::RotL(a, _) | Op::RotR(a, _) => {
                    if a.0 >= i {
                        return Err(format!(
                            "Invariant violated: rotation node {} references subsequent node or self {}",
                            i, a.0
                        ));
                    }
                }
                Op::Select {
                    cond,
                    if_true,
                    if_false,
                } => {
                    if cond.0 >= i || if_true.0 >= i || if_false.0 >= i {
                        return Err(format!(
                            "Invariant violated: Select node {} references future nodes (cond: {}, true: {}, false: {})",
                            i, cond.0, if_true.0, if_false.0
                        ));
                    }
                }
                Op::FusedARX { a, b, d, m, .. } => {
                    if a.0 >= i || b.0 >= i || d.0 >= i || m.0 >= i {
                        return Err(format!(
                            "Invariant violated: FusedARX node {} references future nodes (a: {}, b: {}, d: {}, m: {})",
                            i, a.0, b.0, d.0, m.0
                        ));
                    }
                }
                Op::Output(target) => {
                    output_count += 1;
                    if target.0 >= i {
                        return Err(format!(
                            "Invariant violated: Output node {} references subsequent node {}",
                            i, target.0
                        ));
                    }
                }
            }
        }

        if output_count == 0 {
            return Err("Graph does not have an Output node".to_string());
        }

        Ok(())
    }

    /// Safe high-speed Pure-Rust interpreter.
    /// Operates across any architecture (x86, ARM, RISC-V, WASM) and acts as JIT verification oracle.
    /// Mathematically guarantees panic-freedom and safe division.
    pub fn evaluate_pure(&self, inputs: &[i64]) -> Result<i64, String> {
        self.validate_invariants()?;
        let mut values: Vec<i64> = Vec::with_capacity(self.nodes.len());

        for node in &self.nodes {
            let val = match &node.op {
                Op::Input(idx) => {
                    *inputs
                        .get(*idx as usize)
                        .ok_or_else(|| format!("Positional input {} not provided", idx))?
                }
                Op::ConstI64(v) => *v,
                Op::Add(a, b) => values[a.0].wrapping_add(values[b.0]),
                Op::Sub(a, b) => values[a.0].wrapping_sub(values[b.0]),
                Op::Mul(a, b) => values[a.0].wrapping_mul(values[b.0]),
                Op::Div(a, b) => {
                    let divisor = values[b.0];
                    if divisor == 0 {
                        0 // Deterministic guard: division by zero yields 0
                    } else {
                        let dividend = values[a.0];
                        if dividend == i64::MIN && divisor == -1 {
                            i64::MAX // Guard against x86 #DE overflow
                        } else {
                            dividend.wrapping_div(divisor)
                        }
                    }
                }
                Op::SaturatingAdd(a, b) => values[a.0].saturating_add(values[b.0]),
                Op::SaturatingSub(a, b) => values[a.0].saturating_sub(values[b.0]),
                Op::RotL(a, shift) => values[a.0].rotate_left(shift % 64),
                Op::RotR(a, shift) => values[a.0].rotate_right(shift % 64),
                Op::And(a, b) => values[a.0] & values[b.0],
                Op::Or(a, b) => values[a.0] | values[b.0],
                Op::Xor(a, b) => values[a.0] ^ values[b.0],
                Op::Select {
                    cond,
                    if_true,
                    if_false,
                } => {
                    if values[cond.0] != 0 {
                        values[if_true.0]
                    } else {
                        values[if_false.0]
                    }
                }
                Op::FusedARX { a, b, d, m, rot } => {
                    let sum = values[a.0].wrapping_add(values[b.0]).wrapping_add(values[m.0]);
                    (values[d.0] ^ sum).rotate_right(rot % 64)
                }
                Op::Output(target) => values[target.0],
            };
            values.push(val);
        }

        let out_node = self
            .output_node()
            .ok_or_else(|| "Graph does not have an Output node".to_string())?;
        if let Op::Output(target) = out_node.op {
            Ok(values[target.0])
        } else {
            Err("Invalid output node".to_string())
        }
    }
}

impl Default for ComputationGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_simple_graph() {
        let mut graph = ComputationGraph::new();
        // (a + b) * c
        let a = graph.add_input(0);
        let b = graph.add_input(1);
        let c = graph.add_const(42);
        let sum = graph.add_add(a, b);
        let prod = graph.add_mul(sum, c);
        let out = graph.set_output(prod);

        assert_eq!(graph.nodes.len(), 6);
        assert_eq!(out.0, 5);
        assert!(graph.validate_invariants().is_ok());
    }

    #[test]
    fn test_json_roundtrip() {
        let mut graph = ComputationGraph::new();
        let in0 = graph.add_input(0);
        let c10 = graph.add_const(10);
        let sum = graph.add_add(in0, c10);
        graph.set_output(sum);

        let json = graph.to_json();
        let parsed = ComputationGraph::from_json(&json).expect("Deserialization failed");
        assert_eq!(graph, parsed);
    }

    #[test]
    fn test_node_id_consistency() {
        let mut graph = ComputationGraph::new();
        for i in 0..10 {
            let id = graph.add_const(i as i64);
            assert_eq!(id.0, i);
            assert_eq!(graph.nodes[i].id.0, i);
        }
    }
}
