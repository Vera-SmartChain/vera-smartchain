use std::time::Instant;
use vera_engine_v2::{
    canonical_hash, normalize, simulate_multi_agent_pipeline, ComputationGraph, Op,
};

#[cfg(windows)]
use vera_engine_v2::JitFunction;

#[test]
fn test_isomorphism_interest_calculation() {
    // AI 1 (e.g. Claude) constructs interest calculation: Principal * Rate * (1 + Time) / 12
    let mut claude_graph = ComputationGraph::new();
    let p1 = claude_graph.add_input(0); // Principal
    let r1 = claude_graph.add_input(1); // Rate
    let t1 = claude_graph.add_input(2); // Time
    let one1 = claude_graph.add_const(1);
    let twelve1 = claude_graph.add_const(12);

    let t_plus_1 = claude_graph.add_add(t1, one1);
    let p_times_r = claude_graph.add_mul(p1, r1);
    let numerator1 = claude_graph.add_mul(p_times_r, t_plus_1);
    let interest1 = claude_graph.add_div(numerator1, twelve1);
    claude_graph.set_output(interest1);

    // AI 2 (e.g. GPT-4o) constructs the same calculation in a different topological sequence with inverted operands:
    let mut gpt_graph = ComputationGraph::new();
    let twelve2 = gpt_graph.add_const(12);
    let one2 = gpt_graph.add_const(1);
    let t2 = gpt_graph.add_input(2);
    let p2 = gpt_graph.add_input(0);
    let r2 = gpt_graph.add_input(1);

    let term2 = gpt_graph.add_add(one2, t2); // (1 + t) instead of (t + 1)
    let pr2 = gpt_graph.add_mul(r2, p2);     // (r * p) instead of (p * r)
    let numerator2 = gpt_graph.add_mul(term2, pr2); // (term * pr) instead of (pr * term)
    let interest2 = gpt_graph.add_div(numerator2, twelve2);
    gpt_graph.set_output(interest2);

    // AI 3 (e.g. Gemini) generates redundant subexpressions and dead nodes:
    let mut gemini_graph = ComputationGraph::new();
    let p3 = gemini_graph.add_input(0);
    let r3 = gemini_graph.add_input(1);
    let t3 = gemini_graph.add_input(2);
    let one3 = gemini_graph.add_const(1);
    let twelve3 = gemini_graph.add_const(12);

    // Dead code generated during intermediate reasoning:
    let dead_const = gemini_graph.add_const(9999);
    let _dead_op = gemini_graph.add_mul(p3, dead_const);

    let t_plus_1_gemini = gemini_graph.add_add(t3, one3);
    let pr_gemini = gemini_graph.add_mul(p3, r3);
    let num_gemini = gemini_graph.add_mul(pr_gemini, t_plus_1_gemini);
    let interest3 = gemini_graph.add_div(num_gemini, twelve3);
    gemini_graph.set_output(interest3);

    // Isomorphism Proof and Zero-Friction Verification:
    let hash_claude = canonical_hash(&claude_graph);
    let hash_gpt = canonical_hash(&gpt_graph);
    let hash_gemini = canonical_hash(&gemini_graph);

    assert_eq!(
        hash_claude, hash_gpt,
        "Claude and GPT must converge to the exact same canonical hash"
    );
    assert_eq!(
        hash_claude, hash_gemini,
        "Gemini (with dead code) must converge to the same canonical hash after normalization"
    );
}

#[test]
#[cfg(windows)]
fn test_jit_native_execution() {
    let mut g = ComputationGraph::new();
    // Formula: (x + y) * z - 15
    let x = g.add_input(0);
    let y = g.add_input(1);
    let z = g.add_input(2);
    let c15 = g.add_const(15);

    let sum = g.add_add(x, y);
    let prod = g.add_mul(sum, z);
    let result = g.add_sub(prod, c15);
    g.set_output(result);

    let jit = JitFunction::compile(&g).expect("JIT compilation failed");

    // Test with x = 20, y = 30, z = 4
    // (20 + 30) * 4 - 15 = 50 * 4 - 15 = 200 - 15 = 185
    let output = jit.execute(&[20, 30, 4]);
    assert_eq!(output, 185);

    // Rigorous nanosecond performance measurement
    let mut elapsed_times = Vec::new();
    for _ in 0..1000 {
        let start = Instant::now();
        let val = jit.execute(&[20, 30, 4]);
        let ns = start.elapsed().as_nanos();
        assert_eq!(val, 185);
        elapsed_times.push(ns);
    }

    let min_ns = *elapsed_times.iter().min().unwrap();
    println!(
        "\n🚀 [VERA JIT x86-64] Minimum CPU execution time: {} ns",
        min_ns
    );
    // Machine code execution should be sub-microsecond (< 1000 ns)
    assert!(
        min_ns < 1000,
        "Direct JIT execution in machine code must be under 1 microsecond (executed in {} ns)",
        min_ns
    );
}

#[test]
fn test_zero_friction_composition() {
    // Pipeline graph: inputs -> operation -> foldable constant -> dead code
    let mut g = ComputationGraph::new();
    let in0 = g.add_input(0);
    let in1 = g.add_input(1);
    let c2 = g.add_const(2);
    let c3 = g.add_const(3);
    let folded_const = g.add_mul(c2, c3); // 2 * 3 = 6 at compile time
    let sum = g.add_add(in0, in1);
    let total = g.add_mul(sum, folded_const);
    g.set_output(total);

    let json = g.to_json();
    let sim_result = simulate_multi_agent_pipeline(&json, &[4, 6])
        .expect("Failed to simulate multi-agent composition");

    assert!(sim_result.hashes_match);
    #[cfg(windows)]
    {
        // (4 + 6) * 6 = 10 * 6 = 60
        assert_eq!(sim_result.jit_result, Some(60));
        println!(
            "⚡ [Multi-Agent] JIT execution time: {:?} ns",
            sim_result.jit_time_ns
        );
    }
}

#[test]
fn test_constant_folding_reduces_graph() {
    let mut g = ComputationGraph::new();
    let c10 = g.add_const(10);
    let c20 = g.add_const(20);
    let sum = g.add_add(c10, c20); // Must fold to ConstI64(30)
    g.set_output(sum);

    let normalized = normalize(&g);
    // Must contain only: ConstI64(30) at index 0 and Output(0) at index 1
    assert_eq!(normalized.nodes.len(), 2);
    assert_eq!(normalized.nodes[0].op, Op::ConstI64(30));
}

#[test]
fn test_dead_code_eliminated() {
    let mut g = ComputationGraph::new();
    let in0 = g.add_input(0);
    let c42 = g.add_const(42);
    let out = g.add_add(in0, c42);

    // Adds 5 disconnected dead nodes
    let dead1 = g.add_const(100);
    let dead2 = g.add_const(200);
    let dead3 = g.add_add(dead1, dead2);
    let _dead4 = g.add_mul(dead3, in0);

    g.set_output(out);

    let initial_count = g.nodes.len();
    let normalized = normalize(&g);
    let final_count = normalized.nodes.len();

    assert_eq!(initial_count, 8);
    // Only in0, c42, out and Output(node) remain -> 4 nodes
    assert_eq!(final_count, 4);
    assert!(!normalized.nodes.iter().any(|n| matches!(n.op, Op::ConstI64(100) | Op::ConstI64(200))));
}
