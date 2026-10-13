use crate::canonical::normalize;
use crate::graph::{ComputationGraph, Op};

/// Native compiled x86-64 JIT function executable in Windows memory
pub struct JitFunction {
    code: *mut u8,
    pub size: usize,
}

// JitFunction is safe to send across threads if exclusive ownership is transferred
unsafe impl Send for JitFunction {}

type NativeJitFn = unsafe extern "C" fn(*const i64, usize) -> i64;

impl JitFunction {
    /// Compiles a normalized ComputationGraph directly into native x86-64 opcodes
    pub fn compile(graph: &ComputationGraph) -> Result<Self, String> {
        graph.validate_invariants()?;
        let canonical_graph = normalize(graph);
        canonical_graph.validate_invariants()?;

        let n_nodes = canonical_graph.nodes.len();
        if n_nodes == 0 {
            return Err("Empty graph".to_string());
        }

        // Each node has an 8-byte slot on the local stack.
        // x64 ABI alignment: at entry, rsp % 16 == 8.
        // Therefore, sub rsp, (16 * k + 8) guarantees rsp is 16-byte aligned.
        let raw_slots_bytes = n_nodes * 8;
        let k = (raw_slots_bytes + 15) / 16;
        let frame_size = (k * 16 + 8) as u32;

        let mut code: Vec<u8> = Vec::with_capacity(512);

        // --- PROLOGUE ---
        // sub rsp, frame_size (48 81 EC [imm32])
        code.extend_from_slice(&[0x48, 0x81, 0xEC]);
        code.extend_from_slice(&frame_size.to_le_bytes());

        // --- COMPILATION BODY ---
        for node in &canonical_graph.nodes {
            let i = node.id.0 as u32;
            let disp_i = i * 8;

            match &node.op {
                Op::Input(input_idx) => {
                    // mov rax, [rcx + input_idx * 8] (48 8B 81 [disp32])
                    let in_disp = (*input_idx * 8) as u32;
                    code.extend_from_slice(&[0x48, 0x8B, 0x81]);
                    code.extend_from_slice(&in_disp.to_le_bytes());

                    // mov [rsp + disp_i], rax (48 89 84 24 [disp32])
                    emit_mov_to_rsp(&mut code, disp_i);
                }
                Op::ConstI64(val) => {
                    // mov rax, imm64 (48 B8 [8 bytes])
                    code.extend_from_slice(&[0x48, 0xB8]);
                    code.extend_from_slice(&val.to_le_bytes());

                    // mov [rsp + disp_i], rax
                    emit_mov_to_rsp(&mut code, disp_i);
                }
                Op::Add(a, b) => {
                    emit_mov_from_rsp(&mut code, (a.0 as u32) * 8);
                    // add rax, [rsp + disp_b] (48 03 84 24 [disp32])
                    code.extend_from_slice(&[0x48, 0x03, 0x84, 0x24]);
                    code.extend_from_slice(&((b.0 as u32) * 8).to_le_bytes());
                    emit_mov_to_rsp(&mut code, disp_i);
                }
                Op::Sub(a, b) => {
                    emit_mov_from_rsp(&mut code, (a.0 as u32) * 8);
                    // sub rax, [rsp + disp_b] (48 2B 84 24 [disp32])
                    code.extend_from_slice(&[0x48, 0x2B, 0x84, 0x24]);
                    code.extend_from_slice(&((b.0 as u32) * 8).to_le_bytes());
                    emit_mov_to_rsp(&mut code, disp_i);
                }
                Op::Mul(a, b) => {
                    emit_mov_from_rsp(&mut code, (a.0 as u32) * 8);
                    // imul rax, [rsp + disp_b] (48 0F AF 84 24 [disp32])
                    code.extend_from_slice(&[0x48, 0x0F, 0xAF, 0x84, 0x24]);
                    code.extend_from_slice(&((b.0 as u32) * 8).to_le_bytes());
                    emit_mov_to_rsp(&mut code, disp_i);
                }
                Op::Div(a, b) => {
                    // Deterministic guard against #DE (CPU Divide Error Exception)
                    // 1. mov rax, [rsp + disp_a]
                    emit_mov_from_rsp(&mut code, (a.0 as u32) * 8);
                    // 2. mov r10, [rsp + disp_b]
                    code.extend_from_slice(&[0x4C, 0x8B, 0x94, 0x24]);
                    code.extend_from_slice(&((b.0 as u32) * 8).to_le_bytes());
                    // 3. test r10, r10 (4D 85 D2)
                    code.extend_from_slice(&[0x4D, 0x85, 0xD2]);
                    // 4. jz .div_by_zero (74 28)
                    code.extend_from_slice(&[0x74, 0x28]);
                    // 5. mov r11, 0x8000000000000000 (49 BB [8 bytes])
                    code.extend_from_slice(&[0x49, 0xBB]);
                    code.extend_from_slice(&i64::MIN.to_le_bytes());
                    // 6. cmp rax, r11 (4C 39 D8)
                    code.extend_from_slice(&[0x4C, 0x39, 0xD8]);
                    // 7. jne .do_idiv (75 12)
                    code.extend_from_slice(&[0x75, 0x12]);
                    // 8. cmp r10, -1 (49 83 FA FF)
                    code.extend_from_slice(&[0x49, 0x83, 0xFA, 0xFF]);
                    // 9. jne .do_idiv (75 0C)
                    code.extend_from_slice(&[0x75, 0x0C]);
                    // 10. mov rax, 0x7FFFFFFFFFFFFFFF (48 B8 [8 bytes])
                    code.extend_from_slice(&[0x48, 0xB8]);
                    code.extend_from_slice(&i64::MAX.to_le_bytes());
                    // 11. jmp .done_div (EB 09)
                    code.extend_from_slice(&[0xEB, 0x09]);
                    // .do_idiv:
                    // 12. cqo (48 99)
                    code.extend_from_slice(&[0x48, 0x99]);
                    // 13. idiv r10 (49 F7 FA)
                    code.extend_from_slice(&[0x49, 0xF7, 0xFA]);
                    // 14. jmp .done_div (EB 02)
                    code.extend_from_slice(&[0xEB, 0x02]);
                    // .div_by_zero:
                    // 15. xor eax, eax (31 C0)
                    code.extend_from_slice(&[0x31, 0xC0]);
                    // .done_div:
                    // 16. mov [rsp + disp_i], rax
                    emit_mov_to_rsp(&mut code, disp_i);
                }
                Op::SaturatingAdd(a, b) => {
                    emit_mov_from_rsp(&mut code, (a.0 as u32) * 8);
                    code.extend_from_slice(&[0x4C, 0x8B, 0x94, 0x24]);
                    code.extend_from_slice(&((b.0 as u32) * 8).to_le_bytes());
                    // add rax, r10 (4C 01 D0)
                    code.extend_from_slice(&[0x4C, 0x01, 0xD0]);
                    // jno .no_ovf (71 18)
                    code.extend_from_slice(&[0x71, 0x18]);
                    // js .pos_ovf (78 0C)
                    code.extend_from_slice(&[0x78, 0x0C]);
                    // mov rax, i64::MIN (48 B8 [8 bytes])
                    code.extend_from_slice(&[0x48, 0xB8]);
                    code.extend_from_slice(&i64::MIN.to_le_bytes());
                    // jmp .no_ovf (EB 0A)
                    code.extend_from_slice(&[0xEB, 0x0A]);
                    // .pos_ovf: mov rax, i64::MAX (48 B8 [8 bytes])
                    code.extend_from_slice(&[0x48, 0xB8]);
                    code.extend_from_slice(&i64::MAX.to_le_bytes());
                    // .no_ovf:
                    emit_mov_to_rsp(&mut code, disp_i);
                }
                Op::SaturatingSub(a, b) => {
                    emit_mov_from_rsp(&mut code, (a.0 as u32) * 8);
                    code.extend_from_slice(&[0x4C, 0x8B, 0x94, 0x24]);
                    code.extend_from_slice(&((b.0 as u32) * 8).to_le_bytes());
                    // sub rax, r10 (4C 29 D0)
                    code.extend_from_slice(&[0x4C, 0x29, 0xD0]);
                    // jno .no_ovf (71 18)
                    code.extend_from_slice(&[0x71, 0x18]);
                    // js .pos_ovf (78 0C)
                    code.extend_from_slice(&[0x78, 0x0C]);
                    // mov rax, i64::MIN (48 B8 [8 bytes])
                    code.extend_from_slice(&[0x48, 0xB8]);
                    code.extend_from_slice(&i64::MIN.to_le_bytes());
                    // jmp .no_ovf (EB 0A)
                    code.extend_from_slice(&[0xEB, 0x0A]);
                    // .pos_ovf: mov rax, i64::MAX (48 B8 [8 bytes])
                    code.extend_from_slice(&[0x48, 0xB8]);
                    code.extend_from_slice(&i64::MAX.to_le_bytes());
                    // .no_ovf:
                    emit_mov_to_rsp(&mut code, disp_i);
                }
                Op::RotL(a, shift) => {
                    emit_mov_from_rsp(&mut code, (a.0 as u32) * 8);
                    let s = (*shift % 64) as u8;
                    // rol rax, imm8 (48 C1 C0 [imm8])
                    code.extend_from_slice(&[0x48, 0xC1, 0xC0, s]);
                    emit_mov_to_rsp(&mut code, disp_i);
                }
                Op::RotR(a, shift) => {
                    emit_mov_from_rsp(&mut code, (a.0 as u32) * 8);
                    let s = (*shift % 64) as u8;
                    // ror rax, imm8 (48 C1 C8 [imm8])
                    code.extend_from_slice(&[0x48, 0xC1, 0xC8, s]);
                    emit_mov_to_rsp(&mut code, disp_i);
                }
                Op::And(a, b) => {
                    emit_mov_from_rsp(&mut code, (a.0 as u32) * 8);
                    // and rax, [rsp + disp_b] (48 23 84 24 [disp32])
                    code.extend_from_slice(&[0x48, 0x23, 0x84, 0x24]);
                    code.extend_from_slice(&((b.0 as u32) * 8).to_le_bytes());
                    emit_mov_to_rsp(&mut code, disp_i);
                }
                Op::Or(a, b) => {
                    emit_mov_from_rsp(&mut code, (a.0 as u32) * 8);
                    // or rax, [rsp + disp_b] (48 0B 84 24 [disp32])
                    code.extend_from_slice(&[0x48, 0x0B, 0x84, 0x24]);
                    code.extend_from_slice(&((b.0 as u32) * 8).to_le_bytes());
                    emit_mov_to_rsp(&mut code, disp_i);
                }
                Op::Xor(a, b) => {
                    emit_mov_from_rsp(&mut code, (a.0 as u32) * 8);
                    // xor rax, [rsp + disp_b] (48 33 84 24 [disp32])
                    code.extend_from_slice(&[0x48, 0x33, 0x84, 0x24]);
                    code.extend_from_slice(&((b.0 as u32) * 8).to_le_bytes());
                    emit_mov_to_rsp(&mut code, disp_i);
                }
                Op::Select {
                    cond,
                    if_true,
                    if_false,
                } => {
                    // mov r10, [rsp + disp_cond] (4C 8B 94 24 [disp32])
                    code.extend_from_slice(&[0x4C, 0x8B, 0x94, 0x24]);
                    code.extend_from_slice(&((cond.0 as u32) * 8).to_le_bytes());
                    // test r10, r10 (4D 85 D2)
                    code.extend_from_slice(&[0x4D, 0x85, 0xD2]);
                    // mov rax, [rsp + disp_false] (48 8B 84 24 [disp32])
                    emit_mov_from_rsp(&mut code, (if_false.0 as u32) * 8);
                    // mov r11, [rsp + disp_true] (4C 8B 9C 24 [disp32])
                    code.extend_from_slice(&[0x4C, 0x8B, 0x9C, 0x24]);
                    code.extend_from_slice(&((if_true.0 as u32) * 8).to_le_bytes());
                    // cmovnz rax, r11 (49 0F 45 C3)
                    code.extend_from_slice(&[0x49, 0x0F, 0x45, 0xC3]);
                    emit_mov_to_rsp(&mut code, disp_i);
                }
                Op::FusedARX { a, b, d, m, rot } => {
                    // 1. mov rax, [rsp + disp_a]
                    emit_mov_from_rsp(&mut code, (a.0 as u32) * 8);
                    // 2. add rax, [rsp + disp_b] (48 03 84 24 [disp32])
                    code.extend_from_slice(&[0x48, 0x03, 0x84, 0x24]);
                    code.extend_from_slice(&((b.0 as u32) * 8).to_le_bytes());
                    // 3. add rax, [rsp + disp_m] (48 03 84 24 [disp32])
                    code.extend_from_slice(&[0x48, 0x03, 0x84, 0x24]);
                    code.extend_from_slice(&((m.0 as u32) * 8).to_le_bytes());
                    // 4. xor rax, [rsp + disp_d] (48 33 84 24 [disp32])
                    code.extend_from_slice(&[0x48, 0x33, 0x84, 0x24]);
                    code.extend_from_slice(&((d.0 as u32) * 8).to_le_bytes());
                    // 5. ror rax, rot (48 C1 C8 [rot8])
                    code.extend_from_slice(&[0x48, 0xC1, 0xC8, (rot % 64) as u8]);
                    // 6. mov [rsp + disp_i], rax
                    emit_mov_to_rsp(&mut code, disp_i);
                }
                Op::Output(target) => {
                    // Load final result into rax
                    emit_mov_from_rsp(&mut code, (target.0 as u32) * 8);
                }
            }
        }

        // --- EPILOGUE ---
        // add rsp, frame_size (48 81 C4 [imm32])
        code.extend_from_slice(&[0x48, 0x81, 0xC4]);
        code.extend_from_slice(&frame_size.to_le_bytes());

        // ret (C3)
        code.push(0xC3);

        // Allocate W^X page: initially writable (RW), non-executable
        let alloc_size = code.len();
        let ptr = unsafe { alloc_writable(alloc_size) };
        if ptr.is_null() {
            return Err("Failed to allocate writable memory via VirtualAlloc".to_string());
        }

        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), ptr, alloc_size);
            // W^X enforcement: revoke write and grant only READ + EXECUTE (PAGE_EXECUTE_READ)
            if !protect_executable(ptr, alloc_size) {
                return Err("Failed to apply W^X protection (PAGE_EXECUTE_READ) via VirtualProtect".to_string());
            }
        }

        Ok(Self {
            code: ptr,
            size: alloc_size,
        })
    }

    /// Executes native x86-64 code directly on CPU with supplied arguments
    pub fn execute(&self, args: &[i64]) -> i64 {
        assert!(!self.code.is_null(), "JIT code pointer is null");
        let func: NativeJitFn = unsafe { std::mem::transmute(self.code) };
        unsafe { func(args.as_ptr(), args.len()) }
    }
}

fn emit_mov_to_rsp(code: &mut Vec<u8>, disp: u32) {
    // mov [rsp + disp], rax -> 48 89 84 24 [disp32]
    code.extend_from_slice(&[0x48, 0x89, 0x84, 0x24]);
    code.extend_from_slice(&disp.to_le_bytes());
}

fn emit_mov_from_rsp(code: &mut Vec<u8>, disp: u32) {
    // mov rax, [rsp + disp] -> 48 8B 84 24 [disp32]
    code.extend_from_slice(&[0x48, 0x8B, 0x84, 0x24]);
    code.extend_from_slice(&disp.to_le_bytes());
}

#[cfg(windows)]
unsafe fn alloc_writable(size: usize) -> *mut u8 {
    use windows_sys::Win32::System::Memory::*;
    let ptr = VirtualAlloc(
        std::ptr::null(),
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    ptr as *mut u8
}

#[cfg(windows)]
unsafe fn protect_executable(ptr: *mut u8, size: usize) -> bool {
    use windows_sys::Win32::System::Memory::*;
    let mut old_protect = 0;
    let res = VirtualProtect(
        ptr as _,
        size,
        PAGE_EXECUTE_READ,
        &mut old_protect,
    );
    res != 0
}

#[cfg(unix)]
unsafe fn alloc_writable(size: usize) -> *mut u8 {
    let ptr = libc::mmap(
        std::ptr::null_mut(),
        size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if ptr == libc::MAP_FAILED {
        std::ptr::null_mut()
    } else {
        ptr as *mut u8
    }
}

#[cfg(unix)]
unsafe fn protect_executable(ptr: *mut u8, size: usize) -> bool {
    let res = libc::mprotect(
        ptr as *mut libc::c_void,
        size,
        libc::PROT_READ | libc::PROT_EXEC,
    );
    res == 0
}

#[cfg(not(any(windows, unix)))]
unsafe fn alloc_writable(_size: usize) -> *mut u8 {
    std::ptr::null_mut()
}

#[cfg(not(any(windows, unix)))]
unsafe fn protect_executable(_ptr: *mut u8, _size: usize) -> bool {
    true
}

#[cfg(windows)]
impl Drop for JitFunction {
    fn drop(&mut self) {
        if !self.code.is_null() {
            unsafe {
                use windows_sys::Win32::System::Memory::*;
                VirtualFree(self.code as _, 0, MEM_RELEASE);
            }
        }
    }
}

#[cfg(unix)]
impl Drop for JitFunction {
    fn drop(&mut self) {
        if !self.code.is_null() {
            unsafe {
                libc::munmap(self.code as *mut libc::c_void, self.size);
            }
        }
    }
}

#[cfg(not(any(windows, unix)))]
impl Drop for JitFunction {
    fn drop(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::MAX_GRAPH_NODES;
    use std::time::Instant;

    #[test]
    fn test_jit_simple_addition() {
        let mut g = ComputationGraph::new();
        let a = g.add_input(0);
        let b = g.add_input(1);
        let sum = g.add_add(a, b);
        g.set_output(sum);

        let jit = JitFunction::compile(&g).expect("Failed to compile JIT");
        let result = jit.execute(&[3, 7]);
        assert_eq!(result, 10);
    }

    #[test]
    fn test_jit_complex_expression() {
        let mut g = ComputationGraph::new();
        // (a + b) * c - d / e
        let a = g.add_input(0);
        let b = g.add_input(1);
        let c = g.add_input(2);
        let d = g.add_input(3);
        let e = g.add_const(2);

        let sum = g.add_add(a, b);
        let prod = g.add_mul(sum, c);
        let div = g.add_div(d, e);
        let sub = g.add_sub(prod, div);
        g.set_output(sub);

        let jit = JitFunction::compile(&g).expect("Failed to compile JIT");
        // (10 + 20) * 3 - 8 / 2 = 30 * 3 - 4 = 90 - 4 = 86
        let result = jit.execute(&[10, 20, 3, 8]);
        assert_eq!(result, 86);
    }

    #[test]
    fn test_jit_constant_only() {
        let mut g = ComputationGraph::new();
        let c = g.add_const(42);
        g.set_output(c);

        let jit = JitFunction::compile(&g).expect("Failed to compile JIT");
        let result = jit.execute(&[]);
        assert_eq!(result, 42);
    }

    #[test]
    fn test_jit_select_branchless() {
        let mut g = ComputationGraph::new();
        let cond = g.add_input(0);
        let val_true = g.add_const(100);
        let val_false = g.add_const(200);
        let sel = g.add_select(cond, val_true, val_false);
        g.set_output(sel);

        let jit = JitFunction::compile(&g).expect("Failed to compile JIT");
        assert_eq!(jit.execute(&[1]), 100);
        assert_eq!(jit.execute(&[0]), 200);
    }

    #[test]
    fn test_jit_execution_time_nanoseconds() {
        let mut g = ComputationGraph::new();
        let a = g.add_input(0);
        let b = g.add_input(1);
        let c = g.add_mul(a, b);
        g.set_output(c);

        let jit = JitFunction::compile(&g).expect("Failed to compile JIT");

        // Warmup
        for _ in 0..100 {
            let _ = jit.execute(&[6, 7]);
        }

        let start = Instant::now();
        let res = jit.execute(&[6, 7]);
        let elapsed = start.elapsed();

        assert_eq!(res, 42);
        println!("JIT execution time: {:?}", elapsed);
        // Must execute in under 10 microseconds (typically < 100 ns)
        assert!(elapsed.as_micros() < 10);
    }

    #[test]
    fn test_jit_divide_by_zero_safe() {
        let mut g = ComputationGraph::new();
        let a = g.add_input(0);
        let b = g.add_input(1);
        let div = g.add_div(a, b);
        g.set_output(div);

        let jit = JitFunction::compile(&g).expect("Failed to compile JIT with division");
        // CPU runtime division by zero: must NEVER trigger #DE crash, returns 0 safely
        let res_zero = jit.execute(&[100, 0]);
        assert_eq!(res_zero, 0, "JIT division by zero must safely return 0");

        // Normal division
        let res_normal = jit.execute(&[100, 4]);
        assert_eq!(res_normal, 25);
    }

    #[test]
    fn test_jit_divide_overflow_safe() {
        let mut g = ComputationGraph::new();
        let a = g.add_input(0);
        let b = g.add_input(1);
        let div = g.add_div(a, b);
        g.set_output(div);

        let jit = JitFunction::compile(&g).expect("Failed to compile JIT");
        // i64::MIN / -1 would trigger #DE on x86. Our guard must return i64::MAX
        let res = jit.execute(&[i64::MIN, -1]);
        assert_eq!(res, i64::MAX);
    }

    #[test]
    fn test_jit_saturating_math() {
        let mut g = ComputationGraph::new();
        let a = g.add_input(0);
        let b = g.add_input(1);
        let sat_add = g.add_saturating_add(a, b);
        g.set_output(sat_add);

        let jit = JitFunction::compile(&g).expect("Failed to compile JIT saturating add");
        // Positive overflow
        assert_eq!(jit.execute(&[i64::MAX, 10]), i64::MAX);
        // Negative underflow
        assert_eq!(jit.execute(&[i64::MIN, -10]), i64::MIN);
        // Normal addition
        assert_eq!(jit.execute(&[50, 25]), 75);

        // Saturating subtraction
        let mut g2 = ComputationGraph::new();
        let in0 = g2.add_input(0);
        let in1 = g2.add_input(1);
        let sat_sub = g2.add_saturating_sub(in0, in1);
        g2.set_output(sat_sub);

        let jit2 = JitFunction::compile(&g2).expect("Failed to compile JIT saturating sub");
        assert_eq!(jit2.execute(&[i64::MIN, 10]), i64::MIN);
        assert_eq!(jit2.execute(&[i64::MAX, -10]), i64::MAX);
        assert_eq!(jit2.execute(&[50, 20]), 30);
    }

    #[test]
    fn test_jit_bitwise_rotations() {
        let mut g = ComputationGraph::new();
        let a = g.add_input(0);
        let rotl = g.add_rotl(a, 4);
        g.set_output(rotl);

        let jit = JitFunction::compile(&g).expect("Failed to compile JIT rotl");
        let val: i64 = 0x12345678_9ABCDEF0u64 as i64;
        let expected = val.rotate_left(4);
        assert_eq!(jit.execute(&[val]), expected);

        let mut g2 = ComputationGraph::new();
        let a2 = g2.add_input(0);
        let rotr = g2.add_rotr(a2, 8);
        g2.set_output(rotr);

        let jit2 = JitFunction::compile(&g2).expect("Failed to compile JIT rotr");
        let expected2 = val.rotate_right(8);
        assert_eq!(jit2.execute(&[val]), expected2);
    }

    #[test]
    fn test_jit_pure_interpreter_equivalence() {
        let mut g = ComputationGraph::new();
        let in0 = g.add_input(0);
        let in1 = g.add_input(1);
        let in2 = g.add_input(2);
        let c = g.add_const(15);

        let s1 = g.add_saturating_add(in0, in1);
        let r1 = g.add_rotl(s1, 3);
        let d1 = g.add_div(r1, in2);
        let res = g.add_add(d1, c);
        g.set_output(res);

        let jit = JitFunction::compile(&g).expect("Failed to compile JIT");
        let inputs = [1000, 2000, 7];

        let jit_val = jit.execute(&inputs);
        let pure_val = g.evaluate_pure(&inputs).expect("Failed in pure interpreter");
        assert_eq!(jit_val, pure_val, "JIT and pure interpreter must be identical");

        // Test division by zero in pure interpreter and JIT
        let inputs_div_zero = [1000, 2000, 0];
        let jit_div_zero = jit.execute(&inputs_div_zero);
        let pure_div_zero = g.evaluate_pure(&inputs_div_zero).expect("Failed in pure interpreter");
        assert_eq!(jit_div_zero, pure_div_zero);
        assert_eq!(jit_div_zero, 15); // r1 / 0 = 0, + 15 = 15
    }

    #[test]
    fn test_max_graph_nodes_security_limit() {
        let mut g = ComputationGraph::new();
        let mut prev = g.add_const(1);
        for _ in 0..(MAX_GRAPH_NODES + 10) {
            prev = g.add_const(2);
        }
        g.set_output(prev);

        let res = JitFunction::compile(&g);
        assert!(res.is_err(), "Graph exceeding MAX_GRAPH_NODES must be rejected");
    }

    #[test]
    fn test_jit_fused_arx() {
        let mut g = ComputationGraph::new();
        let in_a = g.add_input(0);
        let in_b = g.add_input(1);
        let in_d = g.add_input(2);
        let in_m = g.add_input(3);
        let fused = g.add_fused_arx(in_a, in_b, in_d, in_m, 24);
        g.set_output(fused);

        let jit = JitFunction::compile(&g).expect("JIT must compile FusedARX");
        let inputs = [0x1234567890ABCDEF, 0x0FEDCBA098765432, 0x5555555555555555, 0x1122334455667788];

        let jit_res = jit.execute(&inputs);
        let pure_res = g.evaluate_pure(&inputs).unwrap();
        assert_eq!(jit_res, pure_res, "JIT and Pure Interpreter must converge on FusedARX");

        let sum = inputs[0].wrapping_add(inputs[1]).wrapping_add(inputs[3]);
        let expected = (inputs[2] ^ sum).rotate_right(24);
        assert_eq!(jit_res, expected);
    }
}
