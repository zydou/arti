//! Dynamically emitted HashX assembly code for x86_64 targets

use crate::CompilerError;
use crate::compiler::{Architecture, Executable, util};
use crate::program::{Instruction, InstructionArray, NUM_INSTRUCTIONS};
use crate::register::{RegisterFile, RegisterId};
use dynasmrt::{DynasmApi, DynasmLabelApi, x64, x64::Rq};
use std::mem;

impl Architecture for Executable {
    fn compile(program: &InstructionArray) -> Result<Self, CompilerError> {
        let mut asm = Assembler::new();
        {
            emit_save_regs(&mut asm);
            emit_load_input(&mut asm);
            emit_init_locals(&mut asm);
            debug_assert_eq!(asm.len(), PROLOGUE_SIZE);
        }
        for inst in program {
            let prev_len = asm.len();
            emit_instruction(&mut asm, inst);
            debug_assert!(asm.len() - prev_len <= INSTRUCTION_SIZE_LIMIT);
        }
        {
            let prev_len = asm.len();
            emit_store_output(&mut asm);
            emit_restore_regs(&mut asm);
            emit_return(&mut asm);
            debug_assert_eq!(asm.len() - prev_len, EPILOGUE_SIZE);
        }
        asm.finalize()
    }

    fn invoke(&self, regs: &mut RegisterFile) {
        // Choose the System V ABI for x86_64. (Rust now lets us do this even on
        // targets that use a different default C ABI.) We aren't using the
        // stack red zone, and we only need one register-sized parameter.
        //
        // Parameters: rdi rsi rdx rcx r8 r9
        // Callee save: rbx rsp rbp r12 r13 r14 r15
        // Scratch: rax rdi rsi rdx rcx r8 r9 r10 r11

        let entry = self.buffer.ptr(Assembler::entry());
        let entry: extern "sysv64" fn(*mut RegisterFile) -> () = unsafe { mem::transmute(entry) };
        entry(regs);
    }
}

/// Architecture-specific fixed prologue size
const PROLOGUE_SIZE: usize = 0x68;

/// Architecture-specific fixed epilogue size
const EPILOGUE_SIZE: usize = 0x60;

/// Architecture-specific maximum size for one instruction
const INSTRUCTION_SIZE_LIMIT: usize = 0x11;

/// Capacity for the temporary output buffer, before code is copied into
/// a long-lived allocation that can be made executable.
const BUFFER_CAPACITY: usize =
    PROLOGUE_SIZE + EPILOGUE_SIZE + NUM_INSTRUCTIONS * INSTRUCTION_SIZE_LIMIT;

/// Architecture-specific specialization of the Assembler
type Assembler = util::Assembler<x64::X64Relocation, BUFFER_CAPACITY>;

/// Map RegisterId in our abstract program to concrete registers and addresses.
trait RegisterMapper {
    /// Map RegisterId(0) to R8, and so on
    fn rq(&self) -> u8;
    /// Byte offset in a raw RegisterFile
    fn offset(&self) -> i32;
}

impl RegisterMapper for RegisterId {
    #[inline(always)]
    fn rq(&self) -> u8 {
        8 + self.as_u8()
    }

    #[inline(always)]
    fn offset(&self) -> i32 {
        (self.as_usize() * mem::size_of::<u64>()) as i32
    }
}

/// Wrapper for `dynasm!`, sets the architecture and defines register aliases
macro_rules! dynasm {
    ($asm:ident $($t:tt)*) => {
        dynasmrt::dynasm!($asm
            ; .arch x64
            ; .alias mulh_in, rax
            ; .alias mulh_result64, rdx
            ; .alias mulh_result32, edx
            ; .alias branch_prohibit_flag, esi
            ; .alias const_ones, ecx
            ; .alias register_file_ptr, rdi
            $($t)*
        )
    }
}

/// Emit code to initialize our local variables to default values.
#[inline(always)]
fn emit_init_locals<A: DynasmApi>(asm: &mut A) {
    dynasm!(asm
    ; xor mulh_result64, mulh_result64
    ; xor branch_prohibit_flag, branch_prohibit_flag
    ; lea const_ones, [branch_prohibit_flag - 1]
    );
}

/// List of registers to save on the stack, in address order
const REGS_TO_SAVE: [Rq; 4] = [Rq::R12, Rq::R13, Rq::R14, Rq::R15];

/// Calculate the amount of stack space to reserve, in bytes.
///
/// This is enough to hold REGS_TO_SAVE, and to keep the platform's
/// 16-byte stack alignment.
const fn stack_size() -> i32 {
    let size = REGS_TO_SAVE.len() * mem::size_of::<u64>();
    let alignment = 0x10;
    let offset = size % alignment;
    let size = if offset == 0 {
        size
    } else {
        size + alignment - offset
    };
    size as i32
}

/// Emit code to allocate stack space and store REGS_TO_SAVE.
#[inline(always)]
fn emit_save_regs<A: DynasmApi>(asm: &mut A) {
    dynasm!(asm; sub rsp, stack_size());
    for (i, reg) in REGS_TO_SAVE.as_ref().iter().enumerate() {
        let offset = (i * mem::size_of::<u64>()) as i32;
        dynasm!(asm; mov [rsp + offset], Rq(*reg));
    }
}

/// Emit code to restore REGS_TO_SAVE and deallocate stack space.
#[inline(always)]
fn emit_restore_regs<A: DynasmApi>(asm: &mut A) {
    for (i, reg) in REGS_TO_SAVE.as_ref().iter().enumerate() {
        let offset = (i * mem::size_of::<u64>()) as i32;
        dynasm!(asm; mov Rq(*reg), [rsp + offset]);
    }
    dynasm!(asm; add rsp, stack_size());
}

/// Emit code to move all input values from the RegisterFile into their
/// actual hardware registers.
#[inline(always)]
#[allow(clippy::useless_conversion)]
fn emit_load_input<A: DynasmApi>(asm: &mut A) {
    for reg in RegisterId::all() {
        dynasm!(asm; mov Rq(reg.rq()), [register_file_ptr + reg.offset()]);
    }
}

/// Emit code to move all output values from machine registers back into
/// their RegisterFile slots.
#[inline(always)]
#[allow(clippy::useless_conversion)]
fn emit_store_output<A: DynasmApi>(asm: &mut A) {
    for reg in RegisterId::all() {
        dynasm!(asm; mov [register_file_ptr + reg.offset()], Rq(reg.rq()));
    }
}

/// Emit a return instruction.
#[inline(always)]
fn emit_return<A: DynasmApi>(asm: &mut A) {
    dynasm!(asm; ret);
}

/// Emit code for a single [`Instruction`] in the hash program.
#[inline(always)]
#[allow(clippy::useless_conversion)]
fn emit_instruction(asm: &mut Assembler, inst: &Instruction) {
    /// Common implementation for binary operations on registers
    macro_rules! reg_op {
        ($op:tt, $dst:ident, $src:ident) => {
            dynasm!(asm; $op Rq($dst.rq()), Rq($src.rq()))
        }
    }

    /// Common implementation for binary operations with a const operand
    macro_rules! const_op {
        ($op:tt, $dst:ident, $src:expr) => {
            dynasm!(asm; $op Rq($dst.rq()), $src)
        }
    }

    /// Common implementation for wide multiply operations.
    /// These use the one-argument form of `mul` (one register plus RDX:RAX)
    macro_rules! mulh_op {
        ($op:tt, $dst:ident, $src:ident) => {
            dynasm!(asm
                ; mov mulh_in, Rq($dst.rq())
                ; $op Rq($src.rq())
                ; mov Rq($dst.rq()), mulh_result64
            )
        }
    }

    /// Common implementation for scaled add using `lea`.
    /// Currently dynasm can only parse literal scale parameters.
    macro_rules! add_scaled_op {
        ($scale:tt, $dst:ident, $src:ident) => {
            dynasm!(asm
                ; lea Rq($dst.rq()), [ Rq($dst.rq()) + $scale * Rq($src.rq()) ]
            )
        }
    }

    match inst {
        Instruction::Target => {
            dynasm!(asm; target: );
        }
        Instruction::Branch { mask } => {
            // Only one branch is allowed, `branch_prohibit_flag` keeps the test
            // from passing. We get mul result tracking for free by assigning
            // mulh_result32 to the corresponding output register used by the
            // x86 mul instruction.
            dynasm!(asm
                ; or mulh_result32, branch_prohibit_flag
                ; test mulh_result32, *mask as i32
                ; cmovz branch_prohibit_flag, const_ones
                ; jz <target
            );
        }
        Instruction::AddShift {
            dst,
            src,
            left_shift,
        } => match left_shift {
            0 => add_scaled_op!(1, dst, src),
            1 => add_scaled_op!(2, dst, src),
            2 => add_scaled_op!(4, dst, src),
            3 => add_scaled_op!(8, dst, src),
            _ => unreachable!(),
        },
        Instruction::UMulH { dst, src } => {
            mulh_op!(mul, dst, src);
        }
        Instruction::SMulH { dst, src } => {
            mulh_op!(imul, dst, src);
        }
        Instruction::Mul { dst, src } => {
            reg_op!(imul, dst, src);
        }
        Instruction::Xor { dst, src } => {
            reg_op!(xor, dst, src);
        }
        Instruction::Sub { dst, src } => {
            reg_op!(sub, dst, src);
        }
        Instruction::AddConst { dst, src } => {
            const_op!(add, dst, *src);
        }
        Instruction::XorConst { dst, src } => {
            const_op!(xor, dst, *src);
        }
        Instruction::Rotate { dst, right_rotate } => {
            const_op!(ror, dst, *right_rotate as i8);
        }
    }
}
