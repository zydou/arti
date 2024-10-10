//! Dynamically emitted HashX assembly code for aarch64 targets

use crate::compiler::{util, Architecture, Executable};
use crate::program::{Instruction, InstructionArray, NUM_INSTRUCTIONS};
use crate::register::{RegisterFile, RegisterId};
use crate::CompilerError;
use dynasmrt::{aarch64, DynasmApi, DynasmLabelApi};
use std::mem;

impl Architecture for Executable {
    fn compile(program: &InstructionArray) -> Result<Self, CompilerError> {
        let mut asm = Assembler::new();
        {
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
            emit_return(&mut asm);
            debug_assert_eq!(asm.len() - prev_len, EPILOGUE_SIZE);
        }
        asm.finalize()
    }

    fn invoke(&self, regs: &mut RegisterFile) {
        // Use the AArch64 Procedure Call Standard
        //
        // r0..r8 -- Parameters, results, scratch
        // r9..r15 -- Temp registers
        // r16, r17 -- Temp for dynamic linker shims
        // r18 -- Platform register, avoid
        // r19..r28 -- Callee-saved
        // r29,r30 -- Frame pointer, link register

        let entry = self.buffer.ptr(Assembler::entry());
        let entry: extern "system" fn(*mut RegisterFile) -> () = unsafe { mem::transmute(entry) };
        entry(regs);
    }
}

/// Architecture-specific fixed prologue size
const PROLOGUE_SIZE: usize = 0x28;

/// Architecture-specific fixed epilogue size
const EPILOGUE_SIZE: usize = 0x24;

/// Architecture-specific maximum size for one instruction
const INSTRUCTION_SIZE_LIMIT: usize = 0x18;

/// Capacity for the temporary output buffer, before code is copied into
/// a long-lived allocation that can be made executable.
const BUFFER_CAPACITY: usize =
    PROLOGUE_SIZE + EPILOGUE_SIZE + NUM_INSTRUCTIONS * INSTRUCTION_SIZE_LIMIT;

/// Architecture-specific specialization of the Assembler
type Assembler = util::Assembler<aarch64::Aarch64Relocation, BUFFER_CAPACITY>;

/// Map RegisterId in our abstract program to concrete registers and addresses.
trait RegisterMapper {
    /// Map RegisterId(0)..RegisterId(7) to r1..r8
    fn x(&self) -> u32;
    /// Byte offset in a raw RegisterFile
    fn offset(&self) -> u32;
}

impl RegisterMapper for RegisterId {
    #[inline(always)]
    fn x(&self) -> u32 {
        1 + (self.as_usize() as u32)
    }

    #[inline(always)]
    fn offset(&self) -> u32 {
        (self.as_usize() * mem::size_of::<u64>()) as u32
    }
}

/// Wrapper for `dynasm!`, sets the architecture and defines register aliases
macro_rules! dynasm {
    ($asm:ident $($t:tt)*) => {
        dynasmrt::dynasm!($asm
            ; .arch aarch64
            ; .alias register_file_ptr, x0
            ; .alias mulh_result32, w9
            ; .alias branch_prohibit_flag, w10
            ; .alias const_temp_64, x11
            ; .alias const_temp_32, w11
            $($t)*
        )
    }
}

/// Emit code to initialize our local variables to default values.
#[inline(always)]
fn emit_init_locals<A: DynasmApi>(asm: &mut A) {
    dynasm!(asm
        ; mov mulh_result32, wzr
        ; mov branch_prohibit_flag, wzr
    );
}

/// Emit code to move all input values from the RegisterFile into their
/// actual hardware registers.
#[inline(always)]
fn emit_load_input<A: DynasmApi>(asm: &mut A) {
    for reg in RegisterId::all() {
        dynasm!(asm; ldr X(reg.x()), [register_file_ptr, #reg.offset()]);
    }
}

/// Emit code to move all output values from machine registers back into
/// their RegisterFile slots.
#[inline(always)]
fn emit_store_output<A: DynasmApi>(asm: &mut A) {
    for reg in RegisterId::all() {
        dynasm!(asm; str X(reg.x()), [register_file_ptr, #reg.offset()]);
    }
}

/// Emit a return instruction.
#[inline(always)]
fn emit_return<A: DynasmApi>(asm: &mut A) {
    dynasm!(asm; ret);
}

/// Load a sign extended 32-bit constant into the const_temp_64
/// register, using a movz/movn and movk pair.
#[inline(always)]
fn emit_i32_const_temp_64<A: DynasmApi>(asm: &mut A, value: i32) {
    let high = (value >> 16) as u32;
    let low = (value & 0xFFFF) as u32;
    if value < 0 {
        dynasm!(asm; movn const_temp_64, #!high, lsl #16);
    } else {
        dynasm!(asm; movz const_temp_64, #high, lsl #16);
    }
    dynasm!(asm; movk const_temp_64, #low, lsl #0);
}

/// Load a 32-bit constant into const_temp_32, without extending.
#[inline(always)]
fn emit_u32_const_temp_32<A: DynasmApi>(asm: &mut A, value: u32) {
    let high = value >> 16;
    let low = value & 0xFFFF;
    dynasm!(asm
        ; movz const_temp_32, #high, lsl #16
        ; movk const_temp_32, #low, lsl #0
    );
}

/// Emit code for a single [`Instruction`] in the hash program.
#[inline(always)]
fn emit_instruction(asm: &mut Assembler, inst: &Instruction) {
    /// Common implementation for binary operations on registers
    macro_rules! reg_op {
        ($op:tt, $dst:ident, $src:ident) => {
            dynasm!(asm
                ; $op X($dst.x()), X($dst.x()), X($src.x())
            )
        }
    }

    /// Common implementation for binary operations with a const operand
    macro_rules! const_i32_op {
        ($op:tt, $dst:ident, $src:expr) => {
            emit_i32_const_temp_64(asm, *$src);
            dynasm!(asm
                ; $op X($dst.x()), X($dst.x()), const_temp_64
            )
        }
    }

    /// Common implementation for wide multiply operations
    ///
    /// These make a copy of the bits needed for branch comparisons later.
    ///
    /// The original Hash-X implementation includes an optimization which
    /// avoids this by tracking the register at compile-time, but I hadn't yet
    /// convinced myself this was safe from overwrites in all cases.
    ///
    /// This mov immediately after the mul, however, might just be a bad
    /// pipeline stall. Re-examine this when we're looking at performance.
    /// Can we state that the overwrite is impossible due to program layout?
    /// We should probably just implement a register tracker with a fallback
    /// so we have a guarantee that the data is still saved somewhere even
    /// if another instruction uses the same dest before the branch.
    macro_rules! mulh_op {
        ($op:tt, $dst:ident, $src:ident) => {
            reg_op!($op, $dst, $src);
            dynasm!(asm
                ; mov mulh_result32, W($dst.x())
            )
        }
    }

    match inst {
        Instruction::Target => {
            dynasm!(asm; target: );
        }
        Instruction::Branch { mask } => {
            // Branch at most once, setting branch_prohibit_flag on the way.
            emit_u32_const_temp_32(asm, *mask);
            dynasm!(asm
                ; orr mulh_result32, mulh_result32, branch_prohibit_flag
                ; tst mulh_result32, const_temp_32
                ; csinv branch_prohibit_flag, branch_prohibit_flag, wzr, ne
                ; b.eq <target
            );
        }
        Instruction::Rotate { dst, right_rotate } => {
            let right_rotate: u32 = (*right_rotate).into();
            dynasm!(asm
                ; ror X(dst.x()), X(dst.x()), #right_rotate
            );
        }
        Instruction::AddShift {
            dst,
            src,
            left_shift,
        } => {
            let left_shift: u32 = (*left_shift).into();
            dynasm!(asm
                ; add X(dst.x()), X(dst.x()), X(src.x()), lsl #left_shift
            );
        }
        Instruction::UMulH { dst, src } => {
            mulh_op!(umulh, dst, src);
        }
        Instruction::SMulH { dst, src } => {
            mulh_op!(smulh, dst, src);
        }
        Instruction::Mul { dst, src } => {
            reg_op!(mul, dst, src);
        }
        Instruction::Xor { dst, src } => {
            reg_op!(eor, dst, src);
        }
        Instruction::Sub { dst, src } => {
            reg_op!(sub, dst, src);
        }
        Instruction::AddConst { dst, src } => {
            const_i32_op!(add, dst, src);
        }
        Instruction::XorConst { dst, src } => {
            const_i32_op!(eor, dst, src);
        }
    }
}
