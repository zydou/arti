//! Define the internal hash program representation used by HashX.

use crate::generator::Generator;
use crate::register::{RegisterFile, RegisterId};
use crate::Error;
use fixed_capacity_vec::FixedCapacityVec;
use rand_core::RngCore;
use std::fmt;
use std::ops::BitXor;

/// Maximum number of instructions in the program
///
/// Programs with fewer instructions may be generated (for example, after
/// a timing stall when register allocation fails) but they will not pass
/// whole-program constraint tests.
pub(crate) const NUM_INSTRUCTIONS: usize = 512;

/// Type alias for a full-size array of [`Instruction`]s
pub(crate) type InstructionArray = [Instruction; NUM_INSTRUCTIONS];

/// Type alias for a [`FixedCapacityVec`] that can build [`InstructionArray`]s
pub(crate) type InstructionVec = FixedCapacityVec<Instruction, NUM_INSTRUCTIONS>;

/// Define the HashX virtual instruction set
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum Instruction {
    /// 64-bit multiply of two registers, discarding overflow.
    Mul {
        /// Destination register
        dst: RegisterId,
        /// Source register
        src: RegisterId,
    },

    /// Unsigned 64x64 to 128-bit multiply, saving only the upper half.
    ///
    /// Result is written to dst, and the low 32 bits are saved for the
    /// next Branch test.
    UMulH {
        /// Destination register
        dst: RegisterId,
        /// Source register
        src: RegisterId,
    },

    /// Signed 64x64 to 128-bit multiply, saving only the upper half.
    ///
    /// Result is written to dst, and the low 32 bits are saved for the
    /// next Branch test.
    SMulH {
        /// Destination register
        dst: RegisterId,
        /// Source register
        src: RegisterId,
    },

    /// Shift source register left by a constant amount, add, discard overflow.
    AddShift {
        /// Destination register
        dst: RegisterId,
        /// Source register
        src: RegisterId,
        /// Number of bits to left shift by (0..=3 only)
        left_shift: u8,
    },

    /// 64-bit addition by a sign-extended 32-bit constant.
    AddConst {
        /// Destination register
        dst: RegisterId,
        /// Source immediate, sign-extended from 32-bit to 64-bit
        src: i32,
    },

    /// 64-bit subtraction (dst - src), discarding overflow.
    Sub {
        /// Destination register
        dst: RegisterId,
        /// Source register
        src: RegisterId,
    },

    /// 64-bit XOR of two registers.
    Xor {
        /// Destination register
        dst: RegisterId,
        /// Source register
        src: RegisterId,
    },

    /// XOR a 64-bit register with a sign-extended 32-bit constant.
    XorConst {
        /// Destination register
        dst: RegisterId,
        /// Source immediate, sign-extended from 32-bit to 64-bit
        src: i32,
    },

    /// Rotate a 64-bit register right by a constant amount.
    Rotate {
        /// Destination register
        dst: RegisterId,
        /// Number of bits to rotate right by (0..=63 only)
        right_rotate: u8,
    },

    /// Become the target for the next taken branch, if any.
    Target,

    /// One-shot conditional branch to the last Target.
    Branch {
        /// 32-bit branch condition mask
        ///
        /// This is tested against the last `UMulH`/`SMulH` result. (The low 32
        /// bits of the instruction result, which itself is the upper 64 bits
        /// of the multiplication result.)     
        ///
        /// If `(result & mask)` is zero and no branches have been previously
        /// taken, we jump back to the Target and remember not to take any
        /// future branches. A well formed program will always have a `Target`
        /// prior to any `Branch`.
        mask: u32,
    },
}

/// An instruction operation, without any of its arguments
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum Opcode {
    /// Opcode for [`Instruction::Mul`]
    Mul,
    /// Opcode for [`Instruction::UMulH`]
    UMulH,
    /// Opcode for [`Instruction::SMulH`]
    SMulH,
    /// Opcode for [`Instruction::AddShift`]
    AddShift,
    /// Opcode for [`Instruction::AddConst`]
    AddConst,
    /// Opcode for [`Instruction::Sub`]
    Sub,
    /// Opcode for [`Instruction::Xor`]
    Xor,
    /// Opcode for [`Instruction::XorConst`]
    XorConst,
    /// Opcode for [`Instruction::Rotate`]
    Rotate,
    /// Opcode for [`Instruction::Target`]
    Target,
    /// Opcode for [`Instruction::Branch`]
    Branch,
}

impl Instruction {
    /// Get this instruction's [`Opcode`].
    #[inline(always)]
    pub(crate) fn opcode(&self) -> Opcode {
        match self {
            Instruction::AddConst { .. } => Opcode::AddConst,
            Instruction::AddShift { .. } => Opcode::AddShift,
            Instruction::Branch { .. } => Opcode::Branch,
            Instruction::Mul { .. } => Opcode::Mul,
            Instruction::Rotate { .. } => Opcode::Rotate,
            Instruction::SMulH { .. } => Opcode::SMulH,
            Instruction::Sub { .. } => Opcode::Sub,
            Instruction::Target { .. } => Opcode::Target,
            Instruction::UMulH { .. } => Opcode::UMulH,
            Instruction::Xor { .. } => Opcode::Xor,
            Instruction::XorConst { .. } => Opcode::XorConst,
        }
    }

    /// Get this instruction's destination register, if any.
    #[inline(always)]
    pub(crate) fn destination(&self) -> Option<RegisterId> {
        match self {
            Instruction::AddConst { dst, .. } => Some(*dst),
            Instruction::AddShift { dst, .. } => Some(*dst),
            Instruction::Branch { .. } => None,
            Instruction::Mul { dst, .. } => Some(*dst),
            Instruction::Rotate { dst, .. } => Some(*dst),
            Instruction::SMulH { dst, .. } => Some(*dst),
            Instruction::Sub { dst, .. } => Some(*dst),
            Instruction::Target { .. } => None,
            Instruction::UMulH { dst, .. } => Some(*dst),
            Instruction::Xor { dst, .. } => Some(*dst),
            Instruction::XorConst { dst, .. } => Some(*dst),
        }
    }
}

/// Generated `HashX` program, as a boxed array of instructions
#[derive(Clone)]
pub struct Program(Box<InstructionArray>);

impl fmt::Debug for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Program {{")?;
        for (addr, inst) in self.0.iter().enumerate() {
            writeln!(f, " [{:3}]: {:?}", addr, inst)?;
        }
        write!(f, "}}")
    }
}

impl Program {
    /// Generate a new `Program` from an arbitrary [`RngCore`] implementer
    ///
    /// This can return [`Error::ProgramConstraints`] if the HashX
    /// post-generation program verification fails. During normal use this
    /// will happen once per several thousand random seeds, and the caller
    /// should skip to another seed.
    pub(crate) fn generate<T: RngCore>(rng: &mut T) -> Result<Self, Error> {
        let mut instructions = FixedCapacityVec::new();
        Generator::new(rng).generate_program(&mut instructions)?;
        Ok(Program(
            instructions
                .try_into()
                .map_err(|_| ())
                .expect("wrong length!"),
        ))
    }

    /// Reference implementation for `Program` behavior
    ///
    /// Run the program from start to finish, with up to one branch,
    /// in the provided register file.
    pub(crate) fn interpret(&self, regs: &mut RegisterFile) {
        let mut program_counter = 0;
        let mut allow_branch = true;
        let mut branch_target = None;
        let mut mulh_result: u32 = 0;

        /// Common implementation for binary operations on registers
        macro_rules! binary_reg_op {
            ($dst:ident, $src:ident, $fn:ident, $pc:ident) => {{
                let a = regs.load(*$dst);
                let b = regs.load(*$src);
                regs.store(*$dst, a.$fn(b));
                $pc
            }};
        }

        /// Common implementation for binary operations with a const operand
        macro_rules! binary_const_op {
            ($dst:ident, $src:ident, $fn:ident, $pc:ident) => {{
                let a = regs.load(*$dst);
                let b_sign_extended = i64::from(*$src) as u64;
                regs.store(*$dst, a.$fn(b_sign_extended));
                $pc
            }};
        }

        /// Common implementation for wide multiply operations
        ///
        /// This stores the low 32 bits of its result for later branch tests.
        macro_rules! mulh_op {
            ($dst:ident, $src:ident, $sign:ty, $wide:ty, $pc:ident) => {{
                let a = <$wide>::from(regs.load(*$dst) as $sign);
                let b = <$wide>::from(regs.load(*$src) as $sign);
                let r = (a.wrapping_mul(b) >> 64) as u64;
                mulh_result = r as u32;
                regs.store(*$dst, r);
                $pc
            }};
        }

        while program_counter < self.0.len() {
            let next_pc = program_counter + 1;
            program_counter = match &self.0[program_counter] {
                Instruction::Target => {
                    branch_target = Some(program_counter);
                    next_pc
                }

                Instruction::Branch { mask } => {
                    if allow_branch && (mask & mulh_result) == 0 {
                        allow_branch = false;
                        branch_target
                            .expect("generated programs always have a target before branch")
                    } else {
                        next_pc
                    }
                }

                Instruction::AddShift {
                    dst,
                    src,
                    left_shift,
                } => {
                    let a = regs.load(*dst);
                    let b = regs.load(*src);
                    let r = a.wrapping_add(b.wrapping_shl((*left_shift).into()));
                    regs.store(*dst, r);
                    next_pc
                }

                Instruction::Rotate { dst, right_rotate } => {
                    let a = regs.load(*dst);
                    let r = a.rotate_right((*right_rotate).into());
                    regs.store(*dst, r);
                    next_pc
                }

                Instruction::Mul { dst, src } => binary_reg_op!(dst, src, wrapping_mul, next_pc),
                Instruction::Sub { dst, src } => binary_reg_op!(dst, src, wrapping_sub, next_pc),
                Instruction::Xor { dst, src } => binary_reg_op!(dst, src, bitxor, next_pc),
                Instruction::UMulH { dst, src } => mulh_op!(dst, src, u64, u128, next_pc),
                Instruction::SMulH { dst, src } => mulh_op!(dst, src, i64, i128, next_pc),
                Instruction::XorConst { dst, src } => binary_const_op!(dst, src, bitxor, next_pc),
                Instruction::AddConst { dst, src } => {
                    binary_const_op!(dst, src, wrapping_add, next_pc)
                }
            }
        }
    }
}

impl<'a> From<&'a Program> for &'a InstructionArray {
    #[inline(always)]
    fn from(prog: &'a Program) -> Self {
        &prog.0
    }
}
