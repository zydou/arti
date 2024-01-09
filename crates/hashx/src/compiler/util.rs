//! Shared utility layer for all architecture-specific compilers

use crate::compiler::Executable;
use crate::CompilerError;
use arrayvec::ArrayVec;
use dynasmrt::mmap::MutableBuffer;
use dynasmrt::{
    components::PatchLoc, relocations::Relocation, AssemblyOffset, DynamicLabel, DynasmApi,
    DynasmLabelApi,
};
use std::marker::PhantomData;

pub(crate) use dynasmrt::mmap::ExecutableBuffer;

/// Our own simple replacement for [`dynasmrt::Assembler`]
///
/// The default assembler in [`dynasmrt`] has a ton of features we don't need,
/// but more importantly it will panic if it can't make its memory region
/// executable. This is a no-go for us, since there is a fallback available.
///
/// Our needs are simple: a single un-named label, no relocations, and
/// no modification after finalization. However, we do need to handle runtime
/// mmap errors thoroughly.
#[derive(Debug, Clone)]
pub(crate) struct Assembler<R: Relocation, const S: usize> {
    /// Temporary fixed capacity buffer for assembling code
    buffer: ArrayVec<u8, S>,
    /// Address of the last "target" label, if any
    target: Option<AssemblyOffset>,
    /// Relocations are applied immediately and not stored.
    phantom: PhantomData<R>,
}

impl<R: Relocation, const S: usize> Assembler<R, S> {
    /// Return the entry point as an [`AssemblyOffset`].
    #[inline(always)]
    pub(crate) fn entry() -> AssemblyOffset {
        AssemblyOffset(0)
    }

    /// Size of the code stored so far, in bytes
    #[inline(always)]
    pub(crate) fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Make a new assembler with a temporary buffer but no executable buffer.
    #[inline(always)]
    pub(crate) fn new() -> Self {
        Self {
            buffer: ArrayVec::new(),
            target: None,
            phantom: PhantomData,
        }
    }

    /// Return a new [`Executable`] with the code that's been written so far.
    ///
    /// This may fail if we can't allocate some memory, fill it, and mark
    /// it as executable. For example, a Linux platform with policy to restrict
    /// `mprotect` will show runtime errors at this point.
    ///
    /// Performance note: Semantically it makes more sense to consume the
    /// `Assembler` instance here, passing it by value. This can result in a
    /// memcpy that doesn't optimize out, which is a dramatic increase to
    /// the memory bandwidth required in compilation. We avoid that extra
    /// copy by only passing a reference.
    #[inline(always)]
    pub(crate) fn finalize(&self) -> Result<Executable, CompilerError> {
        // We never execute code from the buffer until it's complete, and we use
        // a freshly mmap'ed buffer for each program. Because of this, we don't
        // need to explicitly clear the icache even on platforms that would
        // normally want this. If we reuse buffers in the future, this will need
        // architecture-specific support for icache clearing when a new program
        // is finalized into a buffer we previously ran.
        let mut mut_buf = MutableBuffer::new(self.buffer.len())?;
        mut_buf.set_len(self.buffer.len());
        mut_buf[..].copy_from_slice(&self.buffer);
        Ok(Executable {
            buffer: mut_buf.make_exec()?,
        })
    }
}

impl std::fmt::Debug for Executable {
    /// Debug an [`Executable`] by hex-dumping its contents.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Executable[{}; {} ]",
            std::env::consts::ARCH,
            hex::encode(&self.buffer[..])
        )
    }
}

// Reluctantly implement just enough of [`DynasmLabelApi`] for our single backward label.
impl<R: Relocation, const S: usize> DynasmLabelApi for Assembler<R, S> {
    type Relocation = R;

    #[inline(always)]
    fn local_label(&mut self, name: &'static str) {
        debug_assert_eq!(name, "target");
        self.target = Some(self.offset());
    }

    #[inline(always)]
    fn backward_relocation(
        &mut self,
        name: &'static str,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: R,
    ) {
        debug_assert_eq!(name, "target");
        let target = self
            .target
            .expect("generated programs always have a target before branch");
        // Apply the relocation immediately without storing it.
        let loc = PatchLoc::new(self.offset(), target_offset, field_offset, ref_offset, kind);
        let buf = &mut self.buffer[loc.range(0)];
        loc.patch(buf, 0, target.0)
            .expect("program relocations are always in range");
    }

    fn global_label(&mut self, _name: &'static str) {
        unreachable!();
    }

    fn dynamic_label(&mut self, _id: DynamicLabel) {
        unreachable!();
    }

    fn bare_relocation(&mut self, _target: usize, _field_offset: u8, _ref_offset: u8, _kind: R) {
        unreachable!();
    }

    fn global_relocation(
        &mut self,
        _name: &'static str,
        _target_offset: isize,
        _field_offset: u8,
        _ref_offset: u8,
        _kind: R,
    ) {
        unreachable!();
    }

    fn dynamic_relocation(
        &mut self,
        _id: DynamicLabel,
        _target_offset: isize,
        _field_offset: u8,
        _ref_offset: u8,
        _kind: R,
    ) {
        unreachable!();
    }

    fn forward_relocation(
        &mut self,
        _name: &'static str,
        _target_offset: isize,
        _field_offset: u8,
        _ref_offset: u8,
        _kind: R,
    ) {
        unreachable!();
    }
}

impl<R: Relocation, const S: usize> Extend<u8> for Assembler<R, S> {
    #[inline(always)]
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        self.buffer.extend(iter);
    }
}

impl<'a, R: Relocation, const S: usize> Extend<&'a u8> for Assembler<R, S> {
    #[inline(always)]
    fn extend<T: IntoIterator<Item = &'a u8>>(&mut self, iter: T) {
        for byte in iter {
            self.buffer.push(*byte);
        }
    }
}

impl<R: Relocation, const S: usize> DynasmApi for Assembler<R, S> {
    #[inline(always)]
    fn offset(&self) -> AssemblyOffset {
        AssemblyOffset(self.buffer.len())
    }

    #[inline(always)]
    fn push(&mut self, byte: u8) {
        self.buffer.push(byte);
    }

    fn align(&mut self, _alignment: usize, _with: u8) {
        unreachable!();
    }
}
