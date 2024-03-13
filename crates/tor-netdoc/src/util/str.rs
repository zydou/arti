//! String-manipulation utilities

/// Return the position of one string slice within another.
///
/// If `needle` is indeed part of `haystack`, returns some offset
/// `off`, such that `needle` is the same as
/// `&haystack[off..needle.len()]`.
///
/// Returns None if `needle` is not a part of `haystack`.
///
/// Remember, offsets are in bytes, not in characters.
///
/// # Example
/// ```ignore
/// use tor_netdoc::util::str_offset;
/// let quote = "A rose is a rose is a rose."; // -- Gertrude Stein
/// assert_eq!(&quote[2..6], "rose");
/// assert_eq!(str_offset(quote, &quote[2..6]).unwrap(), 2);
/// assert_eq!(&quote[12..16], "rose");
/// assert_eq!(str_offset(quote, &quote[12..16]).unwrap(), 12);
/// assert_eq!(&quote[22..26], "rose");
/// assert_eq!(str_offset(quote, &quote[22..26]).unwrap(), 22);
///
/// assert_eq!(str_offset(quote, "rose"), None);
///
/// assert_eq!(str_offset(&quote[1..], &quote[2..6]), Some(1));
/// assert_eq!(str_offset(&quote[1..5], &quote[2..6]), None);
/// ```
pub(crate) fn str_offset(haystack: &str, needle: &str) -> Option<usize> {
    let needle_start_u = needle.as_ptr() as usize;
    let needle_end_u = needle_start_u + needle.len();
    let haystack_start_u = haystack.as_ptr() as usize;
    let haystack_end_u = haystack_start_u + haystack.len();
    if haystack_start_u <= needle_start_u && needle_end_u <= haystack_end_u {
        Some(needle_start_u - haystack_start_u)
    } else {
        None
    }
}

/// An extent within a given string slice.
///
/// This whole type is probably naughty and shouldn't exist.  We use
/// it only within this crate, to remember where it was that we found
/// parsed objects within the strings we got them from.
#[derive(Clone, Debug)]
pub(crate) struct Extent {
    /// At what position within the original string is this extent, in bytes?
    offset: usize,
    /// How long is this extend, in bytes?
    length: usize,
    /// What was the original string?
    ///
    /// If this doesn't match, there's been an error.
    sliceptr: *const u8,
    /// How long was the original string?
    ///
    /// If this doesn't match, there's been an error.
    slicelen: usize,
}

impl Extent {
    /// Construct a new extent to represent the position of `needle`
    /// within `haystack`.
    ///
    /// Return None if `needle` is not in fact a slice of `haystack`.
    pub(crate) fn new(haystack: &str, needle: &str) -> Option<Extent> {
        str_offset(haystack, needle).map(|offset| Extent {
            offset,
            length: needle.len(),
            sliceptr: haystack.as_ptr(),
            slicelen: haystack.len(),
        })
    }
    /// Reconstruct the original `needle` within `haystack`.
    ///
    /// Return None if we're sure that the haystack doesn't match the one
    /// we were originally given.
    ///
    /// Note that it is possible for this to give a bogus result if
    /// provided a new haystack that happens to be at the same
    /// position in memory as the original one.
    pub(crate) fn reconstruct<'a>(&self, haystack: &'a str) -> Option<&'a str> {
        if self.sliceptr != haystack.as_ptr() || self.slicelen != haystack.len() {
            None
        } else {
            haystack.get(self.offset..self.offset + self.length)
        }
    }
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    #[test]
    fn test_str_offset() {
        use super::str_offset;
        let quote = "A rose is a rose is a rose."; // -- Gertrude Stein
        assert_eq!(&quote[2..6], "rose");
        assert_eq!(str_offset(quote, &quote[2..6]).unwrap(), 2);
        assert_eq!(&quote[12..16], "rose");
        assert_eq!(str_offset(quote, &quote[12..16]).unwrap(), 12);
        assert_eq!(&quote[22..26], "rose");
        assert_eq!(str_offset(quote, &quote[22..26]).unwrap(), 22);

        assert_eq!(str_offset(quote, "rose"), None);

        assert_eq!(str_offset(&quote[1..], &quote[2..6]), Some(1));
        assert_eq!(str_offset(&quote[1..5], &quote[2..6]), None);
    }

    #[test]
    fn test_extent() {
        use super::Extent;
        let quote = "What is a winter wedding a winter wedding."; // -- ibid
        assert_eq!(&quote[10..16], "winter");
        let ex = Extent::new(quote, &quote[10..16]).unwrap();
        let s = ex.reconstruct(quote).unwrap();
        assert_eq!(s, "winter");

        assert!(Extent::new(quote, "winter").is_none());
        assert!(ex.reconstruct("Hello world").is_none());
    }
}
