//! Code for parsing the relay specific config options.

use tor_netdoc::types::Nickname;

/// Return the default relay nickname. Again, taken from C-tor.
pub(crate) fn default_nickname() -> Nickname {
    "Unnamed".parse().expect("Default nickname is invalid")
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
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;
    use tor_netdoc::types::ContactInfo;

    #[test]
    fn contact_valid() {
        for info in [
            "Arti relay team",
            "8096R/13371337 Rosa Park<rosa.park@awesome.com>",
            "trailing whitespace is fine  ",
            "Du français avec accent ééé, on aime!",
        ] {
            let contact: ContactInfo = info.parse().unwrap();
            assert_eq!(contact.to_string(), info);
        }
    }

    #[test]
    fn contact_invalid() {
        for info in [
            " leading whitespace", // Leading whitespace
            "\tleading tab",       // Same but with a tab
            "two\nlines",          // New line
            "trailing newline\n",  // Trailing new line
        ] {
            assert!(info.parse::<ContactInfo>().is_err());
        }
    }

    #[test]
    fn nickname_valid() {
        // Some basic names that are all valid.
        for name in ["Unnamed", "a", "42", "Op3nB0rd3rs", "A".repeat(19).as_str()] {
            let nickname: Nickname = name.parse().unwrap();
            assert_eq!(nickname.to_string(), name);
        }
    }

    #[test]
    fn nickname_invalid() {
        for name in [
            "",                      // Too short
            "A".repeat(20).as_str(), // Too long
            "with space",            // Windows spaces...
            "under_score",           // Non alphanumeric
            "dash-ing",              // Non alphanumeric
            "unicödé",               // The French... :P
        ] {
            assert!(name.parse::<Nickname>().is_err());
        }
    }
}
