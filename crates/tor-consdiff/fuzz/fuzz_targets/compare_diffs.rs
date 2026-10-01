#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let parts: Vec<_> = s.splitn(2, "=====\n").collect();
        if parts.len() == 2 {
            let orig = parts[0];
            let diff = parts[1];
            let out1 = tor_consdiff::apply_diff_trivial(orig, diff);
            let out2 =
                tor_consdiff::apply_diff(orig, diff, None, tor_consdiff::DiffSizeStrictness::None);
            // dbg!(&out1);
            // dbg!(&out2);
            assert_eq!(out1.is_err(), out2.is_err());
            match (out1, out2) {
                (Ok(a), Ok(b)) => assert_eq!(a.to_string(), b.to_string()),
                (_, _) => (),
            }
        }
    }
});
