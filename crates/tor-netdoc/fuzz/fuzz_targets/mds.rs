#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_netdoc::doc::microdesc::MicrodescReader;
use tor_netdoc::AllowAnnotations;

fuzz_target!(|data: (bool, &str)| {
    let allow = if data.0 {
        AllowAnnotations::AnnotationsAllowed
    } else {
        AllowAnnotations::AnnotationsNotAllowed
    };

    if let Ok(md) = MicrodescReader::new(data.1, &allow) {
        for _ in md {}
    }
});
