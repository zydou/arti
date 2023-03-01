#![no_main]
use libfuzzer_sys::fuzz_target;
use tor_cell::chancell::codec::ChannelCodec;
use tor_cell::chancell::msg::AnyChanMsg;

fuzz_target!(|data: &[u8]| {
    let mut bytes = data.into();
    let _ = ChannelCodec::new(4).decode_cell::<AnyChanMsg>(&mut bytes);
});
