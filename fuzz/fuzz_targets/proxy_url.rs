#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| cfrs::fuzzing::proxy_url(data));
