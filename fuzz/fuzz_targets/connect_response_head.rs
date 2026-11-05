#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podnet::fuzzing::connect_response_head(data));
