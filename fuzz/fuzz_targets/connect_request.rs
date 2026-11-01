#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| cfrs::fuzzing::connect_request(data));
