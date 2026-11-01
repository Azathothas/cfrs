#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| cfrs::fuzzing::doh_json(data));
