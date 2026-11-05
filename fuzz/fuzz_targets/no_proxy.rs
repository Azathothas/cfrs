#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podnet::fuzzing::no_proxy(data));
