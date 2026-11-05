#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| podnet::fuzzing::h2_header_block(data));
