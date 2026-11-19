//! An AuthZEN evaluation response body comes from the PDP over the network,
//! so it is parsed before anything about it is known to be sane.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = visado_authzen::parse_response(data);
});
