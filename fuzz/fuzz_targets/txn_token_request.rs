//! A token request to the Transaction Token Service is a set of decoded form
//! parameters, every name and value chosen by the client. `request_context`
//! and `request_details` are JSON parsed from those values.
//!
//! The input is one `name=value` pair per line; a line without `=` is a name
//! with an empty value. Splitting on lines rather than `&` lets values carry
//! any character a decoded form value can.
#![no_main]

use libfuzzer_sys::fuzz_target;
use visado_txn_token::TokenRequest;

fuzz_target!(|data: &str| {
    let pairs = data
        .split('\n')
        .map(|line| line.split_once('=').unwrap_or((line, "")));
    let _ = TokenRequest::from_form(pairs);
});
