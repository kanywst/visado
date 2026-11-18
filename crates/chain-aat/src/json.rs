//! A strict JSON parser that keeps numbers as written, rejects duplicate
//! member names, and serializes values as JCS (RFC 8785).
//!
//! AAT needs all three (§3.4, §8 steps 3b, 4b, 6b, 7b and 7f), and a parser
//! that rounds numbers to doubles cannot tell an admissible number from an
//! inadmissible one.

use std::collections::HashSet;
use std::fmt::Write as _;

/// The deepest nesting accepted. Deeper input is rejected before recursion
/// can exhaust the stack.
const MAX_NESTING: usize = 256;

/// Why a document did not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParseError {
    Syntax,
    DuplicateMember,
    TooDeep,
}

/// A JSON number, kept as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Number(String);

/// A JSON value. Objects keep member order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub(crate) fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Self::Object(members) => Some(members),
            _ => None,
        }
    }

    pub(crate) fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// An integer written with no fraction or exponent part (§3.2).
    pub(crate) fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Number(n) => n.as_integer(),
            _ => None,
        }
    }

    /// A non-negative integer written with no fraction or exponent part.
    pub(crate) fn as_count(&self) -> Option<u32> {
        self.as_integer().and_then(|n| u32::try_from(n).ok())
    }

    /// Whether every number in this value is admissible (§3.4).
    pub(crate) fn numbers_admissible(&self) -> bool {
        match self {
            Self::Number(n) => n.is_admissible(),
            Self::Array(items) => items.iter().all(Self::numbers_admissible),
            Self::Object(members) => members.iter().all(|(_, v)| v.numbers_admissible()),
            Self::Null | Self::Bool(_) | Self::String(_) => true,
        }
    }

    /// The JCS serialization. Numbers go through their double, so call
    /// [`Value::numbers_admissible`] first where that matters.
    pub(crate) fn jcs(&self) -> String {
        let mut out = String::new();
        self.write_jcs(&mut out);
        out
    }

    fn write_jcs(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(true) => out.push_str("true"),
            Self::Bool(false) => out.push_str("false"),
            Self::Number(n) => out.push_str(&n.jcs().unwrap_or_else(|| "null".to_owned())),
            Self::String(s) => write_jcs_string(s, out),
            Self::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_jcs(out);
                }
                out.push(']');
            }
            Self::Object(members) => {
                let mut sorted: Vec<&(String, Value)> = members.iter().collect();
                sorted.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
                out.push('{');
                for (i, (k, v)) in sorted.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_jcs_string(k, out);
                    out.push(':');
                    v.write_jcs(out);
                }
                out.push('}');
            }
        }
    }
}

/// Writes `s` as a JCS string literal (RFC 8785 §3.2.2.2).
pub(crate) fn write_jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

impl Number {
    /// The value as an `i64`, if it is written as an integer.
    pub(crate) fn as_integer(&self) -> Option<i64> {
        if self.0.contains(['.', 'e', 'E']) {
            return None;
        }
        self.0.parse().ok()
    }

    /// The nearest double. Finite for every admissible number.
    pub(crate) fn to_f64(&self) -> f64 {
        self.0.parse().unwrap_or(f64::NAN)
    }

    /// The JCS form: ECMAScript `Number.prototype.toString` of the double.
    /// `None` if the double is not finite.
    pub(crate) fn jcs(&self) -> Option<String> {
        es_number(self.to_f64())
    }

    /// §3.4: the JCS form of the double denotes the same mathematical value
    /// as the number as written.
    pub(crate) fn is_admissible(&self) -> bool {
        self.jcs()
            .is_some_and(|jcs| Decimal::parse(&jcs) == Decimal::parse(&self.0))
    }
}

/// ECMAScript `Number::toString(x)` for a finite double (ECMA-262 §6.1.6.1.20).
fn es_number(x: f64) -> Option<String> {
    if !x.is_finite() {
        return None;
    }
    if x == 0.0 {
        return Some("0".to_owned());
    }
    if x < 0.0 {
        return es_number(-x).map(|s| format!("-{s}"));
    }
    // `{:e}` prints the shortest digits that round-trip, as `d.ddde<exp>`.
    let sci = format!("{x:e}");
    let (mantissa, exp) = sci.split_once('e')?;
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let k = i64::try_from(digits.len()).ok()?;
    let n = exp.parse::<i64>().ok()? + 1;
    let out = if k <= n && n <= 21 {
        let zeros = usize::try_from(n - k).ok()?;
        format!("{digits}{}", "0".repeat(zeros))
    } else if 0 < n && n <= 21 {
        let split = usize::try_from(n).ok()?;
        format!("{}.{}", &digits[..split], &digits[split..])
    } else if -6 < n && n <= 0 {
        let zeros = usize::try_from(-n).ok()?;
        format!("0.{}{digits}", "0".repeat(zeros))
    } else {
        let e = n - 1;
        let sign = if e < 0 { '-' } else { '+' };
        if k == 1 {
            format!("{digits}e{sign}{}", e.abs())
        } else {
            format!("{}.{}e{sign}{}", &digits[..1], &digits[1..], e.abs())
        }
    };
    Some(out)
}

/// An exact decimal: `(-1)^negative × digits × 10^exponent`, normalized so
/// equal values compare equal.
#[derive(Debug, PartialEq, Eq)]
struct Decimal {
    negative: bool,
    digits: String,
    exponent: i128,
}

impl Decimal {
    /// Parses JSON number syntax. The caller passes text the parser or
    /// [`es_number`] produced, so it is well-formed.
    fn parse(text: &str) -> Self {
        let (negative, rest) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let (mantissa, exp) = match rest.find(['e', 'E']) {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, "0"),
        };
        let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        let exp = parse_exponent(exp);
        let frac_len = i128::try_from(frac.len()).unwrap_or(i128::MAX);
        let mut digits: String = int.chars().chain(frac.chars()).collect();
        let mut exponent = exp.saturating_sub(frac_len);
        let trimmed = digits.trim_start_matches('0').len();
        digits.drain(..digits.len() - trimmed);
        while digits.ends_with('0') {
            digits.pop();
            exponent = exponent.saturating_add(1);
        }
        if digits.is_empty() {
            return Self {
                negative: false,
                digits,
                exponent: 0,
            };
        }
        Self {
            negative,
            digits,
            exponent,
        }
    }
}

/// An exponent, saturating far outside the range of a double.
fn parse_exponent(text: &str) -> i128 {
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let mut value: i128 = 0;
    for digit in digits.chars().filter_map(|c| c.to_digit(10)) {
        value = value
            .saturating_mul(10)
            .saturating_add(i128::from(digit))
            .min(1 << 64);
    }
    if negative { -value } else { value }
}

/// Parses a complete JSON document.
pub(crate) fn parse(input: &[u8]) -> Result<Value, ParseError> {
    let mut p = Parser { input, pos: 0 };
    p.skip_ws();
    let value = p.value(0)?;
    p.skip_ws();
    if p.pos != input.len() {
        return Err(ParseError::Syntax);
    }
    Ok(value)
}

/// Reads the top-level string member `name` without building the document
/// (§8 step 2c). Returns `None` if the input is not a JSON object, or the
/// member is absent or not a string. With duplicates, the first wins; full
/// parsing rejects them later.
pub(crate) fn top_level_string(input: &[u8], name: &str) -> Option<String> {
    let mut p = Parser { input, pos: 0 };
    p.skip_ws();
    p.expect(b'{').ok()?;
    p.skip_ws();
    let mut found = None;
    if p.peek() == Some(b'}') {
        return None;
    }
    loop {
        p.skip_ws();
        let key = p.string().ok()?;
        p.skip_ws();
        p.expect(b':').ok()?;
        p.skip_ws();
        if key == name && found.is_none() {
            if p.peek() != Some(b'"') {
                return None;
            }
            found = Some(p.string().ok()?);
        } else {
            p.skip_value(1).ok()?;
        }
        p.skip_ws();
        match p.next() {
            Some(b',') => {}
            Some(b'}') => break,
            _ => return None,
        }
    }
    p.skip_ws();
    if p.pos != input.len() {
        return None;
    }
    found
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn expect(&mut self, b: u8) -> Result<(), ParseError> {
        if self.next() == Some(b) {
            Ok(())
        } else {
            Err(ParseError::Syntax)
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), ParseError> {
        if self.input.get(self.pos..self.pos + word.len()) == Some(word) {
            self.pos += word.len();
            Ok(())
        } else {
            Err(ParseError::Syntax)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth >= MAX_NESTING {
            return Err(ParseError::TooDeep);
        }
        match self.peek().ok_or(ParseError::Syntax)? {
            b'n' => self.literal(b"null").map(|()| Value::Null),
            b't' => self.literal(b"true").map(|()| Value::Bool(true)),
            b'f' => self.literal(b"false").map(|()| Value::Bool(false)),
            b'"' => self.string().map(Value::String),
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                loop {
                    self.skip_ws();
                    items.push(self.value(depth + 1)?);
                    self.skip_ws();
                    match self.next() {
                        Some(b',') => {}
                        Some(b']') => return Ok(Value::Array(items)),
                        _ => return Err(ParseError::Syntax),
                    }
                }
            }
            b'{' => {
                self.pos += 1;
                let mut members: Vec<(String, Value)> = Vec::new();
                let mut seen: HashSet<String> = HashSet::new();
                self.skip_ws();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(Value::Object(members));
                }
                loop {
                    self.skip_ws();
                    let key = self.string()?;
                    if !seen.insert(key.clone()) {
                        return Err(ParseError::DuplicateMember);
                    }
                    self.skip_ws();
                    self.expect(b':')?;
                    self.skip_ws();
                    let value = self.value(depth + 1)?;
                    members.push((key, value));
                    self.skip_ws();
                    match self.next() {
                        Some(b',') => {}
                        Some(b'}') => return Ok(Value::Object(members)),
                        _ => return Err(ParseError::Syntax),
                    }
                }
            }
            _ => self.number().map(Value::Number),
        }
    }

    fn skip_value(&mut self, depth: usize) -> Result<(), ParseError> {
        if depth >= MAX_NESTING {
            return Err(ParseError::TooDeep);
        }
        match self.peek().ok_or(ParseError::Syntax)? {
            b'n' => self.literal(b"null"),
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'"' => self.string().map(drop),
            open @ (b'[' | b'{') => {
                let close = if open == b'[' { b']' } else { b'}' };
                self.pos += 1;
                self.skip_ws();
                if self.peek() == Some(close) {
                    self.pos += 1;
                    return Ok(());
                }
                loop {
                    self.skip_ws();
                    if open == b'{' {
                        self.string()?;
                        self.skip_ws();
                        self.expect(b':')?;
                        self.skip_ws();
                    }
                    self.skip_value(depth + 1)?;
                    self.skip_ws();
                    match self.next() {
                        Some(b',') => {}
                        Some(b) if b == close => return Ok(()),
                        _ => return Err(ParseError::Syntax),
                    }
                }
            }
            _ => self.number().map(drop),
        }
    }

    fn number(&mut self) -> Result<Number, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.next() {
            Some(b'0') => {}
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(ParseError::Syntax),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            self.one_or_more_digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            self.one_or_more_digits()?;
        }
        let text =
            std::str::from_utf8(&self.input[start..self.pos]).map_err(|_| ParseError::Syntax)?;
        Ok(Number(text.to_owned()))
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
    }

    fn one_or_more_digits(&mut self) -> Result<(), ParseError> {
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(ParseError::Syntax);
        }
        self.digits();
        Ok(())
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let start = self.pos;
            while matches!(self.peek(), Some(b) if b != b'"' && b != b'\\' && b >= 0x20) {
                self.pos += 1;
            }
            let run = std::str::from_utf8(&self.input[start..self.pos])
                .map_err(|_| ParseError::Syntax)?;
            out.push_str(run);
            match self.next() {
                Some(b'"') => return Ok(out),
                Some(b'\\') => {}
                _ => return Err(ParseError::Syntax),
            }
            match self.next() {
                Some(b'"') => out.push('"'),
                Some(b'\\') => out.push('\\'),
                Some(b'/') => out.push('/'),
                Some(b'b') => out.push('\u{8}'),
                Some(b'f') => out.push('\u{c}'),
                Some(b'n') => out.push('\n'),
                Some(b'r') => out.push('\r'),
                Some(b't') => out.push('\t'),
                Some(b'u') => {
                    let first = self.hex4()?;
                    let code = if (0xD800..0xDC00).contains(&first) {
                        if self.next() != Some(b'\\') || self.next() != Some(b'u') {
                            return Err(ParseError::Syntax);
                        }
                        let second = self.hex4()?;
                        if !(0xDC00..0xE000).contains(&second) {
                            return Err(ParseError::Syntax);
                        }
                        0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                    } else {
                        first
                    };
                    out.push(char::from_u32(code).ok_or(ParseError::Syntax)?);
                }
                _ => return Err(ParseError::Syntax),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let mut value = 0;
        for _ in 0..4 {
            let digit = char::from(self.next().ok_or(ParseError::Syntax)?)
                .to_digit(16)
                .ok_or(ParseError::Syntax)?;
            value = value * 16 + digit;
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{ParseError, Value, parse, top_level_string};

    fn number(text: &str) -> super::Number {
        match parse(text.as_bytes()) {
            Ok(Value::Number(n)) => n,
            other => panic!("not a number: {other:?}"),
        }
    }

    #[test]
    fn es_number_formatting() {
        for (input, jcs) in [
            ("0", "0"),
            ("-0", "0"),
            ("1", "1"),
            ("0.1", "0.1"),
            ("1e20", "100000000000000000000"),
            ("1e21", "1e+21"),
            ("1.5e-7", "1.5e-7"),
            ("0.000001", "0.000001"),
            ("123.456", "123.456"),
            ("-2.5", "-2.5"),
            ("9007199254740993", "9007199254740992"),
        ] {
            assert_eq!(number(input).jcs().as_deref(), Some(jcs), "{input}");
        }
    }

    #[test]
    fn admissibility() {
        for ok in [
            "0.1",
            "1e20",
            "9007199254740994",
            "1152921504606847000",
            "-0",
            "1.0",
        ] {
            assert!(number(ok).is_admissible(), "{ok}");
        }
        for bad in [
            "9007199254740993",
            "1.00000000000000001",
            "1152921504606846976",
            "1e400",
            "1e-400",
        ] {
            assert!(!number(bad).is_admissible(), "{bad}");
        }
    }

    #[test]
    fn duplicates_and_depth() {
        assert_eq!(parse(br#"{"a":1,"a":2}"#), Err(ParseError::DuplicateMember));
        let deep = "[".repeat(300) + &"]".repeat(300);
        assert_eq!(parse(deep.as_bytes()), Err(ParseError::TooDeep));
        assert_eq!(parse(b"[1,]"), Err(ParseError::Syntax));
        assert_eq!(parse(b"01"), Err(ParseError::Syntax));
    }

    #[test]
    fn large_object_duplicates() {
        let members: Vec<String> = (0..20_000).map(|i| format!("\"k{i}\":{i}")).collect();
        let unique = format!("{{{}}}", members.join(","));
        let value = parse(unique.as_bytes()).unwrap();
        assert_eq!(value.as_object().map(<[_]>::len), Some(20_000));
        let last_dup = format!("{{{},\"k0\":0}}", members.join(","));
        assert_eq!(parse(last_dup.as_bytes()), Err(ParseError::DuplicateMember));
    }

    #[test]
    fn jcs_sorts_and_escapes() {
        let v = parse("{\"b\":[1e1,\"\\u0001\"],\"a\":true}".as_bytes()).unwrap();
        assert_eq!(v.jcs(), "{\"a\":true,\"b\":[10,\"\\u0001\"]}");
    }

    #[test]
    fn top_level_extraction() {
        assert_eq!(
            top_level_string(br#"{"x":{"jti":"inner"},"jti":"outer"}"#, "jti").as_deref(),
            Some("outer")
        );
        assert_eq!(top_level_string(br#"{"jti":7}"#, "jti"), None);
        assert_eq!(top_level_string(br#"{"jti":"a""#, "jti"), None);
    }
}
