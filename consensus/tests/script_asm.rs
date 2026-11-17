use core::fmt;
use primitives::{
    opcodes::{all, Opcode},
    script::{Builder as BuilderT, PushBytesBuf, ScriptBuf as ScriptBufT},
};
use std::collections::HashMap;
use std::sync::OnceLock;

type Builder = BuilderT<()>;
type ScriptBuf = ScriptBufT<()>;

#[derive(Debug)]
pub enum ParseScriptError {
    BadDecimal(String),
    DecimalOutOfRange(i128),
    BadOpcode(String),
}

impl fmt::Display for ParseScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseScriptError::BadDecimal(tok) => write!(f, "bad decimal literal `{tok}`"),
            ParseScriptError::DecimalOutOfRange(n) => {
                write!(f, "decimal out of range: {n} (allowed: -0xffffffff..=0xffffffff)")
            }
            ParseScriptError::BadOpcode(tok) => write!(f, "unknown opcode `{tok}`"),
        }
    }
}

type OpcodeMap = HashMap<String, Opcode>;
static LEGACY_OPCODE_MAP: OnceLock<OpcodeMap> = OnceLock::new();

fn core_opcode_map() -> &'static OpcodeMap {
    LEGACY_OPCODE_MAP.get_or_init(build_core_opcode_map)
}

fn build_core_opcode_map() -> OpcodeMap {
    let mut map = HashMap::new();
    for byte in 0u8..=255 {
        if byte == all::OP_CHECKSIGADD.to_u8() {
            // Preserve the historical textual-parser behavior that excludes
            // OP_CHECKSIGADD from asm token parsing.
            continue;
        }
        let opcode = Opcode::from(byte);
        let name = match byte {
            0xb1 => "OP_CHECKLOCKTIMEVERIFY".into(),
            0xb2 => "OP_CHECKSEQUENCEVERIFY".into(),
            _ => opcode.to_string(),
        };

        if name == "OP_UNKNOWN" {
            continue;
        }
        let is_reserved = name == "OP_RESERVED";
        if byte < all::OP_NOP.to_u8() && !is_reserved {
            continue;
        }

        map.insert(name.clone(), opcode);
        if let Some(bare) = name.strip_prefix("OP_") {
            map.insert(bare.to_string(), opcode);
        }
    }
    map
}

pub fn parse_opcode(token: &str) -> Result<Opcode, ParseScriptError> {
    core_opcode_map()
        .get(token)
        .copied()
        .ok_or_else(|| ParseScriptError::BadOpcode(token.to_string()))
}

fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn parse_decimal_i64(s: &str) -> Result<i64, ParseScriptError> {
    let value = s.parse().map_err(|_| ParseScriptError::BadDecimal(s.to_string()))?;
    const LIM: i128 = 0xffff_ffff;
    if !(-LIM..=LIM).contains(&value) {
        return Err(ParseScriptError::DecimalOutOfRange(value));
    }
    Ok(value as i64)
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn parse_hex_bytes(s: &str) -> Vec<u8> {
    fn hex_nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("invalid hex literal"),
        }
    }

    let bytes = s.as_bytes();
    assert!(bytes.len().is_multiple_of(2), "hex literal must have even length");
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        out.push((hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]));
    }
    out
}

enum Token<'a> {
    Decimal(i64),
    Hex(Vec<u8>),
    Quoted(&'a str),
    Opcode(Opcode),
}

fn classify(token: &str) -> Result<Token<'_>, ParseScriptError> {
    if is_all_digits(token)
        || (token.starts_with('-') && token.len() > 1 && is_all_digits(&token[1..]))
    {
        Ok(Token::Decimal(parse_decimal_i64(token)?))
    } else if token.starts_with("0x") && token.len() > 2 && is_hex(&token[2..]) {
        Ok(Token::Hex(parse_hex_bytes(&token[2..])))
    } else if token.len() >= 2 && token.starts_with('\'') && token.ends_with('\'') {
        Ok(Token::Quoted(&token[1..token.len() - 1]))
    } else {
        Ok(Token::Opcode(parse_opcode(token)?))
    }
}

pub fn parse_script(s: &str) -> Result<ScriptBuf, ParseScriptError> {
    if s.trim().is_empty() {
        return Ok(ScriptBuf::new());
    }
    let mut out = Vec::new();
    for part in s.split([' ', '\t', '\n']).filter(|w| !w.is_empty()) {
        match classify(part)? {
            Token::Decimal(value) => {
                out.extend_from_slice(
                    Builder::new()
                        .push_int(value as i32)
                        .expect("decimal script integer in range")
                        .into_script()
                        .as_bytes(),
                );
            }
            Token::Hex(bytes) => out.extend_from_slice(&bytes),
            Token::Quoted(body) => {
                let push = PushBytesBuf::try_from(body.as_bytes().to_vec())
                    .map_err(|_| ParseScriptError::BadOpcode(part.to_string()))?;
                out.extend_from_slice(Builder::new().push_slice(push).into_script().as_bytes());
            }
            Token::Opcode(op) => {
                out.extend_from_slice(Builder::new().push_opcode(op).into_script().as_bytes())
            }
        }
    }
    Ok(ScriptBuf::from_bytes(out))
}
