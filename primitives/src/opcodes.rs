// SPDX-License-Identifier: CC0-1.0

//! Tidecoin script opcodes.

#![allow(non_camel_case_types)]

use core::fmt;

use self::all::{
    OP_1, OP_16, OP_1NEGATE, OP_2DIV, OP_2MUL, OP_AND, OP_CAT, OP_CHECKSIGADD, OP_DIV,
    OP_INVALIDOPCODE, OP_INVERT, OP_LEFT, OP_LSHIFT, OP_MOD, OP_MUL, OP_NOP, OP_NOP1, OP_NOP10,
    OP_OR, OP_PUSHBYTES_75, OP_RESERVED, OP_RESERVED1, OP_RESERVED2, OP_RETURN, OP_RIGHT,
    OP_RSHIFT, OP_SUBSTR, OP_VER, OP_VERIF, OP_VERNOTIF, OP_XOR,
};

const PUSHBYTE_NAMES: [&str; 76] = [
    "OP_PUSHBYTES_0",
    "OP_PUSHBYTES_1",
    "OP_PUSHBYTES_2",
    "OP_PUSHBYTES_3",
    "OP_PUSHBYTES_4",
    "OP_PUSHBYTES_5",
    "OP_PUSHBYTES_6",
    "OP_PUSHBYTES_7",
    "OP_PUSHBYTES_8",
    "OP_PUSHBYTES_9",
    "OP_PUSHBYTES_10",
    "OP_PUSHBYTES_11",
    "OP_PUSHBYTES_12",
    "OP_PUSHBYTES_13",
    "OP_PUSHBYTES_14",
    "OP_PUSHBYTES_15",
    "OP_PUSHBYTES_16",
    "OP_PUSHBYTES_17",
    "OP_PUSHBYTES_18",
    "OP_PUSHBYTES_19",
    "OP_PUSHBYTES_20",
    "OP_PUSHBYTES_21",
    "OP_PUSHBYTES_22",
    "OP_PUSHBYTES_23",
    "OP_PUSHBYTES_24",
    "OP_PUSHBYTES_25",
    "OP_PUSHBYTES_26",
    "OP_PUSHBYTES_27",
    "OP_PUSHBYTES_28",
    "OP_PUSHBYTES_29",
    "OP_PUSHBYTES_30",
    "OP_PUSHBYTES_31",
    "OP_PUSHBYTES_32",
    "OP_PUSHBYTES_33",
    "OP_PUSHBYTES_34",
    "OP_PUSHBYTES_35",
    "OP_PUSHBYTES_36",
    "OP_PUSHBYTES_37",
    "OP_PUSHBYTES_38",
    "OP_PUSHBYTES_39",
    "OP_PUSHBYTES_40",
    "OP_PUSHBYTES_41",
    "OP_PUSHBYTES_42",
    "OP_PUSHBYTES_43",
    "OP_PUSHBYTES_44",
    "OP_PUSHBYTES_45",
    "OP_PUSHBYTES_46",
    "OP_PUSHBYTES_47",
    "OP_PUSHBYTES_48",
    "OP_PUSHBYTES_49",
    "OP_PUSHBYTES_50",
    "OP_PUSHBYTES_51",
    "OP_PUSHBYTES_52",
    "OP_PUSHBYTES_53",
    "OP_PUSHBYTES_54",
    "OP_PUSHBYTES_55",
    "OP_PUSHBYTES_56",
    "OP_PUSHBYTES_57",
    "OP_PUSHBYTES_58",
    "OP_PUSHBYTES_59",
    "OP_PUSHBYTES_60",
    "OP_PUSHBYTES_61",
    "OP_PUSHBYTES_62",
    "OP_PUSHBYTES_63",
    "OP_PUSHBYTES_64",
    "OP_PUSHBYTES_65",
    "OP_PUSHBYTES_66",
    "OP_PUSHBYTES_67",
    "OP_PUSHBYTES_68",
    "OP_PUSHBYTES_69",
    "OP_PUSHBYTES_70",
    "OP_PUSHBYTES_71",
    "OP_PUSHBYTES_72",
    "OP_PUSHBYTES_73",
    "OP_PUSHBYTES_74",
    "OP_PUSHBYTES_75",
];

const OP_RETURN_NAMES: [&str; 68] = [
    "OP_RETURN_187",
    "OP_RETURN_188",
    "OP_RETURN_189",
    "OP_RETURN_190",
    "OP_RETURN_191",
    "OP_RETURN_192",
    "OP_RETURN_193",
    "OP_RETURN_194",
    "OP_RETURN_195",
    "OP_RETURN_196",
    "OP_RETURN_197",
    "OP_RETURN_198",
    "OP_RETURN_199",
    "OP_RETURN_200",
    "OP_RETURN_201",
    "OP_RETURN_202",
    "OP_RETURN_203",
    "OP_RETURN_204",
    "OP_RETURN_205",
    "OP_RETURN_206",
    "OP_RETURN_207",
    "OP_RETURN_208",
    "OP_RETURN_209",
    "OP_RETURN_210",
    "OP_RETURN_211",
    "OP_RETURN_212",
    "OP_RETURN_213",
    "OP_RETURN_214",
    "OP_RETURN_215",
    "OP_RETURN_216",
    "OP_RETURN_217",
    "OP_RETURN_218",
    "OP_RETURN_219",
    "OP_RETURN_220",
    "OP_RETURN_221",
    "OP_RETURN_222",
    "OP_RETURN_223",
    "OP_RETURN_224",
    "OP_RETURN_225",
    "OP_RETURN_226",
    "OP_RETURN_227",
    "OP_RETURN_228",
    "OP_RETURN_229",
    "OP_RETURN_230",
    "OP_RETURN_231",
    "OP_RETURN_232",
    "OP_RETURN_233",
    "OP_RETURN_234",
    "OP_RETURN_235",
    "OP_RETURN_236",
    "OP_RETURN_237",
    "OP_RETURN_238",
    "OP_RETURN_239",
    "OP_RETURN_240",
    "OP_RETURN_241",
    "OP_RETURN_242",
    "OP_RETURN_243",
    "OP_RETURN_244",
    "OP_RETURN_245",
    "OP_RETURN_246",
    "OP_RETURN_247",
    "OP_RETURN_248",
    "OP_RETURN_249",
    "OP_RETURN_250",
    "OP_RETURN_251",
    "OP_RETURN_252",
    "OP_RETURN_253",
    "OP_RETURN_254",
];

/// A script opcode.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Opcode {
    code: u8,
}

impl Opcode {
    /// Returns the raw opcode byte.
    #[inline]
    pub const fn to_u8(self) -> u8 {
        self.code
    }

    /// Returns the opcode display name.
    #[inline]
    #[allow(clippy::too_many_lines)]
    pub fn as_str(self) -> &'static str {
        match self.code {
            0x00..=0x4b => PUSHBYTE_NAMES[usize::from(self.code)],
            0x4c => "OP_PUSHDATA1",
            0x4d => "OP_PUSHDATA2",
            0x4e => "OP_PUSHDATA4",
            0x4f => "OP_1NEGATE",
            0x50 => "OP_RESERVED",
            0x51 => "OP_1",
            0x52 => "OP_2",
            0x53 => "OP_3",
            0x54 => "OP_4",
            0x55 => "OP_5",
            0x56 => "OP_6",
            0x57 => "OP_7",
            0x58 => "OP_8",
            0x59 => "OP_9",
            0x5a => "OP_10",
            0x5b => "OP_11",
            0x5c => "OP_12",
            0x5d => "OP_13",
            0x5e => "OP_14",
            0x5f => "OP_15",
            0x60 => "OP_16",
            0x61 => "OP_NOP",
            0x62 => "OP_VER",
            0x63 => "OP_IF",
            0x64 => "OP_NOTIF",
            0x65 => "OP_VERIF",
            0x66 => "OP_VERNOTIF",
            0x67 => "OP_ELSE",
            0x68 => "OP_ENDIF",
            0x69 => "OP_VERIFY",
            0x6a => "OP_RETURN",
            0x6b => "OP_TOALTSTACK",
            0x6c => "OP_FROMALTSTACK",
            0x6d => "OP_2DROP",
            0x6e => "OP_2DUP",
            0x6f => "OP_3DUP",
            0x70 => "OP_2OVER",
            0x71 => "OP_2ROT",
            0x72 => "OP_2SWAP",
            0x73 => "OP_IFDUP",
            0x74 => "OP_DEPTH",
            0x75 => "OP_DROP",
            0x76 => "OP_DUP",
            0x77 => "OP_NIP",
            0x78 => "OP_OVER",
            0x79 => "OP_PICK",
            0x7a => "OP_ROLL",
            0x7b => "OP_ROT",
            0x7c => "OP_SWAP",
            0x7d => "OP_TUCK",
            0x7e => "OP_CAT",
            0x7f => "OP_SUBSTR",
            0x80 => "OP_LEFT",
            0x81 => "OP_RIGHT",
            0x82 => "OP_SIZE",
            0x83 => "OP_INVERT",
            0x84 => "OP_AND",
            0x85 => "OP_OR",
            0x86 => "OP_XOR",
            0x87 => "OP_EQUAL",
            0x88 => "OP_EQUALVERIFY",
            0x89 => "OP_RESERVED1",
            0x8a => "OP_RESERVED2",
            0x8b => "OP_1ADD",
            0x8c => "OP_1SUB",
            0x8d => "OP_2MUL",
            0x8e => "OP_2DIV",
            0x8f => "OP_NEGATE",
            0x90 => "OP_ABS",
            0x91 => "OP_NOT",
            0x92 => "OP_0NOTEQUAL",
            0x93 => "OP_ADD",
            0x94 => "OP_SUB",
            0x95 => "OP_MUL",
            0x96 => "OP_DIV",
            0x97 => "OP_MOD",
            0x98 => "OP_LSHIFT",
            0x99 => "OP_RSHIFT",
            0x9a => "OP_BOOLAND",
            0x9b => "OP_BOOLOR",
            0x9c => "OP_NUMEQUAL",
            0x9d => "OP_NUMEQUALVERIFY",
            0x9e => "OP_NUMNOTEQUAL",
            0x9f => "OP_LESSTHAN",
            0xa0 => "OP_GREATERTHAN",
            0xa1 => "OP_LESSTHANOREQUAL",
            0xa2 => "OP_GREATERTHANOREQUAL",
            0xa3 => "OP_MIN",
            0xa4 => "OP_MAX",
            0xa5 => "OP_WITHIN",
            0xa6 => "OP_RIPEMD160",
            0xa7 => "OP_SHA1",
            0xa8 => "OP_SHA256",
            0xa9 => "OP_HASH160",
            0xaa => "OP_HASH256",
            0xab => "OP_CODESEPARATOR",
            0xac => "OP_CHECKSIG",
            0xad => "OP_CHECKSIGVERIFY",
            0xae => "OP_CHECKMULTISIG",
            0xaf => "OP_CHECKMULTISIGVERIFY",
            0xb0 => "OP_NOP1",
            0xb1 => "OP_CLTV",
            0xb2 => "OP_CSV",
            0xb3 => "OP_SHA512",
            0xb4 => "OP_NOP5",
            0xb5 => "OP_NOP6",
            0xb6 => "OP_NOP7",
            0xb7 => "OP_NOP8",
            0xb8 => "OP_NOP9",
            0xb9 => "OP_NOP10",
            0xba => "OP_CHECKSIGADD",
            0xbb..=0xfe => OP_RETURN_NAMES[usize::from(self.code - 0xbb)],
            0xff => "OP_INVALIDOPCODE",
        }
    }

    /// Classifies an opcode into a broad execution class.
    #[inline]
    #[must_use]
    pub fn classify(self) -> Class {
        match self {
            OP_VERIF | OP_VERNOTIF | OP_INVALIDOPCODE => Class::IllegalOp,
            #[rustfmt::skip]
            OP_CAT | OP_SUBSTR
            | OP_LEFT | OP_RIGHT
            | OP_INVERT
            | OP_AND | OP_OR | OP_XOR
            | OP_2MUL | OP_2DIV
            | OP_MUL | OP_DIV | OP_MOD
            | OP_LSHIFT | OP_RSHIFT => Class::IllegalOp,
            OP_NOP => Class::NoOp,
            op if op.code >= OP_NOP1.code && op.code <= OP_NOP10.code => Class::NoOp,
            OP_RETURN => Class::ReturnOp,
            OP_RESERVED | OP_RESERVED1 | OP_RESERVED2 | OP_VER => Class::ReturnOp,
            op if op.code >= OP_CHECKSIGADD.code => Class::IllegalOp,
            OP_1NEGATE => Class::PushNum(-1),
            op if op.code >= OP_1.code && op.code <= OP_16.code => {
                Class::PushNum(1 + i32::from(self.code) - i32::from(OP_1.code))
            }
            op if op.code <= OP_PUSHBYTES_75.code => Class::PushBytes(u32::from(self.code)),
            _ => Class::Ordinary(Ordinary::with(self)),
        }
    }

    /// Decodes a PUSHNUM opcode to its numeric value.
    #[inline]
    #[must_use]
    pub const fn decode_pushnum(self) -> Option<u8> {
        const START: u8 = OP_1.code;
        const END: u8 = OP_16.code;
        match self.code {
            START..=END => Some(self.code - START + 1),
            _ => None,
        }
    }
}

impl From<u8> for Opcode {
    #[inline]
    fn from(code: u8) -> Self {
        Self { code }
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Opcode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// Enables wildcard imports to bring into scope only opcode constants.
pub mod all {
    use super::Opcode;

    macro_rules! opcode {
        ($name:ident, $code:expr) => {
            #[doc = concat!("Opcode `", stringify!($name), "`.")]
            pub const $name: Opcode = Opcode { code: $code };
        };
    }

    opcode!(OP_PUSHBYTES_0, 0x00);
    opcode!(OP_PUSHBYTES_1, 0x01);
    opcode!(OP_PUSHBYTES_2, 0x02);
    opcode!(OP_PUSHBYTES_3, 0x03);
    opcode!(OP_PUSHBYTES_4, 0x04);
    opcode!(OP_PUSHBYTES_5, 0x05);
    opcode!(OP_PUSHBYTES_6, 0x06);
    opcode!(OP_PUSHBYTES_7, 0x07);
    opcode!(OP_PUSHBYTES_8, 0x08);
    opcode!(OP_PUSHBYTES_9, 0x09);
    opcode!(OP_PUSHBYTES_10, 0x0a);
    opcode!(OP_PUSHBYTES_11, 0x0b);
    opcode!(OP_PUSHBYTES_12, 0x0c);
    opcode!(OP_PUSHBYTES_13, 0x0d);
    opcode!(OP_PUSHBYTES_14, 0x0e);
    opcode!(OP_PUSHBYTES_15, 0x0f);
    opcode!(OP_PUSHBYTES_16, 0x10);
    opcode!(OP_PUSHBYTES_17, 0x11);
    opcode!(OP_PUSHBYTES_18, 0x12);
    opcode!(OP_PUSHBYTES_19, 0x13);
    opcode!(OP_PUSHBYTES_20, 0x14);
    opcode!(OP_PUSHBYTES_21, 0x15);
    opcode!(OP_PUSHBYTES_22, 0x16);
    opcode!(OP_PUSHBYTES_23, 0x17);
    opcode!(OP_PUSHBYTES_24, 0x18);
    opcode!(OP_PUSHBYTES_25, 0x19);
    opcode!(OP_PUSHBYTES_26, 0x1a);
    opcode!(OP_PUSHBYTES_27, 0x1b);
    opcode!(OP_PUSHBYTES_28, 0x1c);
    opcode!(OP_PUSHBYTES_29, 0x1d);
    opcode!(OP_PUSHBYTES_30, 0x1e);
    opcode!(OP_PUSHBYTES_31, 0x1f);
    opcode!(OP_PUSHBYTES_32, 0x20);
    opcode!(OP_PUSHBYTES_33, 0x21);
    opcode!(OP_PUSHBYTES_34, 0x22);
    opcode!(OP_PUSHBYTES_35, 0x23);
    opcode!(OP_PUSHBYTES_36, 0x24);
    opcode!(OP_PUSHBYTES_37, 0x25);
    opcode!(OP_PUSHBYTES_38, 0x26);
    opcode!(OP_PUSHBYTES_39, 0x27);
    opcode!(OP_PUSHBYTES_40, 0x28);
    opcode!(OP_PUSHBYTES_41, 0x29);
    opcode!(OP_PUSHBYTES_42, 0x2a);
    opcode!(OP_PUSHBYTES_43, 0x2b);
    opcode!(OP_PUSHBYTES_44, 0x2c);
    opcode!(OP_PUSHBYTES_45, 0x2d);
    opcode!(OP_PUSHBYTES_46, 0x2e);
    opcode!(OP_PUSHBYTES_47, 0x2f);
    opcode!(OP_PUSHBYTES_48, 0x30);
    opcode!(OP_PUSHBYTES_49, 0x31);
    opcode!(OP_PUSHBYTES_50, 0x32);
    opcode!(OP_PUSHBYTES_51, 0x33);
    opcode!(OP_PUSHBYTES_52, 0x34);
    opcode!(OP_PUSHBYTES_53, 0x35);
    opcode!(OP_PUSHBYTES_54, 0x36);
    opcode!(OP_PUSHBYTES_55, 0x37);
    opcode!(OP_PUSHBYTES_56, 0x38);
    opcode!(OP_PUSHBYTES_57, 0x39);
    opcode!(OP_PUSHBYTES_58, 0x3a);
    opcode!(OP_PUSHBYTES_59, 0x3b);
    opcode!(OP_PUSHBYTES_60, 0x3c);
    opcode!(OP_PUSHBYTES_61, 0x3d);
    opcode!(OP_PUSHBYTES_62, 0x3e);
    opcode!(OP_PUSHBYTES_63, 0x3f);
    opcode!(OP_PUSHBYTES_64, 0x40);
    opcode!(OP_PUSHBYTES_65, 0x41);
    opcode!(OP_PUSHBYTES_66, 0x42);
    opcode!(OP_PUSHBYTES_67, 0x43);
    opcode!(OP_PUSHBYTES_68, 0x44);
    opcode!(OP_PUSHBYTES_69, 0x45);
    opcode!(OP_PUSHBYTES_70, 0x46);
    opcode!(OP_PUSHBYTES_71, 0x47);
    opcode!(OP_PUSHBYTES_72, 0x48);
    opcode!(OP_PUSHBYTES_73, 0x49);
    opcode!(OP_PUSHBYTES_74, 0x4a);
    opcode!(OP_PUSHBYTES_75, 0x4b);
    opcode!(OP_PUSHDATA1, 0x4c);
    opcode!(OP_PUSHDATA2, 0x4d);
    opcode!(OP_PUSHDATA4, 0x4e);
    opcode!(OP_1NEGATE, 0x4f);
    opcode!(OP_RESERVED, 0x50);
    opcode!(OP_1, 0x51);
    opcode!(OP_2, 0x52);
    opcode!(OP_3, 0x53);
    opcode!(OP_4, 0x54);
    opcode!(OP_5, 0x55);
    opcode!(OP_6, 0x56);
    opcode!(OP_7, 0x57);
    opcode!(OP_8, 0x58);
    opcode!(OP_9, 0x59);
    opcode!(OP_10, 0x5a);
    opcode!(OP_11, 0x5b);
    opcode!(OP_12, 0x5c);
    opcode!(OP_13, 0x5d);
    opcode!(OP_14, 0x5e);
    opcode!(OP_15, 0x5f);
    opcode!(OP_16, 0x60);
    opcode!(OP_NOP, 0x61);
    opcode!(OP_VER, 0x62);
    opcode!(OP_IF, 0x63);
    opcode!(OP_NOTIF, 0x64);
    opcode!(OP_VERIF, 0x65);
    opcode!(OP_VERNOTIF, 0x66);
    opcode!(OP_ELSE, 0x67);
    opcode!(OP_ENDIF, 0x68);
    opcode!(OP_VERIFY, 0x69);
    opcode!(OP_RETURN, 0x6a);
    opcode!(OP_TOALTSTACK, 0x6b);
    opcode!(OP_FROMALTSTACK, 0x6c);
    opcode!(OP_2DROP, 0x6d);
    opcode!(OP_2DUP, 0x6e);
    opcode!(OP_3DUP, 0x6f);
    opcode!(OP_2OVER, 0x70);
    opcode!(OP_2ROT, 0x71);
    opcode!(OP_2SWAP, 0x72);
    opcode!(OP_IFDUP, 0x73);
    opcode!(OP_DEPTH, 0x74);
    opcode!(OP_DROP, 0x75);
    opcode!(OP_DUP, 0x76);
    opcode!(OP_NIP, 0x77);
    opcode!(OP_OVER, 0x78);
    opcode!(OP_PICK, 0x79);
    opcode!(OP_ROLL, 0x7a);
    opcode!(OP_ROT, 0x7b);
    opcode!(OP_SWAP, 0x7c);
    opcode!(OP_TUCK, 0x7d);
    opcode!(OP_CAT, 0x7e);
    opcode!(OP_SUBSTR, 0x7f);
    opcode!(OP_LEFT, 0x80);
    opcode!(OP_RIGHT, 0x81);
    opcode!(OP_SIZE, 0x82);
    opcode!(OP_INVERT, 0x83);
    opcode!(OP_AND, 0x84);
    opcode!(OP_OR, 0x85);
    opcode!(OP_XOR, 0x86);
    opcode!(OP_EQUAL, 0x87);
    opcode!(OP_EQUALVERIFY, 0x88);
    opcode!(OP_RESERVED1, 0x89);
    opcode!(OP_RESERVED2, 0x8a);
    opcode!(OP_1ADD, 0x8b);
    opcode!(OP_1SUB, 0x8c);
    opcode!(OP_2MUL, 0x8d);
    opcode!(OP_2DIV, 0x8e);
    opcode!(OP_NEGATE, 0x8f);
    opcode!(OP_ABS, 0x90);
    opcode!(OP_NOT, 0x91);
    opcode!(OP_0NOTEQUAL, 0x92);
    opcode!(OP_ADD, 0x93);
    opcode!(OP_SUB, 0x94);
    opcode!(OP_MUL, 0x95);
    opcode!(OP_DIV, 0x96);
    opcode!(OP_MOD, 0x97);
    opcode!(OP_LSHIFT, 0x98);
    opcode!(OP_RSHIFT, 0x99);
    opcode!(OP_BOOLAND, 0x9a);
    opcode!(OP_BOOLOR, 0x9b);
    opcode!(OP_NUMEQUAL, 0x9c);
    opcode!(OP_NUMEQUALVERIFY, 0x9d);
    opcode!(OP_NUMNOTEQUAL, 0x9e);
    opcode!(OP_LESSTHAN, 0x9f);
    opcode!(OP_GREATERTHAN, 0xa0);
    opcode!(OP_LESSTHANOREQUAL, 0xa1);
    opcode!(OP_GREATERTHANOREQUAL, 0xa2);
    opcode!(OP_MIN, 0xa3);
    opcode!(OP_MAX, 0xa4);
    opcode!(OP_WITHIN, 0xa5);
    opcode!(OP_RIPEMD160, 0xa6);
    opcode!(OP_SHA1, 0xa7);
    opcode!(OP_SHA256, 0xa8);
    opcode!(OP_HASH160, 0xa9);
    opcode!(OP_HASH256, 0xaa);
    opcode!(OP_CODESEPARATOR, 0xab);
    opcode!(OP_CHECKSIG, 0xac);
    opcode!(OP_CHECKSIGVERIFY, 0xad);
    opcode!(OP_CHECKMULTISIG, 0xae);
    opcode!(OP_CHECKMULTISIGVERIFY, 0xaf);
    opcode!(OP_NOP1, 0xb0);
    opcode!(OP_CLTV, 0xb1);
    opcode!(OP_CSV, 0xb2);
    opcode!(OP_SHA512, 0xb3);
    opcode!(OP_NOP5, 0xb4);
    opcode!(OP_NOP6, 0xb5);
    opcode!(OP_NOP7, 0xb6);
    opcode!(OP_NOP8, 0xb7);
    opcode!(OP_NOP9, 0xb8);
    opcode!(OP_NOP10, 0xb9);
    opcode!(OP_CHECKSIGADD, 0xba);
    opcode!(OP_RETURN_187, 0xbb);
    opcode!(OP_RETURN_188, 0xbc);
    opcode!(OP_RETURN_189, 0xbd);
    opcode!(OP_RETURN_190, 0xbe);
    opcode!(OP_RETURN_191, 0xbf);
    opcode!(OP_RETURN_192, 0xc0);
    opcode!(OP_RETURN_193, 0xc1);
    opcode!(OP_RETURN_194, 0xc2);
    opcode!(OP_RETURN_195, 0xc3);
    opcode!(OP_RETURN_196, 0xc4);
    opcode!(OP_RETURN_197, 0xc5);
    opcode!(OP_RETURN_198, 0xc6);
    opcode!(OP_RETURN_199, 0xc7);
    opcode!(OP_RETURN_200, 0xc8);
    opcode!(OP_RETURN_201, 0xc9);
    opcode!(OP_RETURN_202, 0xca);
    opcode!(OP_RETURN_203, 0xcb);
    opcode!(OP_RETURN_204, 0xcc);
    opcode!(OP_RETURN_205, 0xcd);
    opcode!(OP_RETURN_206, 0xce);
    opcode!(OP_RETURN_207, 0xcf);
    opcode!(OP_RETURN_208, 0xd0);
    opcode!(OP_RETURN_209, 0xd1);
    opcode!(OP_RETURN_210, 0xd2);
    opcode!(OP_RETURN_211, 0xd3);
    opcode!(OP_RETURN_212, 0xd4);
    opcode!(OP_RETURN_213, 0xd5);
    opcode!(OP_RETURN_214, 0xd6);
    opcode!(OP_RETURN_215, 0xd7);
    opcode!(OP_RETURN_216, 0xd8);
    opcode!(OP_RETURN_217, 0xd9);
    opcode!(OP_RETURN_218, 0xda);
    opcode!(OP_RETURN_219, 0xdb);
    opcode!(OP_RETURN_220, 0xdc);
    opcode!(OP_RETURN_221, 0xdd);
    opcode!(OP_RETURN_222, 0xde);
    opcode!(OP_RETURN_223, 0xdf);
    opcode!(OP_RETURN_224, 0xe0);
    opcode!(OP_RETURN_225, 0xe1);
    opcode!(OP_RETURN_226, 0xe2);
    opcode!(OP_RETURN_227, 0xe3);
    opcode!(OP_RETURN_228, 0xe4);
    opcode!(OP_RETURN_229, 0xe5);
    opcode!(OP_RETURN_230, 0xe6);
    opcode!(OP_RETURN_231, 0xe7);
    opcode!(OP_RETURN_232, 0xe8);
    opcode!(OP_RETURN_233, 0xe9);
    opcode!(OP_RETURN_234, 0xea);
    opcode!(OP_RETURN_235, 0xeb);
    opcode!(OP_RETURN_236, 0xec);
    opcode!(OP_RETURN_237, 0xed);
    opcode!(OP_RETURN_238, 0xee);
    opcode!(OP_RETURN_239, 0xef);
    opcode!(OP_RETURN_240, 0xf0);
    opcode!(OP_RETURN_241, 0xf1);
    opcode!(OP_RETURN_242, 0xf2);
    opcode!(OP_RETURN_243, 0xf3);
    opcode!(OP_RETURN_244, 0xf4);
    opcode!(OP_RETURN_245, 0xf5);
    opcode!(OP_RETURN_246, 0xf6);
    opcode!(OP_RETURN_247, 0xf7);
    opcode!(OP_RETURN_248, 0xf8);
    opcode!(OP_RETURN_249, 0xf9);
    opcode!(OP_RETURN_250, 0xfa);
    opcode!(OP_RETURN_251, 0xfb);
    opcode!(OP_RETURN_252, 0xfc);
    opcode!(OP_RETURN_253, 0xfd);
    opcode!(OP_RETURN_254, 0xfe);
    opcode!(OP_INVALIDOPCODE, 0xff);

    #[allow(missing_docs)]
    pub const OP_0: Opcode = OP_PUSHBYTES_0;
    #[allow(missing_docs)]
    pub const OP_FALSE: Opcode = OP_PUSHBYTES_0;
    #[allow(missing_docs)]
    pub const OP_TRUE: Opcode = OP_1;
    #[allow(missing_docs)]
    pub const OP_NOP2: Opcode = OP_CLTV;
    #[allow(missing_docs)]
    pub const OP_NOP3: Opcode = OP_CSV;
    #[allow(missing_docs)]
    pub const OP_NOP4: Opcode = OP_SHA512;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_NEG1: Opcode = OP_1NEGATE;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_1: Opcode = OP_1;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_2: Opcode = OP_2;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_3: Opcode = OP_3;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_4: Opcode = OP_4;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_5: Opcode = OP_5;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_6: Opcode = OP_6;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_7: Opcode = OP_7;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_8: Opcode = OP_8;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_9: Opcode = OP_9;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_10: Opcode = OP_10;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_11: Opcode = OP_11;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_12: Opcode = OP_12;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_13: Opcode = OP_13;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_14: Opcode = OP_14;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_15: Opcode = OP_15;
    #[allow(missing_docs)]
    pub const OP_PUSHNUM_16: Opcode = OP_16;
}

/// Broad categories of opcodes with similar execution behavior.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Class {
    /// Pushes the given number onto the stack.
    PushNum(i32),
    /// Pushes the given number of bytes onto the stack.
    PushBytes(u32),
    /// Fails the script if executed.
    ReturnOp,
    /// Fails the script even if not executed.
    IllegalOp,
    /// Does nothing.
    NoOp,
    /// Any opcode not covered above.
    Ordinary(Ordinary),
}

macro_rules! ordinary_opcode {
    ($($op:ident),* $(,)?) => {
        #[repr(u8)]
        #[doc(hidden)]
        #[derive(Copy, Clone, PartialEq, Eq, Debug)]
        pub enum Ordinary {
            $( $op = all::$op.code ),*
        }

        impl fmt::Display for Ordinary {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match *self {
                    $(Self::$op => f.pad(stringify!($op))),*
                }
            }
        }

        impl Ordinary {
            fn with(opcode: Opcode) -> Self {
                match opcode {
                    $(all::$op => Self::$op),*,
                    _ => unreachable!("construction of `Ordinary` from non-ordinary opcode {}", opcode),
                }
            }

            /// Constructs an [`Ordinary`] opcode from a generic [`Opcode`].
            pub fn from_opcode(opcode: Opcode) -> Option<Self> {
                match opcode {
                    $(all::$op => Some(Self::$op)),*,
                    _ => None,
                }
            }

            /// Encodes this opcode as a byte.
            #[inline]
            pub fn to_u8(self) -> u8 { self as u8 }
        }
    };
}

ordinary_opcode! {
    OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4,
    OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_VERIFY,
    OP_TOALTSTACK, OP_FROMALTSTACK,
    OP_2DROP, OP_2DUP, OP_3DUP, OP_2OVER, OP_2ROT, OP_2SWAP,
    OP_DROP, OP_DUP, OP_NIP, OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_SWAP, OP_TUCK,
    OP_IFDUP, OP_DEPTH, OP_SIZE,
    OP_EQUAL, OP_EQUALVERIFY,
    OP_1ADD, OP_1SUB, OP_NEGATE, OP_ABS, OP_NOT, OP_0NOTEQUAL,
    OP_ADD, OP_SUB, OP_BOOLAND, OP_BOOLOR,
    OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN,
    OP_GREATERTHAN, OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL,
    OP_MIN, OP_MAX, OP_WITHIN,
    OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256,
    OP_CODESEPARATOR, OP_CHECKSIG, OP_CHECKSIGVERIFY,
    OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY,
}

/// Read the following byte as a pushdata length.
pub const OP_PUSHDATA1: u8 = 0x4c;
/// Read the following two bytes as a pushdata length.
pub const OP_PUSHDATA2: u8 = 0x4d;
/// Read the following four bytes as a pushdata length.
pub const OP_PUSHDATA4: u8 = 0x4e;

/// Format a byte as a script opcode.
///
/// # Errors
///
/// Returns any formatter error from `f`.
pub fn fmt_opcode(op: u8, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match op {
        0x00 => f.write_str("OP_0"),
        0x01..=0x4b => write!(f, "OP_PUSHBYTES_{}", op),
        0x4c => f.write_str("OP_PUSHDATA1"),
        0x4d => f.write_str("OP_PUSHDATA2"),
        0x4e => f.write_str("OP_PUSHDATA4"),
        0x4f => f.write_str("OP_1NEGATE"),
        0x50 => f.write_str("OP_RESERVED"),
        0x51..=0x60 => write!(f, "OP_{}", op - 0x50),
        0xb3 => f.write_str("OP_SHA512"),
        other => write!(f, "{}", Opcode::from(other)),
    }
}
