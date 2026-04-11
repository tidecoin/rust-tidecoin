// SPDX-License-Identifier: CC0-1.0

//! Unit tests for the `amount` module.

#[cfg(feature = "alloc")]
use alloc::format;
#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};
use core::num::{NonZeroI64, NonZeroU64};
#[cfg(feature = "std")]
use std::panic;

use super::*;
use crate::result::{MathOp, NumOpError, NumOpResult};
#[cfg(feature = "alloc")]
use crate::FeeRate;
use crate::Weight;

fn amt_err(e: ParseAmountErrorInner) -> ParseAmountError {
    ParseAmountError(e)
}

fn parse_err(e: ParseAmountErrorInner) -> ParseError {
    ParseError(ParseErrorInner::Amount(ParseAmountError(e)))
}
fn denom_err(e: ParseDenominationError) -> ParseError {
    ParseError(ParseErrorInner::Denomination(e))
}

#[track_caller]
fn sat(sat: u64) -> Amount {
    Amount::from_sat(sat).unwrap()
}

#[track_caller]
fn ssat(ssat: i64) -> SignedAmount {
    SignedAmount::from_sat(ssat).unwrap()
}

#[track_caller]
fn res(n_sat: u64) -> NumOpResult<Amount> {
    NumOpResult::from(sat(n_sat))
}

#[track_caller]
fn sres(n_sat: i64) -> NumOpResult<SignedAmount> {
    NumOpResult::from(ssat(n_sat))
}

#[test]
fn sanity_check() {
    assert_eq!(ssat(-100).abs(), ssat(100));
    assert_eq!(ssat(-100).signum(), -1);
    assert_eq!(ssat(0).signum(), 0);
    assert_eq!(ssat(100).signum(), 1);
    assert_eq!(SignedAmount::from(sat(100)), ssat(100));
    assert!(!ssat(-100).is_positive());
    assert!(ssat(100).is_positive());

    #[cfg(feature = "alloc")]
    {
        assert_eq!(Amount::from_float_in(0_f64, Denomination::Tidecoin).unwrap(), sat(0));
        assert_eq!(Amount::from_float_in(2_f64, Denomination::Tidecoin).unwrap(), sat(200_000_000));
        assert!(Amount::from_float_in(-100_f64, Denomination::Tidecoin).is_err());
    }

    let result = NumOpResult::Valid(sat(123));
    assert_eq!(Some(sat(123)), result.ok());
    assert!(result.is_valid());
    assert!(!result.is_error());
}

#[test]
fn check_if_num_is_too_precise() {
    // Has decimal, not too precise
    assert_eq!(is_too_precise("1234.5678", 4), Some(0));
    // Has decimal, is too precise
    assert_eq!(is_too_precise("1234.5678", 3), Some(3));
    // No decimal, not too precise
    assert_eq!(is_too_precise("1234", 4), Some(0));
    // No decimal, is too precise
    assert_eq!(is_too_precise("1234", 2), Some(3));
}

#[test]
#[cfg(feature = "alloc")]
fn from_str_zero() {
    let denoms = ["TDC", "cTDC", "mTDC", "uTDC", "bits", "tidos"];
    for denom in denoms {
        for v in &["0", "000"] {
            let s = format!("{} {}", v, denom);
            match s.parse::<Amount>() {
                Err(e) => panic!("failed to create amount from {}: {:?}", s, e),
                Ok(amount) => assert_eq!(amount, Amount::ZERO),
            }
        }

        let s = format!("-0 {}", denom);
        match s.parse::<Amount>() {
            Err(e) => assert_eq!(
                e,
                ParseError(ParseErrorInner::Amount(ParseAmountError(
                    ParseAmountErrorInner::OutOfRange(OutOfRangeError::negative())
                )))
            ),
            Ok(_) => panic!("unsigned amount from {}", s),
        }
        match s.parse::<SignedAmount>() {
            Err(e) => panic!("failed to create amount from {}: {:?}", s, e),
            Ok(amount) => assert_eq!(amount, SignedAmount::ZERO),
        }
    }
}

#[test]
fn from_str_zero_without_denomination() {
    let _a = Amount::from_str("0").unwrap();
    let _a = Amount::from_str("0.0").unwrap();
    let _a = Amount::from_str("00.0").unwrap();

    assert!(Amount::from_str("-0").is_err());
    assert!(Amount::from_str("-0.0").is_err());
    assert!(Amount::from_str("-00.0").is_err());

    let _a = SignedAmount::from_str("-0").unwrap();
    let _a = SignedAmount::from_str("-0.0").unwrap();
    let _a = SignedAmount::from_str("-00.0").unwrap();

    let _a = SignedAmount::from_str("0").unwrap();
    let _a = SignedAmount::from_str("0.0").unwrap();
    let _a = SignedAmount::from_str("00.0").unwrap();
}

#[test]
fn from_int_tdc() {
    let amt = Amount::from_tdc_u16(2);
    assert_eq!(sat(200_000_000), amt);
    let amt = Amount::from_int_tdc(2_u16);
    assert_eq!(sat(200_000_000), amt);

    let amt = SignedAmount::from_tdc_i16(-2);
    assert_eq!(ssat(-200_000_000), amt);
    let amt = SignedAmount::from_int_tdc(-2_i16);
    assert_eq!(ssat(-200_000_000), amt);
}

#[test]
#[cfg(feature = "alloc")]
fn display_display_struct() {
    let display_fixed_tdc = Display {
        sats_abs: 100_000_000,
        is_negative: false,
        style: DisplayStyle::FixedDenomination {
            denomination: Denomination::Tidecoin,
            show_denomination: true,
        },
    };
    assert_eq!(format!("{}", display_fixed_tdc), "1 TDC");

    let display_fixed_tidoshi = Display {
        sats_abs: 1,
        is_negative: false,
        style: DisplayStyle::FixedDenomination {
            denomination: Denomination::Tidoshi,
            show_denomination: true,
        },
    };
    assert_eq!(format!("{}", display_fixed_tidoshi), "1 tidoshi");

    let display_dynamic_tdc = Display {
        sats_abs: 100_000_000,
        is_negative: false,
        style: DisplayStyle::DynamicDenomination,
    };
    assert_eq!(format!("{}", display_dynamic_tdc), "1 TDC");

    let display_dynamic_tidoshi = Display {
        sats_abs: 99_999_999,
        is_negative: false,
        style: DisplayStyle::DynamicDenomination,
    };
    assert_eq!(format!("{}", display_dynamic_tidoshi), "99999999 tidoshi");

    let display_negative_tdc = Display {
        sats_abs: 100_000_000,
        is_negative: true,
        style: DisplayStyle::DynamicDenomination,
    };
    assert_eq!(format!("{}", display_negative_tdc), "-1 TDC");

    let display_negative_tidoshi = Display {
        sats_abs: 99_999_999,
        is_negative: true,
        style: DisplayStyle::DynamicDenomination,
    };
    assert_eq!(format!("{}", display_negative_tidoshi), "-99999999 tidoshi");
}

#[test]
#[cfg(feature = "alloc")]
fn display_math_op() {
    let cases = [
        (MathOp::Add, "add"),
        (MathOp::Sub, "sub"),
        (MathOp::Mul, "mul"),
        (MathOp::Div, "div"),
        (MathOp::Rem, "rem"),
        (MathOp::Neg, "neg"),
    ];

    for (op, expected) in cases {
        assert_eq!(format!("{}", op), expected);
    }
}

#[test]
fn amount_try_from_signed_amount() {
    let sa_positive = ssat(123);
    let ua_positive = Amount::try_from(sa_positive).unwrap();
    assert_eq!(ua_positive, sat(123));

    let sa_negative = ssat(-123);
    let result = Amount::try_from(sa_negative);
    assert_eq!(result, Err(OutOfRangeError { is_signed: false, is_greater_than_max: false }));
}

#[test]
fn mul_div() {
    let op_result_sat = |a| NumOpResult::Valid(sat(a));
    let op_result_ssat = |a| NumOpResult::Valid(ssat(a));

    assert_eq!(sat(14) * 3, op_result_sat(42));
    assert_eq!(sat(14) / 2, op_result_sat(7));
    assert_eq!(sat(14) % 3, op_result_sat(2));
    assert_eq!(ssat(-14) * 3, op_result_ssat(-42));
    assert_eq!(ssat(-14) / 2, op_result_ssat(-7));
    assert_eq!(ssat(-14) % 3, op_result_ssat(-2));
}

#[test]
fn neg() {
    let amount = -ssat(2);
    assert_eq!(amount.to_sat(), -2);
}

#[test]
fn add() {
    assert!(sat(0) + sat(0) == sat(0).into());
    assert!(sat(127) + sat(179) == sat(306).into());

    assert!(ssat(0) + ssat(0) == ssat(0).into());
    assert!(ssat(127) + ssat(179) == ssat(306).into());
    assert!(ssat(-127) + ssat(179) == ssat(52).into());
    assert!(ssat(127) + ssat(-179) == ssat(-52).into());
    assert!(ssat(-127) + ssat(-179) == ssat(-306).into());

    // Implemented using generic impl.
    assert!(res(127) + sat(179) == sat(306).into());
    assert!(sres(127) + ssat(179) == ssat(306).into());
}

#[test]
fn sub() {
    assert!(sat(0) - sat(0) == sat(0).into());
    assert!(sat(179) - sat(127) == sat(52).into());
    assert!((sat(127) - sat(179)).is_error());

    assert!(ssat(0) - ssat(0) == ssat(0).into());
    assert!(ssat(127) - ssat(179) == ssat(-52).into());
    assert!(ssat(-127) - ssat(179) == ssat(-306).into());
    assert!(ssat(127) - ssat(-179) == ssat(306).into());
    assert!(ssat(-127) - ssat(-179) == ssat(52).into());

    // Implemented using generic impl.
    assert!(res(179) - sat(127) == sat(52).into());
    assert!(sres(179) - ssat(127) == ssat(52).into());
}

#[test]
fn checked_arithmetic() {
    assert_eq!(SignedAmount::MAX.checked_add(ssat(1)), None);
    assert_eq!(SignedAmount::MIN.checked_sub(ssat(1)), None);
    assert_eq!(Amount::MAX.checked_add(sat(1)), None);
    assert_eq!(Amount::MIN.checked_sub(sat(1)), None);

    assert_eq!(sat(5).checked_div(2), Some(sat(2))); // integer division
    assert_eq!(ssat(-6).checked_div(2), Some(ssat(-3)));
}

#[test]
fn positive_sub() {
    assert_eq!(ssat(10).positive_sub(ssat(7)).unwrap(), ssat(3));
    assert_eq!(ssat(10).positive_sub(ssat(10)).unwrap(), ssat(0));
    assert!(ssat(-10).positive_sub(ssat(7)).is_none());
    assert!(ssat(10).positive_sub(ssat(-7)).is_none());
    assert!(ssat(10).positive_sub(ssat(11)).is_none());
}

#[test]
#[cfg(feature = "alloc")]
fn amount_checked_div_by_weight_ceil() {
    let weight = Weight::from_kwu(1).unwrap();
    let fee_rate = sat(1).div_by_weight_ceil(weight).unwrap();
    // 1 sats / 1,000 wu = 1 sats/kwu
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(1));

    let weight = Weight::from_wu(381);
    let fee_rate = sat(329).div_by_weight_ceil(weight).unwrap();
    // 329 sats / 381 wu = 863.5 sats/kwu
    // round up to 864
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(864));

    let fee_rate = Amount::ONE_SAT.div_by_weight_ceil(Weight::ZERO);
    assert!(fee_rate.is_error());
}

#[test]
#[cfg(feature = "alloc")]
fn amount_checked_div_by_weight_floor() {
    let weight = Weight::from_kwu(1).unwrap();
    let fee_rate = sat(1).div_by_weight_floor(weight).unwrap();
    // 1 sats / 1,000 wu = 1 sats/kwu
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(1));

    let weight = Weight::from_wu(381);
    let fee_rate = sat(329).div_by_weight_floor(weight).unwrap();
    // 329 sats / 381 wu = 863.5 sats/kwu
    // round down to 863
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(863));

    let fee_rate = Amount::ONE_SAT.div_by_weight_floor(Weight::ZERO);
    assert!(fee_rate.is_error());
}

#[test]
#[cfg(feature = "alloc")]
fn amount_checked_div_by_fee_rate() {
    let amount = sat(1000);
    let fee_rate = FeeRate::from_sat_per_kwu(2);

    // Test floor division
    let weight = amount.div_by_fee_rate_floor(fee_rate).unwrap();
    // 1000 sats / (2 sats/kwu) = 500,000 wu
    assert_eq!(weight, Weight::from_wu(500_000));

    // Test ceiling division
    let weight = amount.div_by_fee_rate_ceil(fee_rate).unwrap();
    assert_eq!(weight, Weight::from_wu(500_000)); // Same result for exact division

    // Test truncation behavior
    let amount = sat(1000);
    let fee_rate = FeeRate::from_sat_per_kwu(3);
    let floor_weight = amount.div_by_fee_rate_floor(fee_rate).unwrap();
    let ceil_weight = amount.div_by_fee_rate_ceil(fee_rate).unwrap();
    assert_eq!(floor_weight, Weight::from_wu(333_333));
    assert_eq!(ceil_weight, Weight::from_wu(333_334));

    // Test division by zero
    let zero_fee_rate = FeeRate::from_sat_per_kwu(0);
    assert!(amount.div_by_fee_rate_floor(zero_fee_rate).is_error());
    assert!(amount.div_by_fee_rate_ceil(zero_fee_rate).is_error());

    // Test with maximum amount
    let max_amount = Amount::MAX;
    let small_fee_rate = FeeRate::from_sat_per_kwu(1);
    let weight = max_amount.div_by_fee_rate_floor(small_fee_rate).unwrap();
    // 21_000_000_0000_0000 sats / (1 sat/kwu) = 2_100_000_000_000_000_000 wu
    assert_eq!(weight, Weight::from_wu(2_100_000_000_000_000_000));
}

#[test]
#[cfg(feature = "alloc")]
fn floating_point() {
    use super::Denomination as D;
    let f = Amount::from_float_in;
    let sf = SignedAmount::from_float_in;

    assert_eq!(f(11.22, D::Tidecoin), Ok(sat(1_122_000_000)));
    assert_eq!(sf(-11.22, D::MilliTidecoin), Ok(ssat(-1_122_000)));
    assert_eq!(f(11.22, D::Bit), Ok(sat(1122)));
    assert_eq!(f(0.000_123_4, D::Tidecoin), Ok(sat(12_340)));
    assert_eq!(sf(-0.000_123_45, D::Tidecoin), Ok(ssat(-12_345)));

    assert_eq!(
        f(11.22, D::Tidoshi),
        Err(amt_err(ParseAmountErrorInner::TooPrecise(TooPreciseError { position: 3 })))
    );
    assert_eq!(
        f(42.123_456_781, D::Tidecoin),
        Err(amt_err(ParseAmountErrorInner::TooPrecise(TooPreciseError { position: 11 })))
    );
    assert_eq!(
        sf(-184_467_440_738.0, D::Tidecoin),
        Err(amt_err(ParseAmountErrorInner::OutOfRange(OutOfRangeError::too_small())))
    );
    assert_eq!(
        f(18_446_744_073_709_551_617.0, D::Tidoshi),
        Err(amt_err(ParseAmountErrorInner::OutOfRange(OutOfRangeError::too_big(false))))
    );

    assert_eq!(
        f(Amount::MAX.to_float_in(D::Tidoshi) + 1.0, D::Tidoshi),
        Err(amt_err(ParseAmountErrorInner::OutOfRange(OutOfRangeError::too_big(false))))
    );

    assert_eq!(
        sf(SignedAmount::MAX.to_float_in(D::Tidoshi) + 1.0, D::Tidoshi),
        Err(amt_err(ParseAmountErrorInner::OutOfRange(OutOfRangeError::too_big(true))))
    );

    let tdc = move |f| SignedAmount::from_tdc(f).unwrap();
    assert_eq!(tdc(2.5).to_float_in(D::Tidecoin), 2.5);
    assert_eq!(tdc(-2.5).to_float_in(D::CentiTidecoin), -250.0);
    assert_eq!(tdc(-2.5).to_float_in(D::MilliTidecoin), -2500.0);
    assert_eq!(tdc(2.5).to_float_in(D::Tidoshi), 250_000_000.0);

    let tdc = move |f| Amount::from_tdc(f).unwrap();
    assert_eq!(&tdc(0.0012).to_float_in(D::Tidecoin).to_string(), "0.0012");
}

#[test]
#[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per TDC.
fn parsing() {
    use super::ParseAmountError as E;

    let den_tdc = Denomination::Tidecoin;
    let den_sat = Denomination::Tidoshi;
    let p = Amount::from_str_in;
    let sp = SignedAmount::from_str_in;

    assert_eq!(
        p("x", den_tdc),
        Err(amt_err(ParseAmountErrorInner::InvalidCharacter(InvalidCharacterError {
            invalid_char: 'x',
            position: 0
        })))
    );
    assert_eq!(
        p("-", den_tdc),
        Err(amt_err(ParseAmountErrorInner::MissingDigits(MissingDigitsError {
            kind: MissingDigitsKind::OnlyMinusSign
        })))
    );
    assert_eq!(
        sp("-", den_tdc),
        Err(amt_err(ParseAmountErrorInner::MissingDigits(MissingDigitsError {
            kind: MissingDigitsKind::OnlyMinusSign
        })))
    );
    assert_eq!(
        p("-1.0x", den_tdc),
        Err(amt_err(ParseAmountErrorInner::InvalidCharacter(InvalidCharacterError {
            invalid_char: 'x',
            position: 4
        })))
    );
    assert_eq!(
        p("0.0 ", den_tdc),
        Err(amt_err(ParseAmountErrorInner::InvalidCharacter(InvalidCharacterError {
            invalid_char: ' ',
            position: 3
        })))
    );
    assert_eq!(
        p("0.000.000", den_tdc),
        Err(amt_err(ParseAmountErrorInner::InvalidCharacter(InvalidCharacterError {
            invalid_char: '.',
            position: 5
        })))
    );
    #[cfg(feature = "alloc")]
    let more_than_max = format!("{}", Amount::MAX.to_sat() + 1);
    #[cfg(feature = "alloc")]
    assert_eq!(
        p(&more_than_max, den_tdc),
        Err(amt_err(ParseAmountErrorInner::OutOfRange(OutOfRangeError::too_big(false))))
    );
    assert_eq!(
        p("0.000000042", den_tdc),
        Err(amt_err(ParseAmountErrorInner::TooPrecise(TooPreciseError { position: 10 })))
    );
    assert_eq!(p("1.0000000", den_sat), Ok(sat(1)));
    assert_eq!(
        p("1.1", den_sat),
        Err(amt_err(ParseAmountErrorInner::TooPrecise(TooPreciseError { position: 2 })))
    );
    assert_eq!(
        p("1000.1", den_sat),
        Err(amt_err(ParseAmountErrorInner::TooPrecise(TooPreciseError { position: 5 })))
    );
    assert_eq!(p("1001.0000000", den_sat), Ok(sat(1001)));
    assert_eq!(
        p("1000.0000001", den_sat),
        Err(amt_err(ParseAmountErrorInner::TooPrecise(TooPreciseError { position: 11 })))
    );

    assert_eq!(p("1", den_tdc), Ok(sat(1_000_000_00)));
    assert_eq!(sp("-.5", den_tdc), Ok(ssat(-500_000_00)));
    #[cfg(feature = "alloc")]
    assert_eq!(sp(&SignedAmount::MIN.to_sat().to_string(), den_sat), Ok(SignedAmount::MIN));
    assert_eq!(p("1.1", den_tdc), Ok(sat(1_100_000_00)));
    assert_eq!(p("100", den_sat), Ok(sat(100)));
    assert_eq!(p("55", den_sat), Ok(sat(55)));
    assert_eq!(p("2100000000000000", den_sat), Ok(sat(21_000_000__000_000_00)));
    assert_eq!(p("2100000000000000.", den_sat), Ok(sat(21_000_000__000_000_00)));
    assert_eq!(p("21000000", den_tdc), Ok(sat(21_000_000__000_000_00)));

    // exactly 50 chars.
    assert_eq!(
        p("100000000000000.0000000000000000000000000000000000", Denomination::Tidecoin),
        Err(amt_err(ParseAmountErrorInner::OutOfRange(OutOfRangeError::too_big(false))))
    );
    // more than 50 chars.
    assert_eq!(
        p("100000000000000.00000000000000000000000000000000000", Denomination::Tidecoin),
        Err(E(ParseAmountErrorInner::InputTooLarge(InputTooLargeError { len: 51 })))
    );
}

#[test]
#[cfg(feature = "alloc")]
fn to_string() {
    use super::Denomination as D;

    assert_eq!(Amount::ONE_TDC.to_string_in(D::Tidecoin), "1");
    assert_eq!(format!("{:.8}", Amount::ONE_TDC.display_in(D::Tidecoin)), "1.00000000");
    assert_eq!(Amount::ONE_TDC.to_string_in(D::Tidoshi), "100000000");
    assert_eq!(Amount::ONE_SAT.to_string_in(D::Tidecoin), "0.00000001");
    assert_eq!(ssat(-42).to_string_in(D::Tidecoin), "-0.00000042");

    assert_eq!(Amount::ONE_TDC.to_string_with_denomination(D::Tidecoin), "1 TDC");
    assert_eq!(SignedAmount::ONE_TDC.to_string_with_denomination(D::Tidoshi), "100000000 tidoshi");
    assert_eq!(Amount::ONE_SAT.to_string_with_denomination(D::Tidecoin), "0.00000001 TDC");
    assert_eq!(ssat(-42).to_string_with_denomination(D::Tidecoin), "-0.00000042 TDC");
}

// May help identify a problem sooner
#[test]
#[cfg(feature = "alloc")]
fn test_repeat_char() {
    let mut buf = String::new();
    repeat_char(&mut buf, '0', 0).unwrap();
    assert_eq!(buf.len(), 0);
    repeat_char(&mut buf, '0', 42).unwrap();
    assert_eq!(buf.len(), 42);
    assert!(buf.chars().all(|c| c == '0'));
}

// Constructs individual test functions to make it easier to find which check failed.
macro_rules! check_format_non_negative {
    ($denom:ident; $($test_name:ident, $val:literal, $format_string:literal, $expected:literal);* $(;)?) => {
        $(
            #[test]
            #[cfg(feature = "alloc")]
            fn $test_name() {
                assert_eq!(format!($format_string, sat($val).display_in(Denomination::$denom)), $expected);
                assert_eq!(format!($format_string, ssat($val as i64).display_in(Denomination::$denom)), $expected);
            }
        )*
    }
}

macro_rules! check_format_non_negative_show_denom {
    ($denom:ident, $denom_suffix:literal; $($test_name:ident, $val:literal, $format_string:literal, $expected:literal);* $(;)?) => {
        $(
            #[test]
            #[cfg(feature = "alloc")]
            fn $test_name() {
                assert_eq!(format!($format_string, sat($val).display_in(Denomination::$denom).show_denomination()), concat!($expected, $denom_suffix));
                assert_eq!(format!($format_string, ssat($val as i64).display_in(Denomination::$denom).show_denomination()), concat!($expected, $denom_suffix));
            }
        )*
    }
}

check_format_non_negative! {
    Tidoshi;
    sat_check_fmt_non_negative_0, 0, "{}", "0";
    sat_check_fmt_non_negative_1, 0, "{:2}", " 0";
    sat_check_fmt_non_negative_2, 0, "{:02}", "00";
    sat_check_fmt_non_negative_3, 0, "{:.1}", "0.0";
    sat_check_fmt_non_negative_4, 0, "{:4.1}", " 0.0";
    sat_check_fmt_non_negative_5, 0, "{:04.1}", "00.0";
    sat_check_fmt_non_negative_6, 1, "{}", "1";
    sat_check_fmt_non_negative_7, 1, "{:2}", " 1";
    sat_check_fmt_non_negative_8, 1, "{:02}", "01";
    sat_check_fmt_non_negative_9, 1, "{:.1}", "1.0";
    sat_check_fmt_non_negative_10, 1, "{:4.1}", " 1.0";
    sat_check_fmt_non_negative_11, 1, "{:04.1}", "01.0";
    sat_check_fmt_non_negative_12, 10, "{}", "10";
    sat_check_fmt_non_negative_13, 10, "{:2}", "10";
    sat_check_fmt_non_negative_14, 10, "{:02}", "10";
    sat_check_fmt_non_negative_15, 10, "{:3}", " 10";
    sat_check_fmt_non_negative_16, 10, "{:03}", "010";
    sat_check_fmt_non_negative_17, 10, "{:.1}", "10.0";
    sat_check_fmt_non_negative_18, 10, "{:5.1}", " 10.0";
    sat_check_fmt_non_negative_19, 10, "{:05.1}", "010.0";
    sat_check_fmt_non_negative_20, 1, "{:<2}", "1 ";
    sat_check_fmt_non_negative_21, 1, "{:<02}", "01";
    sat_check_fmt_non_negative_22, 1, "{:<3.1}", "1.0";
    sat_check_fmt_non_negative_23, 1, "{:<4.1}", "1.0 ";
}

check_format_non_negative_show_denom! {
    Tidoshi, " tidoshi";
    sat_check_fmt_non_negative_show_denom_0, 0, "{}", "0";
    sat_check_fmt_non_negative_show_denom_1, 0, "{:2}", "0";
    sat_check_fmt_non_negative_show_denom_2, 0, "{:02}", "0";
    sat_check_fmt_non_negative_show_denom_3, 0, "{:9}", "0";
    sat_check_fmt_non_negative_show_denom_4, 0, "{:09}", "0";
    sat_check_fmt_non_negative_show_denom_5, 0, "{:10}", " 0";
    sat_check_fmt_non_negative_show_denom_6, 0, "{:010}", "00";
    sat_check_fmt_non_negative_show_denom_7, 0, "{:.1}", "0.0";
    sat_check_fmt_non_negative_show_denom_8, 0, "{:11.1}", "0.0";
    sat_check_fmt_non_negative_show_denom_9, 0, "{:011.1}", "0.0";
    sat_check_fmt_non_negative_show_denom_10, 0, "{:12.1}", " 0.0";
    sat_check_fmt_non_negative_show_denom_11, 0, "{:012.1}", "00.0";
    sat_check_fmt_non_negative_show_denom_12, 1, "{}", "1";
    sat_check_fmt_non_negative_show_denom_13, 1, "{:10}", " 1";
    sat_check_fmt_non_negative_show_denom_14, 1, "{:010}", "01";
    sat_check_fmt_non_negative_show_denom_15, 1, "{:.1}", "1.0";
    sat_check_fmt_non_negative_show_denom_16, 1, "{:12.1}", " 1.0";
    sat_check_fmt_non_negative_show_denom_17, 1, "{:012.1}", "01.0";
    sat_check_fmt_non_negative_show_denom_18, 10, "{}", "10";
    sat_check_fmt_non_negative_show_denom_19, 10, "{:10}", "10";
    sat_check_fmt_non_negative_show_denom_20, 10, "{:010}", "10";
    sat_check_fmt_non_negative_show_denom_21, 10, "{:11}", " 10";
    sat_check_fmt_non_negative_show_denom_22, 10, "{:011}", "010";
}

check_format_non_negative! {
    Tidecoin;
    tdc_check_fmt_non_negative_0, 0, "{}", "0";
    tdc_check_fmt_non_negative_1, 0, "{:2}", " 0";
    tdc_check_fmt_non_negative_2, 0, "{:02}", "00";
    tdc_check_fmt_non_negative_3, 0, "{:.1}", "0.0";
    tdc_check_fmt_non_negative_4, 0, "{:4.1}", " 0.0";
    tdc_check_fmt_non_negative_5, 0, "{:04.1}", "00.0";
    tdc_check_fmt_non_negative_6, 1, "{}", "0.00000001";
    tdc_check_fmt_non_negative_7, 1, "{:2}", "0.00000001";
    tdc_check_fmt_non_negative_8, 1, "{:02}", "0.00000001";
    tdc_check_fmt_non_negative_9, 1, "{:.1}", "0.0";
    tdc_check_fmt_non_negative_10, 1, "{:11}", " 0.00000001";
    tdc_check_fmt_non_negative_11, 1, "{:11.1}", "        0.0";
    tdc_check_fmt_non_negative_12, 1, "{:011.1}", "000000000.0";
    tdc_check_fmt_non_negative_13, 1, "{:.9}", "0.000000010";
    tdc_check_fmt_non_negative_14, 1, "{:11.9}", "0.000000010";
    tdc_check_fmt_non_negative_15, 1, "{:011.9}", "0.000000010";
    tdc_check_fmt_non_negative_16, 1, "{:12.9}", " 0.000000010";
    tdc_check_fmt_non_negative_17, 1, "{:012.9}", "00.000000010";
    tdc_check_fmt_non_negative_18, 100_000_000, "{}", "1";
    tdc_check_fmt_non_negative_19, 100_000_000, "{:2}", " 1";
    tdc_check_fmt_non_negative_20, 100_000_000, "{:02}", "01";
    tdc_check_fmt_non_negative_21, 100_000_000, "{:.1}", "1.0";
    tdc_check_fmt_non_negative_22, 100_000_000, "{:4.1}", " 1.0";
    tdc_check_fmt_non_negative_23, 100_000_000, "{:04.1}", "01.0";
    tdc_check_fmt_non_negative_24, 110_000_000, "{}", "1.1";
    tdc_check_fmt_non_negative_25, 100_000_001, "{}", "1.00000001";
    tdc_check_fmt_non_negative_26, 100_000_001, "{:1}", "1.00000001";
    tdc_check_fmt_non_negative_27, 100_000_001, "{:.1}", "1.0";
    tdc_check_fmt_non_negative_28, 100_000_001, "{:10}", "1.00000001";
    tdc_check_fmt_non_negative_29, 100_000_001, "{:11}", " 1.00000001";
    tdc_check_fmt_non_negative_30, 100_000_001, "{:011}", "01.00000001";
    tdc_check_fmt_non_negative_31, 100_000_001, "{:.8}", "1.00000001";
    tdc_check_fmt_non_negative_32, 100_000_001, "{:.9}", "1.000000010";
    tdc_check_fmt_non_negative_33, 100_000_001, "{:11.9}", "1.000000010";
    tdc_check_fmt_non_negative_34, 100_000_001, "{:12.9}", " 1.000000010";
    tdc_check_fmt_non_negative_35, 100_000_001, "{:012.9}", "01.000000010";
    tdc_check_fmt_non_negative_36, 100_000_001, "{:+011.8}", "+1.00000001";
    tdc_check_fmt_non_negative_37, 100_000_001, "{:+12.8}", " +1.00000001";
    tdc_check_fmt_non_negative_38, 100_000_001, "{:+012.8}", "+01.00000001";
    tdc_check_fmt_non_negative_39, 100_000_001, "{:+12.9}", "+1.000000010";
    tdc_check_fmt_non_negative_40, 100_000_001, "{:+012.9}", "+1.000000010";
    tdc_check_fmt_non_negative_41, 100_000_001, "{:+13.9}", " +1.000000010";
    tdc_check_fmt_non_negative_42, 100_000_001, "{:+013.9}", "+01.000000010";
    tdc_check_fmt_non_negative_43, 100_000_001, "{:<10}", "1.00000001";
    tdc_check_fmt_non_negative_44, 100_000_001, "{:<11}", "1.00000001 ";
    tdc_check_fmt_non_negative_45, 100_000_001, "{:<011}", "01.00000001";
    tdc_check_fmt_non_negative_46, 100_000_001, "{:<11.9}", "1.000000010";
    tdc_check_fmt_non_negative_47, 100_000_001, "{:<12.9}", "1.000000010 ";
    tdc_check_fmt_non_negative_48, 100_000_001, "{:<12}", "1.00000001  ";
    tdc_check_fmt_non_negative_49, 100_000_001, "{:^11}", "1.00000001 ";
    tdc_check_fmt_non_negative_50, 100_000_001, "{:^11.9}", "1.000000010";
    tdc_check_fmt_non_negative_51, 100_000_001, "{:^12.9}", "1.000000010 ";
    tdc_check_fmt_non_negative_52, 100_000_001, "{:^12}", " 1.00000001 ";
    tdc_check_fmt_non_negative_53, 100_000_001, "{:^12.9}", "1.000000010 ";
    tdc_check_fmt_non_negative_54, 100_000_001, "{:^13.9}", " 1.000000010 ";
}

check_format_non_negative_show_denom! {
    Tidecoin, " TDC";
    tdc_check_fmt_non_negative_show_denom_0, 1, "{:14.1}", "       0.0";
    tdc_check_fmt_non_negative_show_denom_1, 1, "{:14.8}", "0.00000001";
    tdc_check_fmt_non_negative_show_denom_2, 1, "{:15}", " 0.00000001";
    tdc_check_fmt_non_negative_show_denom_3, 1, "{:015}", "00.00000001";
    tdc_check_fmt_non_negative_show_denom_4, 1, "{:.9}", "0.000000010";
    tdc_check_fmt_non_negative_show_denom_5, 1, "{:15.9}", "0.000000010";
    tdc_check_fmt_non_negative_show_denom_6, 1, "{:16.9}", " 0.000000010";
    tdc_check_fmt_non_negative_show_denom_7, 1, "{:016.9}", "00.000000010";
}

check_format_non_negative_show_denom! {
    Tidecoin, " TDC ";
    tdc_check_fmt_non_negative_show_denom_align_0, 1, "{:<15}", "0.00000001";
    tdc_check_fmt_non_negative_show_denom_align_1, 1, "{:^15}", "0.00000001";
    tdc_check_fmt_non_negative_show_denom_align_2, 1, "{:^16}", " 0.00000001";
}

#[test]
fn unsigned_signed_conversion() {
    let max_sats: u64 = Amount::MAX.to_sat();

    assert_eq!(sat(max_sats).to_signed(), ssat(max_sats as i64));
    assert_eq!(ssat(max_sats as i64).to_unsigned(), Ok(sat(max_sats)));
    assert_eq!(ssat(max_sats as i64).to_unsigned().unwrap().to_signed(), ssat(max_sats as i64));
}

#[test]
#[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per TDC.
#[allow(clippy::items_after_statements)] // Define functions where we use them.
#[allow(clippy::too_many_lines)]
fn from_str() {
    use super::ParseDenominationError;

    assert_eq!(
        "x TDC".parse::<Amount>(),
        Err(ParseError(ParseErrorInner::Amount(ParseAmountError(
            ParseAmountErrorInner::InvalidCharacter(InvalidCharacterError {
                invalid_char: 'x',
                position: 0
            })
        ))))
    );
    assert_eq!(
        "xTDC".parse::<Amount>(),
        Err(ParseError(ParseErrorInner::Denomination(ParseDenominationError::Unknown(
            UnknownDenominationError("xTDC".into())
        )))),
    );
    assert_eq!(
        "5 TDC TDC".parse::<Amount>(),
        Err(ParseError(ParseErrorInner::Denomination(ParseDenominationError::Unknown(
            UnknownDenominationError("TDC TDC".into())
        )))),
    );
    assert_eq!(
        "5TDC TDC".parse::<Amount>(),
        Err(ParseError(ParseErrorInner::Amount(ParseAmountError(
            ParseAmountErrorInner::InvalidCharacter(InvalidCharacterError {
                invalid_char: 'T',
                position: 1
            })
        ))))
    );
    assert_eq!(
        "5 5 TDC".parse::<Amount>(),
        Err(ParseError(ParseErrorInner::Denomination(ParseDenominationError::Unknown(
            UnknownDenominationError("5 TDC".into())
        )))),
    );

    #[track_caller]
    fn ok_case(s: &str, expected: Amount) {
        assert_eq!(s.parse::<Amount>().unwrap(), expected);
        assert_eq!(s.replace(' ', "").parse::<Amount>().unwrap(), expected);
    }

    #[track_caller]
    fn case(s: &str, expected: &Result<Amount, ParseError>) {
        assert_eq!(s.parse::<Amount>(), *expected);
        assert_eq!(s.replace(' ', "").parse::<Amount>(), *expected);
    }

    #[track_caller]
    fn ok_scase(s: &str, expected: SignedAmount) {
        assert_eq!(s.parse::<SignedAmount>().unwrap(), expected);
        assert_eq!(s.replace(' ', "").parse::<SignedAmount>().unwrap(), expected);
    }

    #[track_caller]
    fn scase(s: &str, expected: &Result<SignedAmount, ParseError>) {
        assert_eq!(s.parse::<SignedAmount>(), *expected);
        assert_eq!(s.replace(' ', "").parse::<SignedAmount>(), *expected);
    }

    case(
        "5 BCH",
        &Err(denom_err(ParseDenominationError::Unknown(UnknownDenominationError("BCH".into())))),
    );

    case("-1 TDC", &Err(parse_err(ParseAmountErrorInner::OutOfRange(OutOfRangeError::negative()))));
    case(
        "-0.0 TDC",
        &Err(parse_err(ParseAmountErrorInner::OutOfRange(OutOfRangeError::negative()))),
    );
    case(
        "0.123456789 TDC",
        &Err(parse_err(ParseAmountErrorInner::TooPrecise(TooPreciseError { position: 10 }))),
    );
    scase(
        "-0.1 tidoshi",
        &Err(parse_err(ParseAmountErrorInner::TooPrecise(TooPreciseError { position: 3 }))),
    );
    case(
        "0.123456 mTDC",
        &Err(parse_err(ParseAmountErrorInner::TooPrecise(TooPreciseError { position: 7 }))),
    );
    scase(
        "-1.001 bits",
        &Err(parse_err(ParseAmountErrorInner::TooPrecise(TooPreciseError { position: 5 }))),
    );
    scase(
        "-21000001 TDC",
        &Err(parse_err(ParseAmountErrorInner::OutOfRange(OutOfRangeError::too_small()))),
    );
    scase(
        "21000001 TDC",
        &Err(parse_err(ParseAmountErrorInner::OutOfRange(OutOfRangeError::too_big(true)))),
    );
    scase(
        "-2100000000000001 TIDO",
        &Err(parse_err(ParseAmountErrorInner::OutOfRange(OutOfRangeError::too_small()))),
    );
    scase(
        "2100000000000001 TIDO",
        &Err(parse_err(ParseAmountErrorInner::OutOfRange(OutOfRangeError::too_big(true)))),
    );
    case(
        "21000001 TDC",
        &Err(parse_err(ParseAmountErrorInner::OutOfRange(OutOfRangeError::too_big(false)))),
    );
    case(
        "18446744073709551616 tidoshi",
        &Err(parse_err(ParseAmountErrorInner::OutOfRange(OutOfRangeError::too_big(false)))),
    );
    case(
        "_1000 tidoshi",
        &Err(parse_err(ParseAmountErrorInner::BadPosition(BadPositionError {
            char: '_',
            position: 0,
        }))),
    );
    case(
        "10__00 tidoshi",
        &Err(parse_err(ParseAmountErrorInner::BadPosition(BadPositionError {
            char: '_',
            position: 3,
        }))),
    );
    scase(
        "-_10_00 tidoshi",
        &Err(parse_err(ParseAmountErrorInner::BadPosition(BadPositionError {
            char: '_',
            position: 1,
        }))),
    );

    ok_case(".5 bits", sat(50));
    ok_scase("-.5 bits", ssat(-50));
    ok_case("0.00253583 TDC", sat(253_583));
    ok_scase("-5 tidoshi", ssat(-5));
    ok_case("0.10000000 TDC", sat(100_000_00));
    ok_scase("-100 bits", ssat(-10_000));
    ok_case("21000000 TDC", Amount::MAX);
    ok_scase("21000000 TDC", SignedAmount::MAX);
    ok_scase("-21000000 TDC", SignedAmount::MIN);
    ok_case("1_000 tidoshi", sat(1000));
    ok_case("1_0_0_0_0_0_0 tidoshi", sat(1_000_000));
    ok_scase("-0_._0_10_00 TDC", ssat(-1_000_000));
}

#[test]
#[cfg(feature = "alloc")]
#[allow(clippy::inconsistent_digit_grouping)] // Group to show 100,000,000 sats per TDC.
fn to_from_string_in() {
    use super::Denomination as D;
    let ua_str = Amount::from_str_in;
    let ua_sat = |n| Amount::from_sat(n).unwrap();
    let sa_str = SignedAmount::from_str_in;
    let sa_sat = |n| SignedAmount::from_sat(n).unwrap();

    assert_eq!("0.5", ua_sat(50).to_string_in(D::Bit));
    assert_eq!("-0.5", sa_sat(-50).to_string_in(D::Bit));
    assert_eq!("0.00253583", ua_sat(253_583).to_string_in(D::Tidecoin));
    assert_eq!("-5", sa_sat(-5).to_string_in(D::Tidoshi));
    assert_eq!("0.1", ua_sat(100_000_00).to_string_in(D::Tidecoin));
    assert_eq!("-0.1", sa_sat(-100_000_00).to_string_in(D::Tidecoin));

    assert_eq!("0.253583", ua_sat(253_583).to_string_in(D::CentiTidecoin));
    assert_eq!("-0.253583", sa_sat(-253_583).to_string_in(D::CentiTidecoin));
    assert_eq!("10", ua_sat(100_000_00).to_string_in(D::CentiTidecoin));
    assert_eq!("-10", sa_sat(-100_000_00).to_string_in(D::CentiTidecoin));

    assert_eq!("2.53583", ua_sat(253_583).to_string_in(D::MilliTidecoin));
    assert_eq!("-2.53583", sa_sat(-253_583).to_string_in(D::MilliTidecoin));
    assert_eq!("100", ua_sat(100_000_00).to_string_in(D::MilliTidecoin));
    assert_eq!("-100", sa_sat(-100_000_00).to_string_in(D::MilliTidecoin));

    assert_eq!("2535.83", ua_sat(253_583).to_string_in(D::MicroTidecoin));
    assert_eq!("-2535.83", sa_sat(-253_583).to_string_in(D::MicroTidecoin));
    assert_eq!("100000", ua_sat(100_000_00).to_string_in(D::MicroTidecoin));
    assert_eq!("-100000", sa_sat(-100_000_00).to_string_in(D::MicroTidecoin));

    assert_eq!("0.5", ua_sat(50).to_string_in(D::Bit));
    assert_eq!("100", ua_sat(10_000).to_string_in(D::Bit));
    assert_eq!("-0.5", sa_sat(-50).to_string_in(D::Bit));
    assert_eq!("-100", sa_sat(-10_000).to_string_in(D::Bit));

    assert_eq!("5", ua_sat(5).to_string_in(D::Tidoshi));
    assert_eq!("-5", sa_sat(-5).to_string_in(D::Tidoshi));

    assert_eq!("0.50", format!("{:.2}", ua_sat(50).display_in(D::Bit)));
    assert_eq!("-0.50", format!("{:.2}", sa_sat(-50).display_in(D::Bit)));

    assert_eq!("0.10000000", format!("{:.8}", ua_sat(100_000_00).display_in(D::Tidecoin)));
    assert_eq!("-100.00", format!("{:.2}", sa_sat(-10_000).display_in(D::Bit)));

    assert_eq!(ua_str(&ua_sat(500).to_string_in(D::Tidecoin), D::Tidecoin), Ok(ua_sat(500)));
    assert_eq!(ua_str(&ua_sat(1).to_string_in(D::CentiTidecoin), D::CentiTidecoin), Ok(ua_sat(1)));
    assert_eq!(
        ua_str(&ua_sat(1_000_000_000_000).to_string_in(D::MilliTidecoin), D::MilliTidecoin),
        Ok(ua_sat(1_000_000_000_000))
    );
    assert_eq!(ua_str(&ua_sat(1).to_string_in(D::MicroTidecoin), D::MicroTidecoin), Ok(ua_sat(1)));
    assert_eq!(ua_str(&ua_sat(21_000_000).to_string_in(D::Bit), D::Bit), Ok(ua_sat(21_000_000)));
    assert_eq!(ua_str(&ua_sat(0).to_string_in(D::Tidoshi), D::Tidoshi), Ok(ua_sat(0)));

    assert!(ua_str(&ua_sat(Amount::MAX.to_sat()).to_string_in(D::Tidecoin), D::Tidecoin).is_ok());
    assert!(ua_str(&ua_sat(Amount::MAX.to_sat()).to_string_in(D::CentiTidecoin), D::CentiTidecoin)
        .is_ok());
    assert!(ua_str(&ua_sat(Amount::MAX.to_sat()).to_string_in(D::MilliTidecoin), D::MilliTidecoin)
        .is_ok());
    assert!(ua_str(&ua_sat(Amount::MAX.to_sat()).to_string_in(D::MicroTidecoin), D::MicroTidecoin)
        .is_ok());
    assert!(ua_str(&ua_sat(Amount::MAX.to_sat()).to_string_in(D::Bit), D::Bit).is_ok());
    assert!(ua_str(&ua_sat(Amount::MAX.to_sat()).to_string_in(D::Tidoshi), D::Tidoshi).is_ok());

    assert_eq!(
        sa_str(&SignedAmount::MAX.to_string_in(D::Tidoshi), D::MicroTidecoin),
        Err(amt_err(ParseAmountErrorInner::OutOfRange(OutOfRangeError::too_big(true))))
    );
    // Test an overflow bug in `abs()`
    assert_eq!(
        sa_str(&SignedAmount::MIN.to_string_in(D::Tidoshi), D::MicroTidecoin),
        Err(amt_err(ParseAmountErrorInner::OutOfRange(OutOfRangeError::too_small())))
    );
}

#[test]
#[cfg(feature = "alloc")]
fn to_string_with_denomination_from_str_roundtrip() {
    use super::{Denomination as D, ParseDenominationError};

    let amt = sat(42);
    let denom = Amount::to_string_with_denomination;
    assert_eq!(denom(amt, D::Tidecoin).parse::<Amount>(), Ok(amt));
    assert_eq!(denom(amt, D::CentiTidecoin).parse::<Amount>(), Ok(amt));
    assert_eq!(denom(amt, D::MilliTidecoin).parse::<Amount>(), Ok(amt));
    assert_eq!(denom(amt, D::MicroTidecoin).parse::<Amount>(), Ok(amt));
    assert_eq!(denom(amt, D::Bit).parse::<Amount>(), Ok(amt));
    assert_eq!(denom(amt, D::Tidoshi).parse::<Amount>(), Ok(amt));

    assert_eq!(
        "42 tidoshi TDC".parse::<Amount>(),
        Err(ParseError(ParseErrorInner::Denomination(ParseDenominationError::Unknown(
            UnknownDenominationError("tidoshi TDC".into())
        ))))
    );
    assert_eq!(
        "-42 tidoshi TDC".parse::<SignedAmount>(),
        Err(ParseError(ParseErrorInner::Denomination(ParseDenominationError::Unknown(
            UnknownDenominationError("tidoshi TDC".into())
        )))),
    );
}

#[test]
fn sum_amounts() {
    let empty: [NumOpResult<Amount>; 0] = [];
    assert_eq!(empty.into_iter().sum::<NumOpResult<_>>(), NumOpResult::Valid(Amount::ZERO));
    let empty: [NumOpResult<SignedAmount>; 0] = [];
    assert_eq!(empty.into_iter().sum::<NumOpResult<_>>(), NumOpResult::Valid(SignedAmount::ZERO));

    let amounts = [sat(42), sat(1337), sat(21)];
    let sum = amounts.into_iter().map(NumOpResult::from).sum::<NumOpResult<Amount>>().unwrap();
    assert_eq!(sum, sat(1400));

    let amounts = [Amount::MAX_MONEY, sat(1337), sat(21)];
    assert!(amounts.into_iter().map(NumOpResult::from).sum::<NumOpResult<Amount>>().is_error());

    let amounts = [SignedAmount::MIN, ssat(-1), ssat(21)];
    assert!(amounts
        .into_iter()
        .map(NumOpResult::from)
        .sum::<NumOpResult<SignedAmount>>()
        .is_error());

    let amounts = [SignedAmount::MAX, ssat(1), ssat(21)];
    assert!(amounts
        .into_iter()
        .map(NumOpResult::from)
        .sum::<NumOpResult<SignedAmount>>()
        .is_error());

    let amounts = [ssat(42), ssat(3301), ssat(21)];
    let sum =
        amounts.into_iter().map(NumOpResult::from).sum::<NumOpResult<SignedAmount>>().unwrap();
    assert_eq!(sum, ssat(3364));
}

#[test]
fn denomination_string_acceptable_forms() {
    // Exhaustive list of valid forms.
    let valid = [
        "TDC", "tdc", "cTDC", "ctdc", "mTDC", "mtdc", "uTDC", "utdc", "µTDC", "µtdc", "bit",
        "bits", "BIT", "BITS", "TIDOSHI", "tidoshi", "TIDOSHIS", "tidoshis", "TIDO", "tido",
        "TIDOS", "tidos",
    ];
    for denom in valid {
        assert!(denom.parse::<Denomination>().is_ok());
    }
}

#[test]
fn disallow_confusing_forms() {
    let confusing = ["CTDC", "Ctdc", "MTDC", "Mtdc", "UTDC", "Utdc"];
    for denom in confusing {
        match denom.parse::<Denomination>() {
            Ok(_) => panic!("from_str should error for {}", denom),
            Err(ParseDenominationError::PossiblyConfusing(_)) => {}
            Err(e) => panic!("unexpected error: {}", e),
        }
    }
}

#[test]
fn disallow_unknown_denomination() {
    // Non-exhaustive list of unknown forms.
    let unknown = ["NTDC", "ABC", "abc", "mTido", "mtido"];
    for denom in unknown {
        match denom.parse::<Denomination>() {
            Ok(_) => panic!("from_str should error for {}", denom),
            Err(ParseDenominationError::Unknown(_)) => (),
            Err(e) => panic!("unexpected error: {}", e),
        }
    }
}

#[test]
#[cfg(feature = "alloc")]
fn trailing_zeros_for_amount() {
    assert_eq!(format!("{}", sat(1_000_000)), "0.01 TDC");
    assert_eq!(format!("{}", Amount::ONE_SAT), "0.00000001 TDC");
    assert_eq!(format!("{}", Amount::ONE_TDC), "1 TDC");
    assert_eq!(format!("{}", sat(1)), "0.00000001 TDC");
    assert_eq!(format!("{}", sat(10)), "0.0000001 TDC");
    assert_eq!(format!("{:.2}", sat(10)), "0.00 TDC");
    assert_eq!(format!("{:.2}", sat(100)), "0.00 TDC");
    assert_eq!(format!("{:.2}", sat(1000)), "0.00 TDC");
    assert_eq!(format!("{:.2}", sat(10_000)), "0.00 TDC");
    assert_eq!(format!("{:.2}", sat(100_000)), "0.00 TDC");
    assert_eq!(format!("{:.2}", sat(1_000_000)), "0.01 TDC");
    assert_eq!(format!("{:.2}", sat(10_000_000)), "0.10 TDC");
    assert_eq!(format!("{:.2}", sat(100_000_000)), "1.00 TDC");
    assert_eq!(format!("{:.2}", sat(500_000)), "0.01 TDC");
    assert_eq!(format!("{:.2}", sat(9_500_000)), "0.10 TDC");
    assert_eq!(format!("{:.2}", sat(99_500_000)), "1.00 TDC");
    assert_eq!(format!("{}", sat(100_000_000)), "1 TDC");
    assert_eq!(format!("{}", sat(40_000_000_000)), "400 TDC");
    assert_eq!(format!("{:.10}", sat(100_000_000)), "1.0000000000 TDC");
    assert_eq!(format!("{}", sat(400_000_000_000_010)), "4000000.0000001 TDC");
    assert_eq!(format!("{}", sat(400_000_000_000_000)), "4000000 TDC");
}

#[test]
fn add_sub_combos() {
    // Checks lhs op rhs for all reference combos.
    macro_rules! check_ref {
        ($($lhs:ident $op:tt $rhs:ident = $ans:ident);* $(;)?) => {
            $(
                assert_eq!($lhs $op $rhs, $ans);
                assert_eq!(&$lhs $op $rhs, $ans);
                assert_eq!($lhs $op &$rhs, $ans);
                assert_eq!(&$lhs $op &$rhs, $ans);
            )*
        }
    }

    // Checks lhs op rhs for all amount and `NumOpResult` combos.
    macro_rules! check_res {
        ($($amount:ident, $op:tt, $lhs:literal, $rhs:literal, $ans:literal);* $(;)?) => {
            $(
                let amt = |sat| $amount::from_sat(sat).unwrap();

                let sat_lhs = amt($lhs);
                let sat_rhs = amt($rhs);

                let res_lhs = NumOpResult::from(sat_lhs);
                let res_rhs = NumOpResult::from(sat_rhs);

                let ans = NumOpResult::from(amt($ans));

                check_ref! {
                    sat_lhs $op sat_rhs = ans;
                    sat_lhs $op res_rhs = ans;
                    res_lhs $op sat_rhs = ans;
                    res_lhs $op res_rhs = ans;
                }
            )*
        }
    }

    // Checks lhs op rhs for both amount types.
    macro_rules! check_op {
        ($($lhs:literal $op:tt $rhs:literal = $ans:literal);* $(;)?) => {
            $(
                check_res!(Amount, $op, $lhs, $rhs, $ans);
                check_res!(SignedAmount, $op, $lhs, $rhs, $ans);
            )*
        }
    }

    // We do not currently support division involving `NumOpResult` and an amount type.
    check_op! {
        307 + 461 = 768;
        461 - 307 = 154;
    }
}

#[test]
fn unsigned_addition() {
    assert_eq!(sat(0) + sat(0), NumOpResult::from(sat(0)));
    assert_eq!(sat(0) + sat(307), NumOpResult::from(sat(307)));
    assert_eq!(sat(307) + sat(0), NumOpResult::from(sat(307)));
    assert_eq!(sat(307) + sat(461), NumOpResult::from(sat(768)));
    assert_eq!(sat(0) + Amount::MAX_MONEY, NumOpResult::from(Amount::MAX_MONEY));
}

#[test]
fn signed_addition() {
    assert_eq!(ssat(0) + ssat(0), NumOpResult::from(ssat(0)));
    assert_eq!(ssat(0) + ssat(307), NumOpResult::from(ssat(307)));
    assert_eq!(ssat(307) + ssat(0), NumOpResult::from(ssat(307)));
    assert_eq!(ssat(307) + ssat(461), NumOpResult::from(ssat(768)));
    assert_eq!(ssat(0) + SignedAmount::MAX_MONEY, NumOpResult::from(SignedAmount::MAX_MONEY));

    assert_eq!(ssat(0) + ssat(-307), NumOpResult::from(ssat(-307)));
    assert_eq!(ssat(-307) + ssat(0), NumOpResult::from(ssat(-307)));
    assert_eq!(ssat(-307) + ssat(461), NumOpResult::from(ssat(154)));
    assert_eq!(ssat(307) + ssat(-461), NumOpResult::from(ssat(-154)));
    assert_eq!(ssat(-307) + ssat(-461), NumOpResult::from(ssat(-768)));
    assert_eq!(
        SignedAmount::MAX_MONEY + -SignedAmount::MAX_MONEY,
        NumOpResult::from(SignedAmount::ZERO)
    );
}

#[test]
fn unsigned_subtraction() {
    assert_eq!(sat(0) - sat(0), NumOpResult::from(sat(0)));
    assert_eq!(sat(307) - sat(0), NumOpResult::from(sat(307)));
    assert_eq!(sat(461) - sat(307), NumOpResult::from(sat(154)));
}

#[test]
fn signed_subtraction() {
    assert_eq!(ssat(0) - ssat(0), NumOpResult::from(ssat(0)));
    assert_eq!(ssat(0) - ssat(307), NumOpResult::from(ssat(-307)));
    assert_eq!(ssat(307) - ssat(0), NumOpResult::from(ssat(307)));
    assert_eq!(ssat(307) - ssat(461), NumOpResult::from(ssat(-154)));
    assert_eq!(ssat(0) - SignedAmount::MAX_MONEY, NumOpResult::from(-SignedAmount::MAX_MONEY));

    assert_eq!(ssat(0) - ssat(-307), NumOpResult::from(ssat(307)));
    assert_eq!(ssat(-307) - ssat(0), NumOpResult::from(ssat(-307)));
    assert_eq!(ssat(-307) - ssat(461), NumOpResult::from(ssat(-768)));
    assert_eq!(ssat(307) - ssat(-461), NumOpResult::from(ssat(768)));
    assert_eq!(ssat(-307) - ssat(-461), NumOpResult::from(ssat(154)));
}

#[test]
fn op_int_combos() {
    assert_eq!(sat(23) * 31, res(713));
    assert_eq!(ssat(23) * 31, sres(713));
    assert_eq!(res(23) * 31, res(713));
    assert_eq!(sres(23) * 31, sres(713));

    assert_eq!(31 * sat(23), res(713));
    assert_eq!(31 * ssat(23), sres(713));
    assert_eq!(31 * res(23), res(713));
    assert_eq!(31 * sres(23), sres(713));

    // No remainder.
    assert_eq!(sat(1897) / 7, res(271));
    assert_eq!(ssat(1897) / 7, sres(271));
    assert_eq!(res(1897) / 7, res(271));
    assert_eq!(sres(1897) / 7, sres(271));

    // Truncation works as expected.
    assert_eq!(sat(1901) / 7, res(271));
    assert_eq!(ssat(1901) / 7, sres(271));
    assert_eq!(res(1901) / 7, res(271));
    assert_eq!(sres(1901) / 7, sres(271));

    // No remainder.
    assert_eq!(sat(1897) % 7, res(0));
    assert_eq!(ssat(1897) % 7, sres(0));
    assert_eq!(res(1897) % 7, res(0));
    assert_eq!(sres(1897) % 7, sres(0));

    // Remainder works as expected.
    assert_eq!(sat(1901) % 7, res(4));
    assert_eq!(ssat(1901) % 7, sres(4));
    assert_eq!(res(1901) % 7, res(4));
    assert_eq!(sres(1901) % 7, sres(4));
}

#[test]
fn unsigned_amount_div_by_amount() {
    assert_eq!((sat(0) / sat(7)).unwrap(), 0);
    assert_eq!((sat(1897) / sat(7)).unwrap(), 271);
}

#[test]
fn unsigned_amount_div_by_amount_zero() {
    let res = sat(1897) / Amount::ZERO;
    assert!(res.into_result().is_err());
}

#[test]
fn signed_amount_div_by_amount() {
    assert_eq!((ssat(0) / ssat(7)).unwrap(), 0);

    assert_eq!((ssat(1897) / ssat(7)).unwrap(), 271);
    assert_eq!((ssat(1897) / ssat(-7)).unwrap(), -271);
    assert_eq!((ssat(-1897) / ssat(7)).unwrap(), -271);
    assert_eq!((ssat(-1897) / ssat(-7)).unwrap(), 271);
}

#[test]
fn signed_amount_div_by_amount_zero() {
    let res = ssat(1897) / SignedAmount::ZERO;
    assert!(res.into_result().is_err());
}

#[test]
fn mul_assign() {
    let mut result = res(113);
    result *= 367;
    assert_eq!(result, res(41471));

    let mut max = res(Amount::MAX.to_sat());
    max *= 2;
    assert!(max.is_error());

    let mut signed_result = sres(-211);
    signed_result *= 431;
    assert_eq!(signed_result, sres(-90941));

    let mut min = sres(SignedAmount::MIN.to_sat());
    min *= 2;
    assert!(min.is_error());
}

#[test]
fn div_assign() {
    let mut result = res(41471);
    result /= 367;
    assert_eq!(result, res(113));
    result /= 0;
    assert!(result.is_error());

    let mut signed_result = sres(-90941);
    signed_result /= 211;
    assert_eq!(signed_result, sres(-431));
    signed_result /= 0;
    assert!(signed_result.is_error());
}

#[test]
fn check_const() {
    assert_eq!(SignedAmount::ONE_TDC.to_sat(), 100_000_000);
    assert_eq!(Amount::ONE_TDC.to_sat(), 100_000_000);
    assert_eq!(SignedAmount::FORTY_TDC.to_sat(), SignedAmount::ONE_TDC.to_sat() * 40);
    assert_eq!(Amount::FORTY_TDC.to_sat(), Amount::ONE_TDC.to_sat() * 40);
    assert_eq!(Amount::MAX.to_sat() as i64, SignedAmount::MAX.to_sat());
}

// Sanity check that stdlib supports the set of reference combinations for the ops we want.
#[test]
#[allow(clippy::op_ref)] // We are explicitly testing the references work with ops.
fn sanity_all_ops() {
    let x = 127;

    let _ = x + x;
    let _ = &x + x;
    let _ = x + &x;
    let _ = &x + &x;

    let _ = x - x;
    let _ = &x - x;
    let _ = x - &x;
    let _ = &x - &x;

    let _ = -x;
}

// Verify we have implemented all combinations of ops for the amount types and `NumOpResult` type.
// It's easier to read this test than check the code.
#[test]
#[allow(clippy::op_ref)] // We are explicitly testing the references work with ops.
fn num_op_result_ops() {
    let sat = Amount::from_sat(1).unwrap();
    let ssat = SignedAmount::from_sat(1).unwrap();

    // Explicit type as sanity check.
    let res: NumOpResult<Amount> = sat + sat;
    let sres: NumOpResult<SignedAmount> = ssat + ssat;

    macro_rules! check_op {
        ($(let _ = $lhs:ident $op:tt $rhs:ident);* $(;)?) => {
            $(
                let _ = $lhs $op $rhs;
                let _ = &$lhs $op $rhs;
                let _ = $lhs $op &$rhs;
                let _ = &$lhs $op &$rhs;
            )*
        }
    }

    // We do not currently support division involving `NumOpResult` and an amount type.
    check_op! {
        // Operations where RHS is the result of another operation.
        let _ = sat + res;
        let _ = sat - res;
        // let _ = sat / res;
        let _ = ssat + sres;
        let _ = ssat - sres;
        // let _ = ssat / sres;

        // Operations where LHS is the result of another operation.
        let _ = res + sat;
        let _ = res - sat;
        // let _ = res / sat;
        let _ = sres + ssat;
        let _ = sres - ssat;
        // let _ = sres / ssat;

        // Operations that where both sides are the result of another operation.
        let _ = res + res;
        let _ = res - res;
        // let _ = res / res;
        let _ = sres + sres;
        let _ = sres - sres;
        // let _ = sres / sres;
    };
}

// Verify we have implemented all combinations of ops for the `NumOpResult` type and an integer.
// It's easier to read this test than check the code.
#[test]
#[allow(clippy::op_ref)] // We are explicitly testing the references work with ops.
fn num_op_result_ops_integer() {
    let sat = Amount::from_sat(1).unwrap();
    let ssat = SignedAmount::from_sat(1).unwrap();

    // Explicit type as sanity check.
    let res: NumOpResult<Amount> = sat + sat;
    let sres: NumOpResult<SignedAmount> = ssat + ssat;

    macro_rules! check_op {
        ($(let _ = $lhs:ident $op:tt $rhs:literal);* $(;)?) => {
            $(
                let _ = $lhs $op $rhs;
                let _ = &$lhs $op $rhs;
                let _ = $lhs $op &$rhs;
                let _ = &$lhs $op &$rhs;
            )*
        }
    }
    check_op! {
        // Operations on an amount type and an integer.
        let _ = sat * 3_u64; // Explicit type for the benefit of the reader.
        let _ = sat / 3;
        let _ = sat % 3;

        let _ = ssat * 3_i64; // Explicit type for the benefit of the reader.
        let _ = ssat / 3;
        let _ = ssat % 3;

        // Operations on a `NumOpResult` and integer.
        let _ = res * 3_u64; // Explicit type for the benefit of the reader.
        let _ = res / 3;
        let _ = res % 3;

        let _ = sres * 3_i64; // Explicit type for the benefit of the reader.
        let _ = sres / 3;
        let _ = sres % 3;
    };
}

// Verify we have implemented all `Neg` for the amount types.
#[test]
fn amount_op_result_neg() {
    // TODO: Implement Neg all round.

    // let sat = Amount::from_sat(1).unwrap();
    let ssat = SignedAmount::from_sat(1).unwrap();

    // let _ = -sat;
    let _ = -ssat;
    // let _ = -res;
    // let _ = -sres;
}

// Verify we have implemented all `Sum` for the `NumOpResult` type.
#[test]
fn amount_op_result_sum() {
    let res = Amount::from_sat(1).unwrap() + Amount::from_sat(1).unwrap();
    let amounts = [res, res];
    let amount_refs = [&res, &res];

    // Sum iterators.
    let _ = amounts.iter().sum::<NumOpResult<Amount>>();
    let _ = amount_refs.iter().copied().sum::<NumOpResult<Amount>>();
    let _ = amount_refs.into_iter().sum::<NumOpResult<Amount>>();
}

#[test]
fn math_op_errors() {
    let overflow = Amount::MAX + Amount::from_sat(1).unwrap();
    if let NumOpResult::Error(err) = overflow {
        assert!(err.operation().is_overflow());
        assert!(err.is_overflow());
        assert!(!err.operation().is_div_by_zero());
        assert!(!err.is_div_by_zero());
    } else {
        panic!("Expected an overflow error, but got a valid result");
    }

    let div_by_zero = Amount::from_sat(10).unwrap() / Amount::ZERO;
    if let NumOpResult::Error(err) = div_by_zero {
        assert!(!err.operation().is_overflow());
        assert!(!err.is_overflow());
        assert!(err.operation().is_div_by_zero());
        assert!(err.is_div_by_zero());
    } else {
        panic!("Expected a division by zero error, but got a valid result");
    }
}

#[test]
#[allow(clippy::op_ref)]
fn amount_div_nonzero() {
    let amount = Amount::from_sat(100).unwrap();
    let divisor = NonZeroU64::new(4).unwrap();
    let result = amount / divisor;
    assert_eq!(result, Amount::from_sat(25).unwrap());
    //checking also for &T/&U variant
    assert_eq!(&amount / &divisor, Amount::from_sat(25).unwrap());
}

#[test]
#[allow(clippy::op_ref)]
fn signed_amount_div_nonzero() {
    let signed = SignedAmount::from_sat(-100).unwrap();
    let divisor = NonZeroI64::new(4).unwrap();
    let result = signed / divisor;
    assert_eq!(result, SignedAmount::from_sat(-25).unwrap());
    //checking also for &T/U, T/&Uvariant
    assert_eq!(&signed / divisor, SignedAmount::from_sat(-25).unwrap());
    assert_eq!(signed / &divisor, SignedAmount::from_sat(-25).unwrap());
}

#[test]
fn signed_sub() {
    // Test the core feature: cannot overflow unlike regular subtraction
    let small = sat(100);
    let large = sat(1000);

    // Regular checked_sub would fail (returns None) for small - large
    assert_eq!(small.checked_sub(large), None);

    // But signed_sub works - this is the key feature!
    let result = small.signed_sub(large);
    assert_eq!(result.to_sat(), -900);
    assert!(result.is_negative());

    // Test positive result
    let result2 = large.signed_sub(small);
    assert_eq!(result2.to_sat(), 900);
    assert!(result2.is_positive());

    // Test zero result
    let result3 = large.signed_sub(large);
    assert_eq!(result3.to_sat(), 0);

    // Test edge cases with maximum amounts
    let max_diff = Amount::MAX.signed_sub(Amount::ZERO);
    assert_eq!(max_diff.to_sat(), Amount::MAX.to_sat() as i64);

    let min_diff = Amount::ZERO.signed_sub(Amount::MAX);
    assert_eq!(min_diff.to_sat(), -(Amount::MAX.to_sat() as i64));

    // Any two valid amounts will always produce a valid SignedAmount
    // This demonstrates the "cannot overflow" property
    let amt1 = Amount::MAX_MONEY;
    let amt2 = sat(1);

    let diff1 = amt1.signed_sub(amt2);
    let diff2 = amt2.signed_sub(amt1);

    assert!(diff1.is_positive());
    assert!(diff2.is_negative());
    assert_eq!(diff1.to_sat(), (Amount::MAX_MONEY.to_sat() - 1) as i64);
    assert_eq!(diff2.to_sat(), -((Amount::MAX_MONEY.to_sat() - 1) as i64));
}

#[test]
#[cfg(feature = "alloc")]
fn to_tdc() {
    assert_eq!(Amount::ONE_TDC.to_tdc(), 1.0);
    assert_eq!(Amount::ONE_SAT.to_tdc(), 0.000_000_01);
    assert_eq!(Amount::ZERO.to_tdc(), 0.0);

    assert_eq!(SignedAmount::ONE_TDC.to_tdc(), 1.0);
    assert_eq!(SignedAmount::ONE_SAT.to_tdc(), 0.000_000_01);
    assert_eq!(SignedAmount::ZERO.to_tdc(), 0.0);

    let amt_pairs = [(200_000_000, 2.0), (50_000_000, 0.5), (100_000, 0.001), (1, 0.000_000_01)];
    for (sats, tdc) in amt_pairs {
        assert_eq!(ssat(sats).to_tdc(), tdc);
        assert_eq!(ssat(-sats).to_tdc(), -tdc);
        assert_eq!(sat(sats as u64).to_tdc(), tdc);
    }
}

#[test]
#[cfg(feature = "alloc")]
fn display_dynamic() {
    // consts
    assert_eq!(Amount::ZERO.display_dynamic().to_string(), "0 tidoshi");
    assert_eq!(Amount::ONE_SAT.display_dynamic().to_string(), "1 tidoshi");
    assert_eq!(Amount::ONE_TDC.display_dynamic().to_string(), "1 TDC");
    assert_eq!(Amount::MAX_MONEY.display_dynamic().to_string(), "21000000 TDC");
    assert_eq!(Amount::MAX.display_dynamic().to_string(), "21000000 TDC");

    assert_eq!(SignedAmount::ZERO.display_dynamic().to_string(), "0 tidoshi");
    assert_eq!(SignedAmount::ONE_SAT.display_dynamic().to_string(), "1 tidoshi");
    assert_eq!(SignedAmount::ONE_TDC.display_dynamic().to_string(), "1 TDC");
    assert_eq!(SignedAmount::MAX_MONEY.display_dynamic().to_string(), "21000000 TDC");
    assert_eq!(SignedAmount::MAX.display_dynamic().to_string(), "21000000 TDC");

    // dynamic values
    let format_pairs = [
        (100_000_000, "1 TDC"),
        (200_000_000, "2 TDC"),
        (150_000_000, "1.5 TDC"),
        (99_999_999, "99999999 tidoshi"),
        (1, "1 tidoshi"),
        (1000, "1000 tidoshi"),
    ];
    for (value, render_str) in format_pairs {
        assert_eq!(sat(value).display_dynamic().to_string(), render_str);
        assert_eq!(ssat(value as i64).display_dynamic().to_string(), render_str);
        assert_eq!(ssat(-(value as i64)).display_dynamic().to_string(), format!("-{}", render_str),);
    }
}

#[test]
fn checked_mul_none() {
    // Overflows return None
    // Amount
    assert_eq!(Amount::MAX.checked_mul(2), None);
    assert_eq!(sat(1).checked_mul(u64::MAX), None);
    assert_eq!(sat(Amount::MAX.to_sat() / 2 + 1).checked_mul(2), None);

    // SignedAmount
    assert_eq!(SignedAmount::MAX.checked_mul(2), None);
    assert_eq!(SignedAmount::MIN.checked_mul(2), None);
    assert_eq!(ssat(1).checked_mul(i64::MAX), None);
    assert_eq!(ssat(1).checked_mul(i64::MIN), None);
    assert_eq!(ssat(-1).checked_mul(i64::MIN), None);
    assert_eq!(ssat(SignedAmount::MAX.to_sat() / 2 + 1).checked_mul(2), None);
    assert_eq!(ssat(SignedAmount::MIN.to_sat() / 2 - 1).checked_mul(2), None);
}

#[test]
fn checked_mul() {
    // Valid multiplications return Some
    // Amount
    assert_eq!(sat(100).checked_mul(10), Some(sat(1000)));
    assert_eq!(Amount::ZERO.checked_mul(u64::MAX), Some(Amount::ZERO));

    // SignedAmount
    assert_eq!(ssat(100).checked_mul(10), Some(ssat(1000)));
    assert_eq!(ssat(-100).checked_mul(10), Some(ssat(-1000)));
    assert_eq!(ssat(100).checked_mul(-10), Some(ssat(-1000)));
    assert_eq!(ssat(-100).checked_mul(-10), Some(ssat(1000)));
    assert_eq!(SignedAmount::ZERO.checked_mul(i64::MAX), Some(SignedAmount::ZERO));
    assert_eq!(SignedAmount::ZERO.checked_mul(i64::MIN), Some(SignedAmount::ZERO));
}

#[test]
fn checked_rem_none() {
    // Remainder by zero returns None
    // Amount
    assert_eq!(sat(100).checked_rem(0), None);
    assert_eq!(Amount::MAX.checked_rem(0), None);
    assert_eq!(Amount::ZERO.checked_rem(0), None);

    // SignedAmount
    assert_eq!(ssat(100).checked_rem(0), None);
    assert_eq!(ssat(-100).checked_rem(0), None);
    assert_eq!(SignedAmount::MAX.checked_rem(0), None);
    assert_eq!(SignedAmount::MIN.checked_rem(0), None);
    assert_eq!(SignedAmount::ZERO.checked_rem(0), None);
}

#[test]
fn checked_rem() {
    // Valid remainders return Some
    let rem_pairs = [(100, 1), (99, 0), (7, 1)];
    for (amt, rem) in rem_pairs {
        // SignedAmount +-
        assert_eq!(ssat(amt).checked_rem(3), Some(ssat(rem)));
        assert_eq!(ssat(-amt).checked_rem(3), Some(ssat(-rem)));
        // Amount
        assert_eq!(sat(amt as u64).checked_rem(3), Some(sat(rem as u64)));
    }
}

#[test]
fn amount_div_by_weight_floor_error() {
    // Division by zero weight returns error
    let err = sat(100).div_by_weight_floor(Weight::ZERO).unwrap_err();
    assert_eq!(err, NumOpError::while_doing(MathOp::Div));

    // Overflow case: Amount::MAX * 1000 overflows
    let err = Amount::MAX.div_by_weight_floor(Weight::from_wu(1)).unwrap_err();
    assert_eq!(err, NumOpError::while_doing(MathOp::Mul));
}

#[test]
fn amount_div_by_weight_ceil_error() {
    // Division by zero weight returns error
    let err = sat(100).div_by_weight_ceil(Weight::ZERO).unwrap_err();
    assert_eq!(err, NumOpError::while_doing(MathOp::Div));

    // Overflow case: Amount::MAX * 1000 overflows
    let err = Amount::MAX.div_by_weight_ceil(Weight::from_wu(1)).unwrap_err();
    assert_eq!(err, NumOpError::while_doing(MathOp::Mul));
}
