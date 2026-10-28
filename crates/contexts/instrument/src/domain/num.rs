//! Exact rational numbers for rule evaluation and unit conversion.
//!
//! Rules compute on [`Num`], a reduced fraction of two `i128`s, so that every operation the
//! rule language allows (`+ - * /`) and every UCUM conversion factor is exact and identical
//! on every platform (INS-046). There is no floating point anywhere. Results leave the
//! evaluator as [`Decimal`]s, exactly when the fraction terminates, or by explicit rounding.

use std::cmp::Ordering;
use std::fmt;

use fieldseal_kernel::Decimal;

/// An exact rational number `num / den`, always reduced, with `den > 0`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Num {
    num: i128,
    den: i128,
}

/// An arithmetic result didn't fit in 128 bits, or divided by zero.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum NumError {
    /// The numerator or denominator overflowed.
    #[error("arithmetic overflow")]
    Overflow,
    /// Division by zero.
    #[error("division by zero")]
    DivisionByZero,
}

fn gcd(mut a: i128, mut b: i128) -> i128 {
    a = a.abs();
    b = b.abs();
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

fn pow10(exp: u32) -> Option<i128> {
    10i128.checked_pow(exp)
}

// The arithmetic methods share names with `std::ops` but return a `Result`: overflow and
// division by zero must be handled, never wrap or panic.
#[allow(clippy::should_implement_trait)]
impl Num {
    /// Zero.
    pub const ZERO: Num = Num { num: 0, den: 1 };
    /// One.
    pub const ONE: Num = Num { num: 1, den: 1 };

    /// The fraction `num / den`, reduced.
    pub fn ratio(num: i128, den: i128) -> Result<Num, NumError> {
        if den == 0 {
            return Err(NumError::DivisionByZero);
        }
        let g = gcd(num, den).max(1);
        let (mut n, mut d) = (num / g, den / g);
        if d < 0 {
            n = n.checked_neg().ok_or(NumError::Overflow)?;
            d = d.checked_neg().ok_or(NumError::Overflow)?;
        }
        Ok(Num { num: n, den: d })
    }

    /// An integer.
    pub fn int(value: i128) -> Num {
        Num { num: value, den: 1 }
    }

    /// The exact value of a decimal, if it fits.
    pub fn from_decimal(d: Decimal) -> Option<Num> {
        if d.exponent >= 0 {
            Some(Num::int(d.mantissa.checked_mul(pow10(d.exponent.unsigned_abs())?)?))
        } else {
            Num::ratio(d.mantissa, pow10(d.exponent.unsigned_abs())?).ok()
        }
    }

    /// Parses plain decimal notation (see [`Decimal::parse`]).
    pub fn parse(text: &str) -> Option<Num> {
        Num::from_decimal(Decimal::parse(text).ok()?)
    }

    /// The numerator.
    pub fn numerator(self) -> i128 {
        self.num
    }

    /// The (positive) denominator.
    pub fn denominator(self) -> i128 {
        self.den
    }

    /// Whether this is an integer.
    pub fn is_integer(self) -> bool {
        self.den == 1
    }

    /// Whether this is below zero.
    pub fn is_negative(self) -> bool {
        self.num < 0
    }

    /// Whether this is zero.
    pub fn is_zero(self) -> bool {
        self.num == 0
    }

    /// `self + other`.
    pub fn add(self, other: Num) -> Result<Num, NumError> {
        let g = gcd(self.den, other.den);
        let lhs_factor = other.den / g;
        let rhs_factor = self.den / g;
        let den = self.den.checked_mul(lhs_factor).ok_or(NumError::Overflow)?;
        let a = self.num.checked_mul(lhs_factor).ok_or(NumError::Overflow)?;
        let b = other.num.checked_mul(rhs_factor).ok_or(NumError::Overflow)?;
        Num::ratio(a.checked_add(b).ok_or(NumError::Overflow)?, den)
    }

    /// `-self`.
    pub fn neg(self) -> Result<Num, NumError> {
        Ok(Num { num: self.num.checked_neg().ok_or(NumError::Overflow)?, den: self.den })
    }

    /// `self - other`.
    pub fn sub(self, other: Num) -> Result<Num, NumError> {
        self.add(other.neg()?)
    }

    /// `self * other`.
    pub fn mul(self, other: Num) -> Result<Num, NumError> {
        let g1 = gcd(self.num, other.den).max(1);
        let g2 = gcd(other.num, self.den).max(1);
        let num = (self.num / g1).checked_mul(other.num / g2).ok_or(NumError::Overflow)?;
        let den = (self.den / g2).checked_mul(other.den / g1).ok_or(NumError::Overflow)?;
        Num::ratio(num, den)
    }

    /// `self / other`.
    pub fn div(self, other: Num) -> Result<Num, NumError> {
        if other.num == 0 {
            return Err(NumError::DivisionByZero);
        }
        self.mul(Num::ratio(other.den, other.num)?)
    }

    /// `|self|`.
    pub fn abs(self) -> Result<Num, NumError> {
        if self.num < 0 { self.neg() } else { Ok(self) }
    }

    /// The exact decimal, with the fewest fraction digits that represent it, if the fraction
    /// terminates (its denominator has no prime factors but 2 and 5).
    pub fn to_decimal(self) -> Option<Decimal> {
        let mut d = self.den;
        let (mut twos, mut fives) = (0u32, 0u32);
        while d % 2 == 0 {
            d /= 2;
            twos += 1;
        }
        while d % 5 == 0 {
            d /= 5;
            fives += 1;
        }
        if d != 1 {
            return None;
        }
        let scale = twos.max(fives);
        let factor = pow10(scale)? / self.den;
        Some(Decimal { mantissa: self.num.checked_mul(factor)?, exponent: -i32::try_from(scale).ok()? })
    }

    /// Rounds to `digits` fraction digits, half away from zero, as a decimal with exactly
    /// that scale.
    pub fn round(self, digits: u32) -> Result<Decimal, NumError> {
        let factor = pow10(digits).ok_or(NumError::Overflow)?;
        let scaled = self.num.checked_mul(factor).ok_or(NumError::Overflow)?;
        let q = scaled / self.den;
        let r = scaled % self.den;
        // Compare 2|r| with den to decide; away from zero on ties.
        let twice = r.unsigned_abs().checked_mul(2).ok_or(NumError::Overflow)?;
        let mantissa = if twice >= self.den.unsigned_abs() { q + scaled.signum() } else { q };
        Ok(Decimal { mantissa, exponent: -i32::try_from(digits).map_err(|_| NumError::Overflow)? })
    }

    /// Whether the value has at most `digits` fraction digits.
    pub fn fits_scale(self, digits: u32) -> bool {
        match pow10(digits) {
            Some(f) => f % self.den == 0,
            None => false,
        }
    }

    /// Numeric comparison. Never fails: comparisons widen to 256 bits internally.
    pub fn cmp_num(self, other: Num) -> Ordering {
        // a/b ? c/d  <=>  a*d ? c*b  (b, d > 0)
        mul_wide(self.num, other.den).cmp(&mul_wide(other.num, self.den))
    }

    /// The mean of two numbers.
    pub fn mean2(self, other: Num) -> Result<Num, NumError> {
        self.add(other)?.div(Num::int(2))
    }
}

/// A 256-bit signed product of two `i128`s, as (sign, high, low) ordered tuple.
fn mul_wide(a: i128, b: i128) -> (bool, u128, u128) {
    let negative = (a < 0) != (b < 0) && a != 0 && b != 0;
    let (x, y) = (a.unsigned_abs(), b.unsigned_abs());
    let (x_hi, x_lo) = (x >> 64, x & u128::from(u64::MAX));
    let (y_hi, y_lo) = (y >> 64, y & u128::from(u64::MAX));
    let lo_lo = x_lo * y_lo;
    let hi_lo = x_hi * y_lo;
    let lo_hi = x_lo * y_hi;
    let hi_hi = x_hi * y_hi;
    let mid = (lo_lo >> 64) + (hi_lo & u128::from(u64::MAX)) + (lo_hi & u128::from(u64::MAX));
    let low = (lo_lo & u128::from(u64::MAX)) | (mid << 64);
    let high = hi_hi + (hi_lo >> 64) + (lo_hi >> 64) + (mid >> 64);
    if negative {
        // Order negatives before positives, and larger magnitudes first.
        (false, !high, !low)
    } else {
        (true, high, low)
    }
}

impl PartialOrd for Num {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Num {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_num(*other)
    }
}

impl fmt::Display for Num {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_decimal() {
            Some(d) => write!(f, "{d}"),
            None => write!(f, "{}/{}", self.num, self.den),
        }
    }
}
