//! A minimal proleptic-Gregorian calendar date.
//!
//! Registry expiries need parsing, ordering, and a calendar month — nothing
//! more. A dedicated date crate would pull a timezone database and a wider
//! licence surface into a binary whose whole trust story is that it is small and
//! auditable, so the twenty lines live here instead.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A calendar date, `YYYY-MM-DD`. No time, no zone.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
pub struct Date {
    // Field order carries the Ord derive: year, then month, then day.
    /// Proleptic Gregorian year.
    pub year: i32,
    /// Month, 1-12.
    pub month: u32,
    /// Day of month, 1-31, validated against the month and leap year.
    pub day: u32,
}

/// The supplied text was not a calendar date.
#[derive(Debug, thiserror::Error)]
#[error("'{0}' is not an ISO date (expected YYYY-MM-DD)")]
pub struct DateParseError(String);

/// The system clock reads before the Unix epoch.
#[derive(Debug, thiserror::Error)]
#[error(
    "the system clock reads before 1970-01-01; \
     expiry dates cannot be evaluated against it (pass --as-of to supply a date)"
)]
pub struct ClockError;

impl Date {
    /// Construct, validating the day against the month and leap year.
    pub fn new(year: i32, month: u32, day: u32) -> Option<Self> {
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
            return None;
        }
        Some(Self { year, month, day })
    }

    /// Today, from the system clock, in UTC.
    ///
    /// Callers that need determinism pass an explicit date instead — which is
    /// why the lint takes `--as-of`. A lint whose result depends on when it runs
    /// makes a green build decay silently.
    ///
    /// Fails on a pre-epoch clock rather than substituting a date. Every use of
    /// this is a staleness comparison, and silently answering `1970-01-01`
    /// would make every claim in the registry look fresh for the next half
    /// century — the expiry mechanism switched off, reported as a pass. A
    /// machine whose clock is that wrong cannot support the question being
    /// asked, and saying so is the only useful answer.
    pub fn today_utc() -> Result<Self, ClockError> {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ClockError)?
            .as_secs() as i64;
        Ok(Self::from_days_since_epoch(secs.div_euclid(86_400)))
    }

    /// Convert a day count since 1970-01-01 into a civil date.
    ///
    /// Howard Hinnant's `civil_from_days`, which shifts the era to start in
    /// March so the leap day lands at the end of a 400-year cycle.
    pub fn from_days_since_epoch(days: i64) -> Self {
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        Self {
            year: (y + i64::from(m <= 2)) as i32,
            month: m as u32,
            day: d as u32,
        }
    }

    /// `YYYY-MM` — the bucket the expiry-stagger rule counts in.
    pub fn year_month(&self) -> String {
        format!("{:04}-{:02}", self.year, self.month)
    }
}

impl std::str::FromStr for Date {
    type Err = DateParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || DateParseError(s.to_string());
        let parts: Vec<&str> = s.split('-').collect();
        // Fixed widths only: "2027-3-1" is rejected so that string ordering and
        // date ordering never disagree.
        if parts.len() != 3 || parts[0].len() != 4 || parts[1].len() != 2 || parts[2].len() != 2 {
            return Err(err());
        }
        let year = parts[0].parse::<i32>().map_err(|_| err())?;
        let month = parts[1].parse::<u32>().map_err(|_| err())?;
        let day = parts[2].parse::<u32>().map_err(|_| err())?;
        Date::new(year, month, day).ok_or_else(err)
    }
}

impl TryFrom<String> for Date {
    type Error = DateParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Date> for String {
    fn from(date: Date) -> Self {
        date.to_string()
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_renders_round_trip() {
        let d: Date = "2027-03-15".parse().unwrap();
        assert_eq!((d.year, d.month, d.day), (2027, 3, 15));
        assert_eq!(d.to_string(), "2027-03-15");
        assert_eq!(d.year_month(), "2027-03");
    }

    #[test]
    fn rejects_impossible_and_loosely_formatted_dates() {
        for bad in [
            "2027-02-30",
            "2026-02-29",
            "2027-13-01",
            "2027-00-10",
            "2027-3-15",
            "27-03-15",
            "not-a-date",
            "",
        ] {
            assert!(bad.parse::<Date>().is_err(), "should reject {bad:?}");
        }
        assert!("2028-02-29".parse::<Date>().is_ok(), "2028 is a leap year");
    }

    #[test]
    fn orders_chronologically() {
        let a: Date = "2027-01-31".parse().unwrap();
        let b: Date = "2027-02-01".parse().unwrap();
        assert!(a < b);
        assert!("2026-12-31".parse::<Date>().unwrap() < a);
    }

    /// A working clock still produces a usable date.
    ///
    /// The failure path needs a pre-epoch clock and so cannot be exercised
    /// here; this pins the half that can be, and the lower bound holds for as
    /// long as the code exists.
    #[test]
    fn a_working_clock_yields_a_plausible_date() {
        let today = Date::today_utc().expect("the test machine's clock is sane");
        assert!(
            today.year >= 2026,
            "today_utc returned {today}, which is before this code was written"
        );
    }

    #[test]
    fn epoch_conversion_matches_known_days() {
        assert_eq!(Date::from_days_since_epoch(0).to_string(), "1970-01-01");
        assert_eq!(Date::from_days_since_epoch(-1).to_string(), "1969-12-31");
        // 2000-03-01, just past the leap day of a 400-year leap year.
        assert_eq!(
            Date::from_days_since_epoch(11_017).to_string(),
            "2000-03-01"
        );
        assert_eq!(
            Date::from_days_since_epoch(19_723).to_string(),
            "2024-01-01"
        );
    }
}
