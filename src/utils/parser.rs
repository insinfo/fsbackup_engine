
use bytesize::ByteSize;
use chrono::format::ParseError;
use chrono::prelude::*;
use regex::Regex;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

/// ### parse_lstime
///
/// Convert ls syntax time to System Time
/// ls time has two possible syntax:
/// 1. if year is current: %b %d %H:%M (e.g. Nov 5 13:46)
/// 2. else: %b %d %Y (e.g. Nov 5 2019)
pub fn parse_lstime(tm: &str, fmt_year: &str, fmt_hours: &str) -> Result<SystemTime, ParseError> {
    let datetime: NaiveDateTime = match NaiveDate::parse_from_str(tm, fmt_year) {
        Ok(date) => {
            // Case 2.
            // Return NaiveDateTime from NaiveDate with time 00:00:00
            date.and_hms(0, 0, 0)
        }
        Err(_) => {
            // Might be case 1.
            // We need to add Current Year at the end of the string
            let this_year: i32 = Utc::now().year();
            let date_time_str: String = format!("{} {}", tm, this_year);
            // Now parse
            NaiveDateTime::parse_from_str(
                date_time_str.as_ref(),
                format!("{} %Y", fmt_hours).as_ref(),
            )?
        }
    };
    // Convert datetime to system time
    let sys_time: SystemTime = SystemTime::UNIX_EPOCH;
    Ok(sys_time
        .checked_add(Duration::from_secs(datetime.timestamp() as u64))
        .unwrap_or(SystemTime::UNIX_EPOCH))
}