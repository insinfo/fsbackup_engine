use crate::fs::UnixPex;

use chrono::prelude::*;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// ### fmt_pex
///
/// Convert permissions bytes of permissions value into ls notation (e.g. rwx,-wx,--x)
pub fn fmt_pex(pex: UnixPex) -> String {
    format!(
        "{}{}{}",
        match pex.can_read() {
            true => 'r',
            false => '-',
        },
        match pex.can_write() {
            true => 'w',
            false => '-',
        },
        match pex.can_execute() {
            true => 'x',
            false => '-',
        }
    )
}

/// ### instant_to_str
///
/// Format a `Instant` into a time string
pub fn fmt_time(time: SystemTime, fmt: &str) -> String {
    let datetime: DateTime<Local> = time.into();
    format!("{}", datetime.format(fmt))
}

/// ### fmt_millis
///
/// Format duration as {secs}.{millis}
pub fn fmt_millis(duration: Duration) -> String {
    let seconds: u128 = duration.as_millis() / 1000;
    let millis: u128 = duration.as_millis() % 1000;
    format!("{}.{:0width$}", seconds, millis, width = 3)
}

/// ### elide_path
///
/// Elide a path if longer than width
/// In this case, the path is formatted to {ANCESTOR[0]}/…/{PARENT[0]}/{BASENAME}
pub fn fmt_path_elide(p: &Path, width: usize) -> String {
    fmt_path_elide_ex(p, width, 0)
}

/// ### fmt_path_elide_ex
///
/// Elide a path if longer than width
/// In this case, the path is formatted to {ANCESTOR[0]}/…/{PARENT[0]}/{BASENAME}
/// This function allows to specify an extra length to consider to elide path
pub fn fmt_path_elide_ex(p: &Path, width: usize, extra_len: usize) -> String {
    let fmt_path: String = format!("{}", p.display());
    match fmt_path.len() + extra_len > width as usize {
        false => fmt_path,
        true => {
            // Elide
            let ancestors_len: usize = p.ancestors().count();
            let mut ancestors = p.ancestors();
            let mut elided_path: PathBuf = PathBuf::new();
            // If ancestors_len's size is bigger than 2, push count - 2
            if ancestors_len > 2 {
                elided_path.push(ancestors.nth(ancestors_len - 2).unwrap());
            }
            // If ancestors_len is bigger than 3, push '…' and parent too
            if ancestors_len > 3 {
                elided_path.push("…");
                if let Some(parent) = p.ancestors().nth(1) {
                    elided_path.push(parent.file_name().unwrap());
                }
            }
            // Push file_name
            if let Some(name) = p.file_name() {
                elided_path.push(name);
            }
            format!("{}", elided_path.display())
        }
    }
}

/// ### shadow_password
///
/// Return a string with the same length of input string, but each character is replaced by '*'
pub fn shadow_password(s: &str) -> String {
    (0..s.len()).map(|_| '*').collect()
}

/// ### fmt_bytes
///
/// Format bytes
pub fn fmt_bytes(v: u64) -> String {
    if v >= 1125899906842624 {
        format!("{} PB", v / 1125899906842624)
    } else if v >= 1099511627776 {
        format!("{} TB", v / 1099511627776)
    } else if v >= 1073741824 {
        format!("{} GB", v / 1073741824)
    } else if v >= 1048576 {
        format!("{} MB", v / 1048576)
    } else if v >= 1024 {
        format!("{} KB", v / 1024)
    } else {
        format!("{} B", v)
    }
}
