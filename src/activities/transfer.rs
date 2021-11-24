use bytesize::ByteSize;
use std::fmt;
use std::time::Instant;


// -- States and progress

/// ### TransferStates
///
/// TransferStates contains the states related to the transfer process
pub struct TransferStates {
    aborted: bool,               // Describes whether the transfer process has been aborted
    pub full: ProgressStates,    // full transfer states
    pub partial: ProgressStates, // Partial transfer states
}

/// ### ProgressStates
///
/// Progress states describes the states for the progress of a single transfer part
pub struct ProgressStates {
    started: Instant,
    total: usize,
    written: usize,
}

impl Default for TransferStates {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferStates {
    /// ### new
    ///
    /// Instantiates a new transfer states
    pub fn new() -> TransferStates {
        TransferStates {
            aborted: false,
            full: ProgressStates::default(),
            partial: ProgressStates::default(),
        }
    }

    /// ### reset
    ///
    /// Re-intiialize transfer states
    pub fn reset(&mut self) {
        self.aborted = false;
    }

    /// ### abort
    ///
    /// Set aborted to true
    pub fn abort(&mut self) {
        self.aborted = true;
    }

    /// ### aborted
    ///
    /// Returns whether transfer has been aborted
    pub fn aborted(&self) -> bool {
        self.aborted
    }

    /// ### full_size
    ///
    /// Returns the size of the entire transfer
    pub fn full_size(&self) -> usize {
        self.full.total
    }
}

impl Default for ProgressStates {
    fn default() -> Self {
        ProgressStates {
            started: Instant::now(),
            written: 0,
            total: 0,
        }
    }
}

impl fmt::Display for ProgressStates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let eta: String = match self.calc_eta() {
            0 => String::from("--:--"),
            seconds => format!(
                "{:0width$}:{:0width$}",
                (seconds / 60),
                (seconds % 60),
                width = 2
            ),
        };
        write!(
            f,
            "{:.2}% - ETA {} ({}/s)",
            self.calc_progress_percentage(),
            eta,
            ByteSize(self.calc_bytes_per_second())
        )
    }
}

impl ProgressStates {
    /// ### init
    ///
    /// Initialize a new Progress State
    pub fn init(&mut self, sz: usize) {
        self.started = Instant::now();
        self.total = sz;
        self.written = 0;
    }

    /// ### update_progress
    ///
    /// Update progress state
    pub fn update_progress(&mut self, delta: usize) -> f64 {
        self.written += delta;
        self.calc_progress_percentage()
    }

    /// ### calc_progress
    ///
    /// Calculate progress in a range between 0.0 to 1.0
    pub fn calc_progress(&self) -> f64 {
        // Prevent dividing by 0
        if self.total == 0 {
            return 0.0;
        }
        let prog: f64 = (self.written as f64) / (self.total as f64);
        match prog > 1.0 {
            true => 1.0,
            false => prog,
        }
    }

    /// ### started
    ///
    /// Get started
    pub fn started(&self) -> Instant {
        self.started
    }

    /// ### calc_progress_percentage
    ///
    /// Calculate the current transfer progress as percentage
    fn calc_progress_percentage(&self) -> f64 {
        self.calc_progress() * 100.0
    }

    /// ### calc_bytes_per_second
    ///
    /// Generic function to calculate bytes per second using elapsed time since transfer started and the bytes written
    /// and the total amount of bytes to write
    pub fn calc_bytes_per_second(&self) -> u64 {
        // bytes_written : elapsed_secs = x : 1
        let elapsed_secs: u64 = self.started.elapsed().as_secs();
        match elapsed_secs {
            0 => match self.written == self.total {
                // NOTE: would divide by 0 :D
                true => self.total as u64, // Download completed in less than 1 second
                false => 0,                // 0 B/S
            },
            _ => self.written as u64 / elapsed_secs,
        }
    }

    /// ### calc_eta
    ///
    /// Calculate ETA for current transfer as seconds
    fn calc_eta(&self) -> u64 {
        let elapsed_secs: u64 = self.started.elapsed().as_secs();
        let prog: f64 = self.calc_progress_percentage();
        match prog as u64 {
            0 => 0,
            _ => ((elapsed_secs * 100) / (prog as u64)) - elapsed_secs,
        }
    }
}

// -- Options

/// ## TransferOpts
///
/// Defines the transfer options for transfer actions
pub struct TransferOpts {
    /// Save file as
    pub save_as: Option<String>,
    /// Whether to check if file is being replaced
    pub check_replace: bool,
}

impl Default for TransferOpts {
    fn default() -> Self {
        Self {
            save_as: None,
            check_replace: true,
        }
    }
}

impl TransferOpts {
    /// ### save_as
    ///
    /// Define the name of the file to be saved
    pub fn save_as<S: AsRef<str>>(mut self, n: Option<S>) -> Self {
        self.save_as = n.map(|x| x.as_ref().to_string());
        self
    }

    /// ### check_replace
    ///
    /// Set whether to check if the file being transferred will "replace" an existing one
    pub fn check_replace(mut self, opt: bool) -> Self {
        self.check_replace = opt;
        self
    }
}
