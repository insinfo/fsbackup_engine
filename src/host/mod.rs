// ext
use std::fs::{self, File, Metadata, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use thiserror::Error;
use wildmatch::WildMatch;
// Metadata ext
#[cfg(target_family = "unix")]
use std::fs::set_permissions;
#[cfg(target_family = "unix")]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

// Locals
#[cfg(target_family = "unix")]
use crate::fs::UnixPex;
use crate::fs::{FsDirectory, FsEntry, FsFile};
use crate::utils::path;

/// ## HostErrorType
///
/// HostErrorType provides an overview of the specific host error
#[derive(Error, Debug)]
pub enum HostErrorType {
    #[error("No such file or directory")]
    NoSuchFileOrDirectory,
    #[error("File is readonly")]
    ReadonlyFile,
    #[error("Could not access directory")]
    DirNotAccessible,
    #[error("Could not access file")]
    FileNotAccessible,
    #[error("File already exists")]
    FileAlreadyExists,
    #[error("Could not create file")]
    CouldNotCreateFile,
    #[error("Command execution failed")]
    ExecutionFailed,
    #[error("Could not delete file")]
    DeleteFailed,
}

/// ### HostError
///
/// HostError is a wrapper for the error type and the exact io error
#[derive(Debug)]
pub struct HostError {
    pub error: HostErrorType,
    ioerr: Option<std::io::Error>,
    path: Option<PathBuf>,
}

impl HostError {
    /// ### new
    ///
    /// Instantiates a new HostError
    pub(crate) fn new(error: HostErrorType, errno: Option<std::io::Error>, p: &Path) -> Self {
        HostError {
            error,
            ioerr: errno,
            path: Some(p.to_path_buf()),
        }
    }
}

impl From<HostErrorType> for HostError {
    fn from(error: HostErrorType) -> Self {
        HostError {
            error,
            ioerr: None,
            path: None,
        }
    }
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let p_str: String = match self.path.as_ref() {
            None => String::new(),
            Some(p) => format!(" ({})", p.display().to_string()),
        };
        match &self.ioerr {
            Some(err) => write!(f, "{}: {}{}", self.error, err, p_str),
            None => write!(f, "{}{}", self.error, p_str),
        }
    }
}

/// ## Localhost
///
/// Localhost is the entity which holds the information about the current directory and host.
/// It provides functions to navigate across the local host file system
pub struct Localhost {
    wrkdir: PathBuf,
    files: Vec<FsEntry>,
}

impl Localhost {
    /// ### new
    ///
    /// Instantiates a new Localhost struct
    pub fn new(wrkdir: PathBuf) -> Result<Localhost, HostError> {
        debug!("Initializing localhost at {}", wrkdir.display());
        let mut host: Localhost = Localhost {
            wrkdir,
            files: Vec::new(),
        };
        // Check if dir exists
        if !host.file_exists(host.wrkdir.as_path()) {
            error!(
                "Failed to initialize localhost: {} doesn't exist",
                host.wrkdir.display()
            );
            return Err(HostError::new(
                HostErrorType::NoSuchFileOrDirectory,
                None,
                host.wrkdir.as_path(),
            ));
        }
        // Retrieve files for provided path
        host.files = match host.scan_dir(host.wrkdir.as_path()) {
            Ok(files) => files,
            Err(err) => {
                error!(
                    "Failed to initialize localhost: could not scan wrkdir: {}",
                    err
                );
                return Err(err);
            }
        };
        info!("Localhost initialized with success");
        Ok(host)
    }

    /// ### pwd
    ///
    /// Print working directory
    pub fn pwd(&self) -> PathBuf {
        self.wrkdir.clone()
    }

    /// ### list_dir
    ///
    /// List files in current directory
    #[allow(dead_code)]
    pub fn list_dir(&self) -> Vec<FsEntry> {
        self.files.clone()
    }

    /// ### change_wrkdir
    ///
    /// Change working directory with the new provided directory
    pub fn change_wrkdir(&mut self, new_dir: &Path) -> Result<PathBuf, HostError> {
        let new_dir: PathBuf = self.to_abs_path(new_dir);
        info!("Changing localhost directory to {}...", new_dir.display());
        // Check whether directory exists
        if !self.file_exists(new_dir.as_path()) {
            error!("Could not change directory: No such file or directory");
            return Err(HostError::new(
                HostErrorType::NoSuchFileOrDirectory,
                None,
                new_dir.as_path(),
            ));
        }
        // Change directory
        if let Err(err) = std::env::set_current_dir(new_dir.as_path()) {
            error!("Could not enter directory: {}", err);
            return Err(HostError::new(
                HostErrorType::NoSuchFileOrDirectory,
                Some(err),
                new_dir.as_path(),
            ));
        }
        let prev_dir: PathBuf = self.wrkdir.clone(); // Backup location
        // Update working directory
        // Change dir
        self.wrkdir = new_dir;
        // Scan new directory
        self.files = match self.scan_dir(self.wrkdir.as_path()) {
            Ok(files) => files,
            Err(err) => {
                error!("Could not scan new directory: {}", err);
                // Restore directory
                self.wrkdir = prev_dir;
                return Err(err);
            }
        };
        debug!("Changed directory to {}", self.wrkdir.display());
        Ok(self.wrkdir.clone())
    }

    /// ### mkdir
    ///
    /// Make a directory at path and update the file list (only if relative)
    pub fn mkdir(&mut self, dir_name: &Path) -> Result<(), HostError> {
        self.mkdir_ex(dir_name, false)
    }

    /// ### mkdir_ex
    ///
    /// Extended option version of makedir.
    /// ignex: don't report error if directory already exists
    pub fn mkdir_ex(&mut self, dir_name: &Path, ignex: bool) -> Result<(), HostError> {
        let dir_path: PathBuf = self.to_abs_path(dir_name);
        info!("Making directory {}", dir_path.display());
        // If dir already exists, return Error
        if dir_path.exists() {
            match ignex {
                true => return Ok(()),
                false => {
                    return Err(HostError::new(
                        HostErrorType::FileAlreadyExists,
                        None,
                        dir_path.as_path(),
                    ))
                }
            }
        }
        match std::fs::create_dir(dir_path.as_path()) {
            Ok(_) => {
                // Update dir
                if dir_name.is_relative() {
                    self.files = self.scan_dir(self.wrkdir.as_path())?;
                }
                info!("Created directory {}", dir_path.display());
                Ok(())
            }
            Err(err) => {
                error!("Could not make directory: {}", err);
                Err(HostError::new(
                    HostErrorType::CouldNotCreateFile,
                    Some(err),
                    dir_path.as_path(),
                ))
            }
        }
    }

    /// ### remove
    ///
    /// Remove file entry
    pub fn remove(&mut self, entry: &FsEntry) -> Result<(), HostError> {
        match entry {
            FsEntry::Directory(dir) => {
                // If file doesn't exist; return error
                debug!("Removing directory {}", dir.abs_path.display());
                if !dir.abs_path.as_path().exists() {
                    error!("Directory doesn't exist");
                    return Err(HostError::new(
                        HostErrorType::NoSuchFileOrDirectory,
                        None,
                        dir.abs_path.as_path(),
                    ));
                }
                // Remove
                match std::fs::remove_dir_all(dir.abs_path.as_path()) {
                    Ok(_) => {
                        // Update dir
                        self.files = self.scan_dir(self.wrkdir.as_path())?;
                        info!("Removed directory {}", dir.abs_path.display());
                        Ok(())
                    }
                    Err(err) => {
                        error!("Could not remove directory: {}", err);
                        Err(HostError::new(
                            HostErrorType::DeleteFailed,
                            Some(err),
                            dir.abs_path.as_path(),
                        ))
                    }
                }
            }
            FsEntry::File(file) => {
                // If file doesn't exist; return error
                debug!("Removing file {}", file.abs_path.display());
                if !file.abs_path.as_path().exists() {
                    error!("File doesn't exist");
                    return Err(HostError::new(
                        HostErrorType::NoSuchFileOrDirectory,
                        None,
                        file.abs_path.as_path(),
                    ));
                }
                // Remove
                match std::fs::remove_file(file.abs_path.as_path()) {
                    Ok(_) => {
                        // Update dir
                        self.files = self.scan_dir(self.wrkdir.as_path())?;
                        info!("Removed file {}", file.abs_path.display());
                        Ok(())
                    }
                    Err(err) => {
                        error!("Could not remove file: {}", err);
                        Err(HostError::new(
                            HostErrorType::DeleteFailed,
                            Some(err),
                            file.abs_path.as_path(),
                        ))
                    }
                }
            }
        }
    }

    /// ### rename
    ///
    /// Rename file or directory to new name
    pub fn rename(&mut self, entry: &FsEntry, dst_path: &Path) -> Result<(), HostError> {
        let abs_path: PathBuf = entry.get_abs_path();
        match std::fs::rename(abs_path.as_path(), dst_path) {
            Ok(_) => {
                // Scan dir
                self.files = self.scan_dir(self.wrkdir.as_path())?;
                debug!(
                    "Moved file {} to {}",
                    entry.get_abs_path().display(),
                    dst_path.display()
                );
                Ok(())
            }
            Err(err) => {
                error!(
                    "Failed to move {} to {}: {}",
                    entry.get_abs_path().display(),
                    dst_path.display(),
                    err
                );
                Err(HostError::new(
                    HostErrorType::CouldNotCreateFile,
                    Some(err),
                    abs_path.as_path(),
                ))
            }
        }
    }

    /// ### copy
    ///
    /// Copy file to destination path
    pub fn copy(&mut self, entry: &FsEntry, dst: &Path) -> Result<(), HostError> {
        // Get absolute path of dest
        let dst: PathBuf = self.to_abs_path(dst);
        info!(
            "Copying file {} to {}",
            entry.get_abs_path().display(),
            dst.display()
        );
        // Match entry
        match entry {
            FsEntry::File(file) => {
                // Copy file
                // If destination path is a directory, push file name
                let dst: PathBuf = match dst.as_path().is_dir() {
                    true => {
                        let mut p: PathBuf = dst.clone();
                        p.push(file.name.as_str());
                        p
                    }
                    false => dst.clone(),
                };
                // Copy entry path to dst path
                if let Err(err) = std::fs::copy(file.abs_path.as_path(), dst.as_path()) {
                    error!("Failed to copy file: {}", err);
                    return Err(HostError::new(
                        HostErrorType::CouldNotCreateFile,
                        Some(err),
                        file.abs_path.as_path(),
                    ));
                }
                info!("File copied");
            }
            FsEntry::Directory(dir) => {
                // If destination path doesn't exist, create destination
                if !dst.exists() {
                    debug!("Directory {} doesn't exist; creating it", dst.display());
                    self.mkdir(dst.as_path())?;
                }
                // Scan dir
                let dir_files: Vec<FsEntry> = self.scan_dir(dir.abs_path.as_path())?;
                // Iterate files
                for dir_entry in dir_files.iter() {
                    // Calculate dst
                    let mut sub_dst: PathBuf = dst.clone();
                    sub_dst.push(dir_entry.get_name());
                    // Call function recursively
                    self.copy(dir_entry, sub_dst.as_path())?;
                }
            }
        }
        // Reload directory if dst is pwd
        match dst.is_dir() {
            true => {
                if dst == self.pwd().as_path() {
                    self.files = self.scan_dir(self.wrkdir.as_path())?;
                } else if let Some(parent) = dst.parent() {
                    // If parent is pwd, scan directory
                    if parent == self.pwd().as_path() {
                        self.files = self.scan_dir(self.wrkdir.as_path())?;
                    }
                }
            }
            false => {
                if let Some(parent) = dst.parent() {
                    // If parent is pwd, scan directory
                    if parent == self.pwd().as_path() {
                        self.files = self.scan_dir(self.wrkdir.as_path())?;
                    }
                }
            }
        }
        Ok(())
    }

    /// ### stat
    ///
    /// Stat file and create a FsEntry
    #[cfg(target_family = "unix")]
    pub fn stat(&self, path: &Path) -> Result<FsEntry, HostError> {
        info!("Stating file {}", path.display());
        let path: PathBuf = self.to_abs_path(path);
        let attr: Metadata = match fs::metadata(path.as_path()) {
            Ok(metadata) => metadata,
            Err(err) => {
                error!("Could not read file metadata: {}", err);
                return Err(HostError::new(
                    HostErrorType::FileNotAccessible,
                    Some(err),
                    path.as_path(),
                ));
            }
        };
        let file_name: String = String::from(path.file_name().unwrap().to_str().unwrap_or(""));
        // Match dir / file
        Ok(match path.is_dir() {
            true => FsEntry::Directory(FsDirectory {
                name: file_name,
                abs_path: path.clone(),
                last_change_time: attr.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                last_access_time: attr.accessed().unwrap_or(SystemTime::UNIX_EPOCH),
                creation_time: attr.created().unwrap_or(SystemTime::UNIX_EPOCH),
                symlink: match fs::read_link(path.as_path()) {
                    Ok(p) => match self.stat(p.as_path()) {
                        Ok(entry) => Some(Box::new(entry)),
                        Err(_) => None,
                    },
                    Err(_) => None,
                },
                user: Some(attr.uid()),
                group: Some(attr.gid()),
                unix_pex: Some(self.u32_to_mode(attr.mode())),
            }),
            false => {
                // Is File
                let extension: Option<String> = path
                    .extension()
                    .map(|s| String::from(s.to_str().unwrap_or("")));
                FsEntry::File(FsFile {
                    name: file_name,
                    abs_path: path.clone(),
                    last_change_time: attr.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                    last_access_time: attr.accessed().unwrap_or(SystemTime::UNIX_EPOCH),
                    creation_time: attr.created().unwrap_or(SystemTime::UNIX_EPOCH),
                    size: attr.len() as usize,
                    ftype: extension,
                    symlink: match fs::read_link(path.as_path()) {
                        Ok(p) => match self.stat(p.as_path()) {
                            Ok(entry) => Some(Box::new(entry)),
                            Err(_) => None,
                        },
                        Err(_) => None, // Ignore errors
                    },
                    user: Some(attr.uid()),
                    group: Some(attr.gid()),
                    unix_pex: Some(self.u32_to_mode(attr.mode())),
                })
            }
        })
    }

    /// ### stat
    ///
    /// Stat file and create a FsEntry
    #[cfg(target_os = "windows")]
    pub fn stat(&self, path: &Path) -> Result<FsEntry, HostError> {
        let path: PathBuf = self.to_abs_path(path);
        info!("Stating file {}", path.display());
        let attr: Metadata = match fs::metadata(path.as_path()) {
            Ok(metadata) => metadata,
            Err(err) => {
                error!("Could not read file metadata: {}", err);
                return Err(HostError::new(
                    HostErrorType::FileNotAccessible,
                    Some(err),
                    path.as_path(),
                ));
            }
        };
        let file_name: String = String::from(path.file_name().unwrap().to_str().unwrap_or(""));
        // Match dir / file
        Ok(match path.is_dir() {
            true => FsEntry::Directory(FsDirectory {
                name: file_name,
                abs_path: path.clone(),
                last_change_time: attr.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                last_access_time: attr.accessed().unwrap_or(SystemTime::UNIX_EPOCH),
                creation_time: attr.created().unwrap_or(SystemTime::UNIX_EPOCH),
                symlink: match fs::read_link(path.as_path()) {
                    Ok(p) => match self.stat(p.as_path()) {
                        Ok(entry) => Some(Box::new(entry)),
                        Err(_) => None, // Ignore errors
                    },
                    Err(_) => None,
                },
                user: None,
                group: None,
                unix_pex: None,
            }),
            false => {
                // Is File
                let extension: Option<String> = match path.extension() {
                    Some(s) => Some(String::from(s.to_str().unwrap_or(""))),
                    None => None,
                };
                FsEntry::File(FsFile {
                    name: file_name,
                    abs_path: path.clone(),
                    last_change_time: attr.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                    last_access_time: attr.accessed().unwrap_or(SystemTime::UNIX_EPOCH),
                    creation_time: attr.created().unwrap_or(SystemTime::UNIX_EPOCH),
                    size: attr.len() as usize,
                    ftype: extension,
                    symlink: match fs::read_link(path.as_path()) {
                        Ok(p) => match self.stat(p.as_path()) {
                            Ok(entry) => Some(Box::new(entry)),
                            Err(_) => None,
                        },
                        Err(_) => None,
                    },
                    user: None,
                    group: None,
                    unix_pex: None,
                })
            }
        })
    }

    /// ### exec
    ///
    /// Execute a command on localhost
    pub fn exec(&self, cmd: &str) -> Result<String, HostError> {
        // Make command
        let args: Vec<&str> = cmd.split(' ').collect();
        let cmd: &str = args.first().unwrap();
        let argv: &[&str] = &args[1..];
        info!("Executing command: {} {:?}", cmd, argv);
        match std::process::Command::new(cmd).args(argv).output() {
            Ok(output) => match std::str::from_utf8(&output.stdout) {
                Ok(s) => {
                    info!("Command output: {}", s);
                    Ok(s.to_string())
                }
                Err(_) => Ok(String::new()),
            },
            Err(err) => {
                error!("Failed to run command: {}", err);
                Err(HostError::new(
                    HostErrorType::ExecutionFailed,
                    Some(err),
                    self.wrkdir.as_path(),
                ))
            }
        }
    }

    /// ### chmod
    ///
    /// Change file mode to file, according to UNIX permissions
    #[cfg(target_family = "unix")]
    pub fn chmod(&self, path: &Path, pex: (u8, u8, u8)) -> Result<(), HostError> {
        let path: PathBuf = self.to_abs_path(path);
        // Get metadta
        match fs::metadata(path.as_path()) {
            Ok(metadata) => {
                let mut mpex = metadata.permissions();
                mpex.set_mode(self.mode_to_u32(pex));
                match set_permissions(path.as_path(), mpex) {
                    Ok(_) => {
                        info!("Changed mode for {} to {:?}", path.display(), pex);
                        Ok(())
                    }
                    Err(err) => {
                        error!("Could not change mode for file {}: {}", path.display(), err);
                        Err(HostError::new(
                            HostErrorType::FileNotAccessible,
                            Some(err),
                            path.as_path(),
                        ))
                    }
                }
            }
            Err(err) => {
                error!(
                    "Chmod failed; could not read metadata for file {}: {}",
                    path.display(),
                    err
                );
                Err(HostError::new(
                    HostErrorType::FileNotAccessible,
                    Some(err),
                    path.as_path(),
                ))
            }
        }
    }

    /// ### open_file_read
    ///
    /// Open file for read
    pub fn open_file_read(&self, file: &Path) -> Result<File, HostError> {
        let file: PathBuf = self.to_abs_path(file);
        info!("Opening file {} for read", file.display());
        if !self.file_exists(file.as_path()) {
            error!("File doesn't exist!");
            return Err(HostError::new(
                HostErrorType::NoSuchFileOrDirectory,
                None,
                file.as_path(),
            ));
        }
        match OpenOptions::new()
            .create(false)
            .read(true)
            .write(false)
            .open(file.as_path())
        {
            Ok(f) => Ok(f),
            Err(err) => {
                error!("Could not open file for read: {}", err);
                Err(HostError::new(
                    HostErrorType::FileNotAccessible,
                    Some(err),
                    file.as_path(),
                ))
            }
        }
    }

    /// ### open_file_write
    ///
    /// Open file for write
    pub fn open_file_write(&self, file: &Path) -> Result<File, HostError> {
        let file: PathBuf = self.to_abs_path(file);
        info!("Opening file {} for write", file.display());
        match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(file.as_path())
        {
            Ok(f) => Ok(f),
            Err(err) => {
                error!("Failed to open file: {}", err);
                match self.file_exists(file.as_path()) {
                    true => Err(HostError::new(
                        HostErrorType::ReadonlyFile,
                        Some(err),
                        file.as_path(),
                    )),
                    false => Err(HostError::new(
                        HostErrorType::FileNotAccessible,
                        Some(err),
                        file.as_path(),
                    )),
                }
            }
        }
    }

    /// ### file_exists
    ///
    /// Returns whether provided file path exists
    pub fn file_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    /// ### scan_dir
    ///
    /// Get content of the current directory as a list of fs entry
    pub fn scan_dir(&self, dir: &Path) -> Result<Vec<FsEntry>, HostError> {
        info!("Reading directory {}", dir.display());
        match std::fs::read_dir(dir) {
            Ok(e) => {
                let mut fs_entries: Vec<FsEntry> = Vec::new();
                for entry in e.flatten() {
                    // NOTE: 0.4.1, don't fail if stat for one file fails
                    match self.stat(entry.path().as_path()) {
                        Ok(entry) => fs_entries.push(entry),
                        Err(e) => error!("Failed to stat {}: {}", entry.path().display(), e),
                    }
                }
                Ok(fs_entries)
            }
            Err(err) => Err(HostError::new(
                HostErrorType::DirNotAccessible,
                Some(err),
                dir,
            )),
        }
    }

    /// ### find
    ///
    /// Find files matching `search` on localhost starting from current directory. Search supports recursive search of course.
    /// The `search` argument supports wilcards ('*', '?')
    pub fn find(&self, search: &str) -> Result<Vec<FsEntry>, HostError> {
        self.iter_search(self.wrkdir.as_path(), &WildMatch::new(search))
    }

    // -- privates

    /// ### iter_search
    ///
    /// Recursive call for `find` method.
    /// Search in current directory for files which match `filter`.
    /// If a directory is found in current directory, `iter_search` will be called using that dir as argument.
    fn iter_search(&self, dir: &Path, filter: &WildMatch) -> Result<Vec<FsEntry>, HostError> {
        // Scan directory
        let mut drained: Vec<FsEntry> = Vec::new();
        match self.scan_dir(dir) {
            Err(err) => Err(err),
            Ok(entries) => {
                // Iter entries
                /* For each entry:
                - if is dir: call iter_search with `dir`
                    - push `iter_search` result to `drained`
                - if is file: check if it matches `filter`
                    - if it matches `filter`: push to to filter
                */
                for entry in entries.iter() {
                    match entry {
                        FsEntry::Directory(dir) => {
                            // If directory matches; push directory to drained
                            if filter.matches(dir.name.as_str()) {
                                drained.push(FsEntry::Directory(dir.clone()));
                            }
                            drained.append(&mut self.iter_search(dir.abs_path.as_path(), filter)?);
                        }
                        FsEntry::File(file) => {
                            if filter.matches(file.name.as_str()) {
                                drained.push(FsEntry::File(file.clone()));
                            }
                        }
                    }
                }
                Ok(drained)
            }
        }
    }

    /// ### u32_to_mode
    ///
    /// Return string with format xxxxxx to tuple of permissions (user, group, others)
    #[cfg(target_family = "unix")]
    fn u32_to_mode(&self, mode: u32) -> (UnixPex, UnixPex, UnixPex) {
        let user: UnixPex = UnixPex::from(((mode >> 6) & 0x7) as u8);
        let group: UnixPex = UnixPex::from(((mode >> 3) & 0x7) as u8);
        let others: UnixPex = UnixPex::from((mode & 0x7) as u8);
        (user, group, others)
    }

    /// mode_to_u32
    ///
    /// Convert owner,group,others to u32
    #[cfg(target_family = "unix")]
    fn mode_to_u32(&self, mode: (u8, u8, u8)) -> u32 {
        ((mode.0 as u32) << 6) + ((mode.1 as u32) << 3) + mode.2 as u32
    }

    /// ### to_abs_path
    ///
    /// Convert path to absolute path
    fn to_abs_path(&self, p: &Path) -> PathBuf {
        path::absolutize(self.wrkdir.as_path(), p)
    }
}