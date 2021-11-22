// Ext
use std::path::PathBuf;
use std::time::SystemTime;

/// ## FsEntry
///
/// FsEntry represents a generic entry in a directory

#[derive(Clone, std::fmt::Debug)]
pub enum FsEntry {
    Directory(FsDirectory),
    File(FsFile),
}

/// ## FsDirectory
///
/// Directory provides an interface to file system directories

#[derive(Clone, std::fmt::Debug)]
pub struct FsDirectory {
    pub name: String,
    pub abs_path: PathBuf,
    pub last_change_time: SystemTime,
    pub last_access_time: SystemTime,
    pub creation_time: SystemTime,
    pub symlink: Option<Box<FsEntry>>,                 // UNIX only
    pub user: Option<u32>,                             // UNIX only
    pub group: Option<u32>,                            // UNIX only
    pub unix_pex: Option<(UnixPex, UnixPex, UnixPex)>, // UNIX only
}

/// ### FsFile
///
/// FsFile provides an interface to file system files

#[derive(Clone, std::fmt::Debug)]
pub struct FsFile {
    pub name: String,
    pub abs_path: PathBuf,
    pub last_change_time: SystemTime,
    pub last_access_time: SystemTime,
    pub creation_time: SystemTime,
    pub size: usize,
    pub ftype: Option<String>,                         // File type
    pub symlink: Option<Box<FsEntry>>,                 // UNIX only
    pub user: Option<u32>,                             // UNIX only
    pub group: Option<u32>,                            // UNIX only
    pub unix_pex: Option<(UnixPex, UnixPex, UnixPex)>, // UNIX only
}

/// ## UnixPex
///
/// Describes the permissions on POSIX system.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UnixPex {
    read: bool,
    write: bool,
    execute: bool,
}

impl UnixPex {
    /// ### new
    ///
    /// Instantiates a new `UnixPex`
    pub fn new(read: bool, write: bool, execute: bool) -> Self {
        Self {
            read,
            write,
            execute,
        }
    }

    /// ### can_read
    ///
    /// Returns whether user can read
    pub fn can_read(&self) -> bool {
        self.read
    }

    /// ### can_write
    ///
    /// Returns whether user can write
    pub fn can_write(&self) -> bool {
        self.write
    }

    /// ### can_execute
    ///
    /// Returns whether user can execute
    pub fn can_execute(&self) -> bool {
        self.execute
    }

    /// ### as_byte
    ///
    /// Convert permission to byte as on POSIX systems
    pub fn as_byte(&self) -> u8 {
        ((self.read as u8) << 2) + ((self.write as u8) << 1) + (self.execute as u8)
    }
}

impl From<u8> for UnixPex {
    fn from(bits: u8) -> Self {
        Self {
            read: ((bits >> 2) & 0x01) != 0,
            write: ((bits >> 1) & 0x01) != 0,
            execute: (bits & 0x01) != 0,
        }
    }
}

impl FsEntry {
    /// ### get_abs_path
    ///
    /// Get absolute path from `FsEntry`
    pub fn get_abs_path(&self) -> PathBuf {
        match self {
            FsEntry::Directory(dir) => dir.abs_path.clone(),
            FsEntry::File(file) => file.abs_path.clone(),
        }
    }

    /// ### get_name
    ///
    /// Get file name from `FsEntry`
    pub fn get_name(&self) -> &'_ str {
        match self {
            FsEntry::Directory(dir) => dir.name.as_ref(),
            FsEntry::File(file) => file.name.as_ref(),
        }
    }

    /// ### get_last_change_time
    ///
    /// Get last change time from `FsEntry`
    pub fn get_last_change_time(&self) -> SystemTime {
        match self {
            FsEntry::Directory(dir) => dir.last_change_time,
            FsEntry::File(file) => file.last_change_time,
        }
    }

    /// ### get_last_access_time
    ///
    /// Get access time from `FsEntry`
    pub fn get_last_access_time(&self) -> SystemTime {
        match self {
            FsEntry::Directory(dir) => dir.last_access_time,
            FsEntry::File(file) => file.last_access_time,
        }
    }

    /// ### get_creation_time
    ///
    /// Get creation time from `FsEntry`
    pub fn get_creation_time(&self) -> SystemTime {
        match self {
            FsEntry::Directory(dir) => dir.creation_time,
            FsEntry::File(file) => file.creation_time,
        }
    }

    /// ### get_size
    ///
    /// Get size from `FsEntry`. For directories is always 4096
    pub fn get_size(&self) -> usize {
        match self {
            FsEntry::Directory(_) => 4096,
            FsEntry::File(file) => file.size,
        }
    }

    /// ### get_ftype
    ///
    /// Get file type from `FsEntry`. For directories is always None
    pub fn get_ftype(&self) -> Option<String> {
        match self {
            FsEntry::Directory(_) => None,
            FsEntry::File(file) => file.ftype.clone(),
        }
    }

    /// ### get_user
    ///
    /// Get uid from `FsEntry`
    pub fn get_user(&self) -> Option<u32> {
        match self {
            FsEntry::Directory(dir) => dir.user,
            FsEntry::File(file) => file.user,
        }
    }

    /// ### get_group
    ///
    /// Get gid from `FsEntry`
    pub fn get_group(&self) -> Option<u32> {
        match self {
            FsEntry::Directory(dir) => dir.group,
            FsEntry::File(file) => file.group,
        }
    }

    /// ### get_unix_pex
    ///
    /// Get unix pex from `FsEntry`
    pub fn get_unix_pex(&self) -> Option<(UnixPex, UnixPex, UnixPex)> {
        match self {
            FsEntry::Directory(dir) => dir.unix_pex,
            FsEntry::File(file) => file.unix_pex,
        }
    }

    /// ### is_symlink
    ///
    /// Returns whether the `FsEntry` is a symlink
    pub fn is_symlink(&self) -> bool {
        match self {
            FsEntry::Directory(dir) => dir.symlink.is_some(),
            FsEntry::File(file) => file.symlink.is_some(),
        }
    }

    /// ### is_dir
    ///
    /// Returns whether a FsEntry is a directory
    pub fn is_dir(&self) -> bool {
        matches!(self, FsEntry::Directory(_))
    }

    /// ### is_file
    ///
    /// Returns whether a FsEntry is a File
    pub fn is_file(&self) -> bool {
        matches!(self, FsEntry::File(_))
    }

    /// ### is_hidden
    ///
    /// Returns whether FsEntry is hidden
    pub fn is_hidden(&self) -> bool {
        self.get_name().starts_with('.')
    }

    /// ### get_realfile
    ///
    /// Return the real file pointed by a `FsEntry`
    pub fn get_realfile(&self) -> FsEntry {
        match self {
            FsEntry::Directory(dir) => match &dir.symlink {
                Some(symlink) => symlink.get_realfile(),
                None => self.clone(),
            },
            FsEntry::File(file) => match &file.symlink {
                Some(symlink) => symlink.get_realfile(),
                None => self.clone(),
            },
        }
    }

    /// ### unwrap_file
    ///
    /// Unwrap FsEntry as FsFile
    pub fn unwrap_file(self) -> FsFile {
        match self {
            FsEntry::File(file) => file,
            _ => panic!("unwrap_file: not a file"),
        }
    }

    #[cfg(test)]
    /// ### unwrap_dir
    ///
    /// Unwrap FsEntry as FsDirectory
    pub fn unwrap_dir(self) -> FsDirectory {
        match self {
            FsEntry::Directory(dir) => dir,
            _ => panic!("unwrap_dir: not a directory"),
        }
    }
}
