use std::fmt::Formatter;
// locals
use crate::fs::{FsEntry, FsFile};
// ext
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use wildmatch::WildMatch;

// exports
pub mod params;
mod transfer;

// -- export types
pub use params::{FileTransferParams, ProtocolParams};
pub use transfer::{ScpFileTransfer /*, FtpFileTransfer, S3FileTransfer, , SftpFileTransfer*/};

/// ## FileTransferProtocol
///
/// This enum defines the different transfer protocol available
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum FileTransferProtocol {
    Sftp,
    Scp,
    Ftp(bool),
    // Bool is for secure (true => ftps)
    AwsS3,
}

/// ## FileTransferError
///
/// FileTransferError defines the possible errors available for a file transfer
#[derive(Debug)]
pub struct FileTransferError {
    code: FileTransferErrorType,
    msg: Option<String>,
}

/// ## FileTransferErrorType
///
/// FileTransferErrorType defines the possible errors available for a file transfer
#[derive(Error, Debug, Clone, Copy, PartialEq)]
pub enum FileTransferErrorType {
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("Bad address syntax")]
    BadAddress,
    #[error("Connection error")]
    ConnectionError,
    #[error("SSL error")]
    SslError,
    #[error("Could not stat directory")]
    DirStatFailed,
    #[error("Directory already exists")]
    DirectoryAlreadyExists,
    #[error("Failed to create file")]
    FileCreateDenied,
    #[error("No such file or directory")]
    NoSuchFileOrDirectory,
    #[error("Not enough permissions")]
    PexError,
    #[error("Protocol error")]
    ProtocolError,
    #[error("Uninitialized session")]
    UninitializedSession,
    #[error("Unsupported feature")]
    UnsupportedFeature,
}

/*impl std::fmt::Display for FileTransferErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        //write!(f, "{:?}", self)
        write!(f, "{:?}", match self {
            FileTransferErrorType::AuthenticationFailed => "Authentication failed",
            FileTransferErrorType::BadAddress => "Bad address syntax",
            FileTransferErrorType::ConnectionError => "Connection error",
            FileTransferErrorType::SslError => "SSL error",
            FileTransferErrorType::DirStatFailed => "Directory already exists",
            FileTransferErrorType::DirectoryAlreadyExists => "Directory already exists",
            FileTransferErrorType::FileCreateDenied => "Failed to create file",
            FileTransferErrorType::NoSuchFileOrDirectory => "No such file or directory",
            FileTransferErrorType::PexError => "Not enough permissions",
            FileTransferErrorType::ProtocolError => "Protocol error",
            FileTransferErrorType::UninitializedSession => "Uninitialized session",
            FileTransferErrorType::UnsupportedFeature => "Unsupported feature",
        })
    }
}*/

impl FileTransferError {
    /// ### new
    ///
    /// Instantiates a new FileTransferError
    pub fn new(code: FileTransferErrorType) -> FileTransferError {
        FileTransferError { code, msg: None }
    }

    /// ### new_ex
    ///
    /// Instantiates a new FileTransferError with message
    pub fn new_ex(code: FileTransferErrorType, msg: String) -> FileTransferError {
        let mut err: FileTransferError = FileTransferError::new(code);
        err.msg = Some(msg);
        err
    }

    /// ### kind
    ///
    /// Returns the error kind
    pub fn kind(&self) -> FileTransferErrorType {
        self.code
    }
}

impl std::fmt::Display for FileTransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.msg {
            Some(msg) => write!(f, "{} ({})", self.code, msg),
            None => write!(f, "{}", self.code),
        }
    }
}

/// ## FileTransferResult
///
/// Result type returned by a `FileTransfer` implementation
pub type FileTransferResult<T> = Result<T, FileTransferError>;

/// ## FileTransfer
///
/// File transfer trait must be implemented by all the file transfers and defines the method used by a generic file transfer
pub trait FileTransfer {
    /// ### connect
    ///
    /// Connect to the remote server
    /// Can return banner / welcome message on success
    fn connect(&mut self, params: &ProtocolParams) -> FileTransferResult<Option<String>>;

    /// ### disconnect
    ///
    /// Disconnect from the remote server
    fn disconnect(&mut self) -> FileTransferResult<()>;

    fn try_disconnect(&mut self) -> bool;

    /// ### is_connected
    ///
    /// Indicates whether the client is connected to remote
    fn is_connected(&self) -> bool;

    /// ### pwd
    ///
    /// Print working directory
    fn pwd(&mut self) -> FileTransferResult<PathBuf>;

    /// ### change_dir
    ///
    /// Change working directory
    fn change_dir(&mut self, dir: &Path) -> FileTransferResult<PathBuf>;

    /// ### copy
    ///
    /// Copy file to destination
    fn copy(&mut self, src: &FsEntry, dst: &Path) -> FileTransferResult<()>;

    /// ### list_dir
    ///
    /// List directory entries
    fn list_dir(&mut self, path: &Path) -> FileTransferResult<Vec<FsEntry>>;

    /// ### mkdir
    ///
    /// Make directory
    /// In case the directory already exists, it must return an Error of kind `FileTransferErrorType::DirectoryAlreadyExists`
    fn mkdir(&mut self, dir: &Path) -> FileTransferResult<()>;

    /// ### remove
    ///
    /// Remove a file or a directory
    fn remove(&mut self, file: &FsEntry) -> FileTransferResult<()>;

    /// ### rename
    ///
    /// Rename file or a directory
    fn rename(&mut self, file: &FsEntry, dst: &Path) -> FileTransferResult<()>;

    /// ### stat
    ///
    /// Stat file and return FsEntry
    fn stat(&mut self, path: &Path) -> FileTransferResult<FsEntry>;

    /// ### exec
    ///
    /// Execute a command on remote host
    fn exec(&mut self, cmd: &str) -> FileTransferResult<String>;

    /// ### send_file
    ///
    /// Send file to remote
    /// File name is referred to the name of the file as it will be saved
    /// Data contains the file data
    /// Returns file and its size.
    /// By default returns unsupported feature
    fn send_file(
        &mut self,
        _local: &FsFile,
        _file_name: &Path,
    ) -> FileTransferResult<Box<dyn Write>> {
        Err(FileTransferError::new(
            FileTransferErrorType::UnsupportedFeature,
        ))
    }

    /// ### recv_file
    ///
    /// Receive file from remote with provided name
    /// Returns file and its size
    /// By default returns unsupported feature
    fn recv_file(&mut self, _file: &FsFile) -> FileTransferResult<Box<dyn Read>> {
        Err(FileTransferError::new(
            FileTransferErrorType::UnsupportedFeature,
        ))
    }

    /// ### on_sent
    ///
    /// Finalize send method.
    /// This method must be implemented only if necessary; in case you don't need it, just return `Ok(())`
    /// The purpose of this method is to finalize the connection with the peer when writing data.
    /// This is necessary for some protocols such as FTP.
    /// You must call this method each time you want to finalize the write of the remote file.
    /// By default this function returns already `Ok(())`
    fn on_sent(&mut self, _writable: Box<dyn Write>) -> FileTransferResult<()> {
        Ok(())
    }

    /// ### on_recv
    ///
    /// Finalize recv method.
    /// This method must be implemented only if necessary; in case you don't need it, just return `Ok(())`
    /// The purpose of this method is to finalize the connection with the peer when reading data.
    /// This mighe be necessary for some protocols.
    /// You must call this method each time you want to finalize the read of the remote file.
    /// By default this function returns already `Ok(())`
    fn on_recv(&mut self, _readable: Box<dyn Read>) -> FileTransferResult<()> {
        Ok(())
    }

    /// ### send_file_wno_stream
    ///
    /// Send a file to remote WITHOUT using streams.
    /// This method SHOULD be implemented ONLY when streams are not supported by the current file transfer.
    /// The developer implementing the filetransfer user should FIRST try with `send_file` followed by `on_sent`
    /// If the function returns error kind() `UnsupportedFeature`, then he should call this function.
    /// By default this function uses the streams function to copy content from reader to writer
    fn send_file_wno_stream(
        &mut self,
        src: &FsFile,
        dest: &Path,
        mut reader: Box<dyn Read>,
    ) -> FileTransferResult<()> {
        match self.is_connected() {
            true => {
                let mut stream = self.send_file(src, dest)?;
                io::copy(&mut reader, &mut stream).map_err(|e| {
                    FileTransferError::new_ex(FileTransferErrorType::ProtocolError, e.to_string())
                })?;
                self.on_sent(stream)
            }
            false => Err(FileTransferError::new(
                FileTransferErrorType::UninitializedSession,
            )),
        }
    }

    /// ### recv_file_wno_stream
    ///
    /// Receive a file from remote WITHOUT using streams.
    /// This method SHOULD be implemented ONLY when streams are not supported by the current file transfer.
    /// The developer implementing the filetransfer user should FIRST try with `send_file` followed by `on_sent`
    /// If the function returns error kind() `UnsupportedFeature`, then he should call this function.
    /// For safety reasons this function doesn't accept the `Write` trait, but the destination path.
    /// By default this function uses the streams function to copy content from reader to writer
    fn recv_file_wno_stream(&mut self, src: &FsFile, dest: &Path) -> FileTransferResult<()> {
        match self.is_connected() {
            true => {
                let mut writer = File::create(dest).map_err(|e| {
                    FileTransferError::new_ex(
                        FileTransferErrorType::FileCreateDenied,
                        format!("Could not open local file: {}", e),
                    )
                })?;
                let mut stream = self.recv_file(src)?;
                io::copy(&mut stream, &mut writer)
                    .map(|_| ())
                    .map_err(|e| {
                        FileTransferError::new_ex(
                            FileTransferErrorType::ProtocolError,
                            e.to_string(),
                        )
                    })?;
                self.on_recv(stream)
            }
            false => Err(FileTransferError::new(
                FileTransferErrorType::UninitializedSession,
            )),
        }
    }

    /// ### find
    ///
    /// Find files from current directory (in all subdirectories) whose name matches the provided search
    /// Search supports wildcards ('?', '*')
    fn find(&mut self, search: &str) -> FileTransferResult<Vec<FsEntry>> {
        match self.is_connected() {
            true => {
                // Starting from current directory, iter dir
                match self.pwd() {
                    Ok(p) => self.iter_search(p.as_path(), &WildMatch::new(search)),
                    Err(err) => Err(err),
                }
            }
            false => Err(FileTransferError::new(
                FileTransferErrorType::UninitializedSession,
            )),
        }
    }

    /// ### iter_search
    ///
    /// Search recursively in `dir` for file matching the wildcard.
    /// NOTE: DON'T RE-IMPLEMENT THIS FUNCTION, unless the file transfer provides a faster way to do so
    /// NOTE: don't call this method from outside; consider it as private
    fn iter_search(&mut self, dir: &Path, filter: &WildMatch) -> FileTransferResult<Vec<FsEntry>> {
        let mut drained: Vec<FsEntry> = Vec::new();
        // Scan directory
        match self.list_dir(dir) {
            Ok(entries) => {
                /* For each entry:
                - if is dir: call iter_search with `dir`
                    - push `iter_search` result to `drained`
                - if is file: check if it matches `filter`
                    - if it matches `filter`: push to to filter
                */
                for entry in entries.iter() {
                    match entry {
                        FsEntry::Directory(dir) => {
                            // If directory name, matches wildcard, push it to drained
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
            Err(err) => Err(err),
        }
    }
}

// Traits

impl std::string::ToString for FileTransferProtocol {
    fn to_string(&self) -> String {
        String::from(match self {
            FileTransferProtocol::Ftp(secure) => match secure {
                true => "FTPS",
                false => "FTP",
            },
            FileTransferProtocol::Scp => "SCP",
            FileTransferProtocol::Sftp => "SFTP",
            FileTransferProtocol::AwsS3 => "S3",
        })
    }
}

impl std::str::FromStr for FileTransferProtocol {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "FTP" => Ok(FileTransferProtocol::Ftp(false)),
            "FTPS" => Ok(FileTransferProtocol::Ftp(true)),
            "SCP" => Ok(FileTransferProtocol::Scp),
            "SFTP" => Ok(FileTransferProtocol::Sftp),
            "S3" => Ok(FileTransferProtocol::AwsS3),
            _ => Err(s.to_string()),
        }
    }
}

