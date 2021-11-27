// Locals

use crate::filetransfer::{FileTransferError, FileTransferErrorType};
use crate::fs::{FsEntry, FsFile};
use crate::host::HostError;
use crate::utils::fmt::fmt_millis;

// Ext
use bytesize::ByteSize;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use thiserror::Error;


use crate::{FileTransfer, FileTransferProtocol, FileTransferResult, FsDirectory, Localhost, ProtocolParams, ScpFileTransfer};
use crate::activities::transfer::TransferStates;


/// ## LogLevel
///
/// Log level type
pub enum LogLevel {
    Error,
    Warn,
    Info,
}

/// ## TransferErrorReason
///
/// Describes the reason that caused an error during a file transfer
#[derive(Error, Debug)]
pub enum TransferErrorReason {
    #[error("File transfer aborted")]
    Abrupted,
    #[error("Failed to seek file: {0}")]
    CouldNotRewind(std::io::Error),
    #[error("I/O error on localhost: {0}")]
    LocalIoError(std::io::Error),
    #[error("Host error: {0}")]
    HostError(HostError),
    #[error("I/O error on remote: {0}")]
    RemoteIoError(std::io::Error),
    #[error("File transfer error: {0}")]
    FileTransferError(FileTransferError),
}

/// ## TransferPayload
///
/// Represents the entity to send or receive during a transfer.
/// - File: describes an individual `FsFile` to send
/// - Any: Can be any kind of `FsEntry`, but just one
/// - Many: a list of `FsEntry`
#[derive(Debug)]
pub enum TransferPayload {
    File(FsFile),
    Any(FsEntry),
    Many(Vec<FsEntry>),
}

/// ## FileTransferActivity
///
/// FileTransferActivity is the data holder for the file transfer activity
pub struct FileTransferActivity {
    host: Localhost,
    client: Box<dyn FileTransfer>,
    // File transfer client: SCP | SFTP | FTP
    transfer: TransferStates,
    protocol_params: ProtocolParams,
}

impl FileTransferActivity {
    /// ### new
    ///
    /// Instantiates a new FileTransferActivity
    pub fn new(host: Localhost, protocol: FileTransferProtocol, protocol_params: ProtocolParams) -> FileTransferActivity {
        FileTransferActivity {
            host,
            client: match protocol {
                //FileTransferProtocol::Sftp => Box::new(SftpFileTransfer::new( )),
                // FileTransferProtocol::Ftp(ftps) => Box::new(FtpFileTransfer::new(ftps)),
                FileTransferProtocol::Scp => {
                    Box::new(ScpFileTransfer::new())
                }
                //FileTransferProtocol::AwsS3 => Box::new(S3FileTransfer::default()),
            },
            transfer: TransferStates::default(),
            protocol_params,
        }
    }

    /// ### connect
    ///
    /// Connect to remote
    pub fn connect(&mut self) {
        let config = self.protocol_params.clone();
        // Connect to remote
        match self.client.connect(&config) {
            Ok(welcome) => {
                if let Some(banner) = welcome {
                    // Log welcome

                    self.log(
                        LogLevel::Info,
                        format!(
                            "Established connection with '{}': \"{}\"",
                            self.get_remote_hostname(),
                            banner
                        ),
                    );
                }
            }
            Err(err) => {
                // Set popup fatal error
            }
        }
    }

    /// ### disconnect
    ///
    /// disconnect from remote
    pub fn disconnect(&mut self) {
        let _ = self.client.disconnect();
    }

    /************************ SEND *************************/

    /// ### filetransfer_send
    ///
    /// Send fs entry to remote.
    /// If dst_name is Some, entry will be saved with a different name.
    /// If entry is a directory, this applies to directory only
    pub fn filetransfer_send(
        &mut self,
        payload: TransferPayload,
        curr_remote_path: &Path,
        dst_name: Option<String>,
    ) -> Result<(), String> {
        // Use different method based on payload
        let result = match payload {
            TransferPayload::Any(ref entry) => {
                self.filetransfer_send_any(entry, curr_remote_path, dst_name)
            }
            TransferPayload::File(ref file) => {
                self.filetransfer_send_file(file, curr_remote_path, dst_name)
            }
            TransferPayload::Many(ref entries) => {
                self.filetransfer_send_many(entries, curr_remote_path)
            }
        };
        // Notify
        match &result {
            Ok(_) => {
                self.notify_transfer_completed(&payload);
            }
            Err(e) => {
                self.notify_transfer_error(e.as_str());
            }
        }
        result
    }

    /// ### filetransfer_send_file
    ///
    /// Send one file to remote at specified path.
    fn filetransfer_send_file(
        &mut self,
        file: &FsFile,
        curr_remote_path: &Path,
        dst_name: Option<String>,
    ) -> Result<(), String> {
        // Reset states
        self.transfer.reset();
        // Calculate total size of transfer
        let total_transfer_size: usize = file.size;
        self.transfer.full.init(total_transfer_size);
        // Mount progress bar

        // Get remote path
        let file_name: String = file.name.clone();
        let mut remote_path: PathBuf = PathBuf::from(curr_remote_path);
        let remote_file_name: PathBuf = match dst_name {
            Some(s) => PathBuf::from(s.as_str()),
            None => PathBuf::from(file_name.as_str()),
        };
        remote_path.push(remote_file_name);
        // Send
        let result = self.filetransfer_send_one(file, remote_path.as_path(), file_name);
        // Umount progress bar

        // Return result
        result.map_err(|x| x.to_string())
    }

    /// ### filetransfer_send_any
    ///
    /// Send a `TransferPayload` of type `Any`
    fn filetransfer_send_any(
        &mut self,
        entry: &FsEntry,
        curr_remote_path: &Path,
        dst_name: Option<String>,
    ) -> Result<(), String> {
        // Reset states
        self.transfer.reset();
        // Calculate total size of transfer
        let total_transfer_size: usize = self.get_total_transfer_size_local(entry);
        self.transfer.full.init(total_transfer_size);
        // Mount progress bar

        // Send recurse
        let result = self.filetransfer_send_recurse(entry, curr_remote_path, dst_name);
        // Umount progress bar

        result
    }

    /// ### filetransfer_send_many
    ///
    /// Send many entries to remote
    fn filetransfer_send_many(
        &mut self,
        entries: &[FsEntry],
        curr_remote_path: &Path,
    ) -> Result<(), String> {
        // Reset states
        self.transfer.reset();
        // Calculate total size of transfer
        let total_transfer_size: usize = entries
            .iter()
            .map(|x| self.get_total_transfer_size_local(x))
            .sum();
        self.transfer.full.init(total_transfer_size);
        // Mount progress bar

        // Send recurse
        let result = entries
            .iter()
            .map(|x| self.filetransfer_send_recurse(x, curr_remote_path, None))
            .find(|x| x.is_err())
            .unwrap_or(Ok(()));
        // Umount progress bar

        result
    }

    fn filetransfer_send_recurse(
        &mut self,
        entry: &FsEntry,
        curr_remote_path: &Path,
        dst_name: Option<String>,
    ) -> Result<(), String> {
        // Write popup
        let file_name: String = match entry {
            FsEntry::Directory(dir) => dir.name.clone(),
            FsEntry::File(file) => file.name.clone(),
        };
        // Get remote path
        let mut remote_path: PathBuf = PathBuf::from(curr_remote_path);
        let remote_file_name: PathBuf = match dst_name {
            Some(s) => PathBuf::from(s.as_str()),
            None => PathBuf::from(file_name.as_str()),
        };
        remote_path.push(remote_file_name);
        // Match entry
        let result: Result<(), String> = match entry {
            FsEntry::File(file) => {
                match self.filetransfer_send_one(file, remote_path.as_path(), file_name) {
                    Err(err) => {
                        // If transfer was abrupted or there was an IO error on remote, remove file
                        if matches!(
                            err,
                            TransferErrorReason::Abrupted | TransferErrorReason::RemoteIoError(_)
                        ) {
                            // Stat file on remote and remove it if exists
                            match self.client.stat(remote_path.as_path()) {
                                Err(err) => self.log(
                                    LogLevel::Error,
                                    format!(
                                        "Could not remove created file {}: {}",
                                        remote_path.display(),
                                        err
                                    ),
                                ),
                                Ok(entry) => {
                                    if let Err(err) = self.client.remove(&entry) {
                                        self.log(
                                            LogLevel::Error,
                                            format!(
                                                "Could not remove created file {}: {}",
                                                remote_path.display(),
                                                err
                                            ),
                                        );
                                    }
                                }
                            }
                        }
                        Err(err.to_string())
                    }
                    Ok(_) => Ok(()),
                }
            }
            FsEntry::Directory(dir) => {
                // Create directory on remote first
                match self.client.mkdir(remote_path.as_path()) {
                    Ok(_) => {
                        self.log(
                            LogLevel::Info,
                            format!("Created directory \"{}\"", remote_path.display()),
                        );
                    }
                    Err(err) if err.kind() == FileTransferErrorType::DirectoryAlreadyExists => {
                        self.log(
                            LogLevel::Info,
                            format!(
                                "Directory \"{}\" already exists on remote",
                                remote_path.display()
                            ),
                        );
                    }
                    Err(err) => {
                        self.log(
                            LogLevel::Error,
                            format!(
                                "Failed to create directory \"{}\": {}",
                                remote_path.display(),
                                err
                            ),
                        );
                        return Err(err.to_string());
                    }
                }
                // Get files in dir
                match self.host.scan_dir(dir.abs_path.as_path()) {
                    Ok(entries) => {
                        // Iterate over files
                        for entry in entries.iter() {
                            // If aborted; break
                            if self.transfer.aborted() {
                                break;
                            }
                            // Send entry; name is always None after first call
                            if let Err(err) =
                            self.filetransfer_send_recurse(entry, remote_path.as_path(), None)
                            {
                                return Err(err);
                            }
                        }
                        Ok(())
                    }
                    Err(err) => {
                        self.log(
                            LogLevel::Error,
                            format!(
                                "Could not scan directory \"{}\": {}",
                                dir.abs_path.display(),
                                err
                            ),
                        );
                        Err(err.to_string())
                    }
                }
            }
        };

        // If aborted; show popup
        if self.transfer.aborted() {
            // Log abort
            self.log(
                LogLevel::Warn,
                format!("Upload aborted for \"{}\"!", entry.get_abs_path().display()),
            );
        }
        result
    }

    /// ### filetransfer_send_file
    ///
    /// Send local file and write it to remote path
    fn filetransfer_send_one(
        &mut self,
        local: &FsFile,
        remote: &Path,
        file_name: String,
    ) -> Result<(), TransferErrorReason> {
        // Upload file
        // Try to open local file
        match self.host.open_file_read(local.abs_path.as_path()) {
            Ok(fhnd) => match self.client.send_file(local, remote) {
                Ok(rhnd) => {
                    self.filetransfer_send_one_with_stream(local, remote, file_name, fhnd, rhnd)
                }
                Err(err) if err.kind() == FileTransferErrorType::UnsupportedFeature => {
                    self.filetransfer_send_one_wno_stream(local, remote, file_name, fhnd)
                }
                Err(err) => Err(TransferErrorReason::FileTransferError(err)),
            },
            Err(err) => Err(TransferErrorReason::HostError(err)),
        }
    }

    /// ### filetransfer_send_one_with_stream
    ///
    /// Send file to remote using stream
    fn filetransfer_send_one_with_stream(
        &mut self,
        local: &FsFile,
        remote: &Path,
        file_name: String,
        mut reader: File,
        mut writer: Box<dyn Write>,
    ) -> Result<(), TransferErrorReason> {
        // Write file
        let file_size: usize = reader.seek(std::io::SeekFrom::End(0)).unwrap_or(0) as usize;
        // Init transfer
        self.transfer.partial.init(file_size);
        // rewind
        if let Err(err) = reader.seek(std::io::SeekFrom::Start(0)) {
            return Err(TransferErrorReason::CouldNotRewind(err));
        }
        // Write remote file
        let mut total_bytes_written: usize = 0;
        let mut last_progress_val: f64 = 0.0;
        let mut last_input_event_fetch: Option<Instant> = None;
        // While the entire file hasn't been completely written,
        // Or filetransfer has been aborted
        while total_bytes_written < file_size && !self.transfer.aborted() {
            // Handle input events (each 500ms) or if never fetched before
            if last_input_event_fetch.is_none()
                || last_input_event_fetch
                .unwrap_or_else(Instant::now)
                .elapsed()
                .as_millis()
                >= 500
            {
                // Read events
                //self.read_input_event();
                // Reset instant
                last_input_event_fetch = Some(Instant::now());
            }
            // Read till you can
            let mut buffer: [u8; 65536] = [0; 65536];
            let delta: usize = match reader.read(&mut buffer) {
                Ok(bytes_read) => {
                    total_bytes_written += bytes_read;
                    if bytes_read == 0 {
                        continue;
                    } else {
                        let mut delta: usize = 0;
                        while delta < bytes_read {
                            // Write bytes
                            match writer.write(&buffer[delta..bytes_read]) {
                                Ok(bytes) => {
                                    delta += bytes;
                                }
                                Err(err) => {
                                    return Err(TransferErrorReason::RemoteIoError(err));
                                }
                            }
                        }
                        delta
                    }
                }
                Err(err) => {
                    return Err(TransferErrorReason::LocalIoError(err));
                }
            };
            // Increase progress
            self.transfer.partial.update_progress(delta);
            self.transfer.full.update_progress(delta);
            // Draw only if a significant progress has been made (performance improvement)
            if last_progress_val < self.transfer.partial.calc_progress() - 0.01 {
                // Draw
                // self.update_progress_bar(format!("Uploading \"{}\"…", file_name));

                last_progress_val = self.transfer.partial.calc_progress();
            }
        }
        // Finalize stream
        if let Err(err) = self.client.on_sent(writer) {
            self.log(
                LogLevel::Warn,
                format!("Could not finalize remote stream: \"{}\"", err),
            );
        }
        // if upload was abrupted, return error
        if self.transfer.aborted() {
            return Err(TransferErrorReason::Abrupted);
        }
        self.log(
            LogLevel::Info,
            format!(
                "Saved file \"{}\" to \"{}\" (took {} seconds; at {}/s)",
                local.abs_path.display(),
                remote.display(),
                fmt_millis(self.transfer.partial.started().elapsed()),
                ByteSize(self.transfer.partial.calc_bytes_per_second()),
            ),
        );
        Ok(())
    }

    /// ### filetransfer_send_one_wno_stream
    ///
    /// Send an `FsFile` to remote without using streams.
    fn filetransfer_send_one_wno_stream(
        &mut self,
        local: &FsFile,
        remote: &Path,
        file_name: String,
        mut reader: File,
    ) -> Result<(), TransferErrorReason> {
        // Write file
        let file_size: usize = reader.seek(std::io::SeekFrom::End(0)).unwrap_or(0) as usize;
        // Init transfer
        self.transfer.partial.init(file_size);
        // rewind
        if let Err(err) = reader.seek(std::io::SeekFrom::Start(0)) {
            return Err(TransferErrorReason::CouldNotRewind(err));
        }
        // Draw before
        // self.update_progress_bar(format!("Uploading \"{}\"…", file_name));

        // Send file
        if let Err(err) = self
            .client
            .send_file_wno_stream(local, remote, Box::new(reader))
        {
            return Err(TransferErrorReason::FileTransferError(err));
        }
        // Set transfer size ok
        self.transfer.partial.update_progress(file_size);
        self.transfer.full.update_progress(file_size);
        // Draw again after update_progress_bar

        // log and return Ok
        self.log(
            LogLevel::Info,
            format!(
                "Saved file \"{}\" to \"{}\" (took {} seconds; at {}/s)",
                local.abs_path.display(),
                remote.display(),
                fmt_millis(self.transfer.partial.started().elapsed()),
                ByteSize(self.transfer.partial.calc_bytes_per_second()),
            ),
        );
        Ok(())
    }

    /************************ recv *************************/

    /// ### filetransfer_recv
    ///
    /// Recv fs entry from remote.
    /// If dst_name is Some, entry will be saved with a different name.
    /// If entry is a directory, this applies to directory only
    pub fn filetransfer_recv(
        &mut self,
        payload: TransferPayload,
        local_path: &Path,
        dst_name: Option<String>,
    ) -> Result<(), String> {
        let result = match payload {
            TransferPayload::Any(ref entry) => {
                self.filetransfer_recv_any(entry, local_path, dst_name)
            }
            TransferPayload::File(ref file) => self.filetransfer_recv_file(file, local_path),
            TransferPayload::Many(ref entries) => self.filetransfer_recv_many(entries, local_path),
        };
        // Notify
        match &result {
            Ok(_) => {
                self.notify_transfer_completed(&payload);
            }
            Err(e) => {
                self.notify_transfer_error(e.as_str());
            }
        }
        result
    }

    /// ### filetransfer_recv_any
    ///
    /// Recv fs entry from remote.
    /// If dst_name is Some, entry will be saved with a different name.
    /// If entry is a directory, this applies to directory only
    fn filetransfer_recv_any(
        &mut self,
        entry: &FsEntry,
        local_path: &Path,
        dst_name: Option<String>,
    ) -> Result<(), String> {
        // Reset states
        self.transfer.reset();
        // Calculate total transfer size
        let total_transfer_size: usize = self.get_total_transfer_size_remote(entry);
        self.transfer.full.init(total_transfer_size);
        // Mount progress bar

        // Receive
        let result = self.filetransfer_recv_recurse(entry, local_path, dst_name);
        // Umount progress bar

        result
    }

    /// ### filetransfer_recv_file
    ///
    /// Receive a single file from remote.
    fn filetransfer_recv_file(&mut self, entry: &FsFile, local_path: &Path) -> Result<(), String> {
        // Reset states
        self.transfer.reset();
        // Calculate total transfer size
        let total_transfer_size: usize = entry.size;
        self.transfer.full.init(total_transfer_size);
        // Mount progress bar

        // Receive
        let result = self.filetransfer_recv_one(local_path, entry, entry.name.clone());
        // Umount progress bar

        // Return result
        result.map_err(|x| x.to_string())
    }

    /// ### filetransfer_send_many
    ///
    /// Send many entries to remote
    fn filetransfer_recv_many(
        &mut self,
        entries: &[FsEntry],
        curr_remote_path: &Path,
    ) -> Result<(), String> {
        // Reset states
        self.transfer.reset();
        // Calculate total size of transfer
        let total_transfer_size: usize = entries
            .iter()
            .map(|x| self.get_total_transfer_size_remote(x))
            .sum();
        self.transfer.full.init(total_transfer_size);
        // Mount progress bar

        // Send recurse
        let result = entries
            .iter()
            .map(|x| self.filetransfer_recv_recurse(x, curr_remote_path, None))
            .find(|x| x.is_err())
            .unwrap_or(Ok(()));
        // Umount progress bar

        result
    }
    /// faz a recusão para copiar todos os arquivos, diretorios e subdiretorios
    fn filetransfer_recv_recurse(
        &mut self,
        entry: &FsEntry,
        local_path: &Path,
        dst_name: Option<String>,
    ) -> Result<(), String> {
        info!("chamou: filetransfer_recv_recurse");
        // Write popup
        let file_name: String = match entry {
            FsEntry::Directory(dir) => dir.name.clone(),
            FsEntry::File(file) => file.name.clone(),
        };
        // Match entry
        let result: Result<(), String> = match entry {
            FsEntry::File(file) => {
                // Get local file
                let mut local_file_path: PathBuf = PathBuf::from(local_path);
                let local_file_name: String = match dst_name {
                    Some(n) => n,
                    None => file.name.clone(),
                };
                local_file_path.push(local_file_name.as_str());
                // Download file
                if let Err(err) =
                self.filetransfer_recv_one(local_file_path.as_path(), file, file_name)
                {
                    // If transfer was abrupted or there was an IO error on remote, remove file
                    if matches!(
                        err,
                        TransferErrorReason::Abrupted | TransferErrorReason::LocalIoError(_)
                    ) {
                        // Stat file
                        match self.host.stat(local_file_path.as_path()) {
                            Err(err) => self.log(
                                LogLevel::Error,
                                format!(
                                    "Could not remove created file {}: {}",
                                    local_file_path.display(),
                                    err
                                ),
                            ),
                            Ok(entry) => {
                                if let Err(err) = self.host.remove(&entry) {
                                    self.log(
                                        LogLevel::Error,
                                        format!(
                                            "Could not remove created file {}: {}",
                                            local_file_path.display(),
                                            err
                                        ),
                                    );
                                }
                            }
                        }
                    }
                    Err(err.to_string())
                } else {
                    Ok(())
                }
            }
            FsEntry::Directory(dir) => {

                // Get dir name
                let mut local_dir_path: PathBuf = PathBuf::from(local_path);
                //debug!("Get local_dir_path: {}", local_dir_path.as_path().display());
                match &dst_name {
                    Some(name) => local_dir_path.push(name),
                    None => local_dir_path.push(dir.name.as_str()),
                }
                // debug!("Get dst_name: {:?}", dst_name);
                // Create directory on local
                match self.host.mkdir_ex(local_dir_path.as_path(), true) {
                    Ok(_) => {
                        // Apply file mode to directory
                        #[cfg(any(
                        target_family = "unix",
                        target_os = "macos",
                        target_os = "linux"
                        ))]
                        if let Some((owner, group, others)) = dir.unix_pex {
                            if let Err(err) = self.host.chmod(
                                local_dir_path.as_path(),
                                (owner.as_byte(), group.as_byte(), others.as_byte()),
                            ) {
                                self.log(
                                    LogLevel::Error,
                                    format!(
                                        "Could not apply file mode {:?} to \"{}\": {}",
                                        (owner.as_byte(), group.as_byte(), others.as_byte()),
                                        local_dir_path.display(),
                                        err
                                    ),
                                );
                            }
                        }
                        self.log(
                            LogLevel::Info,
                            format!("Created directory \"{}\"", local_dir_path.display()),
                        );
                        // Get files in dir
                        match self.client.list_dir(dir.abs_path.as_path()) {
                            Ok(entries) => {
                                //debug!("Get files in dir: {:?}",entries);
                                // Iterate over files
                                for entry in entries.iter() {
                                    // If transfer has been aborted; break
                                    if self.transfer.aborted() {
                                        break;
                                    }
                                    // Receive entry; name is always None after first call
                                    // Local path becomes local_dir_path
                                    if let Err(err) = self.filetransfer_recv_recurse(
                                        entry,
                                        local_dir_path.as_path(),
                                        None,
                                    ) {
                                        return Err(err);
                                    }
                                }
                                Ok(())
                            }
                            Err(err) => {
                                self.log(
                                    LogLevel::Error,
                                    format!(
                                        "Could not scan directory \"{}\": {}",
                                        dir.abs_path.display(),
                                        err
                                    ),
                                );
                                Err(err.to_string())
                            }
                        }
                    }
                    Err(err) => {
                        self.log(
                            LogLevel::Error,
                            format!(
                                "Failed to create directory \"{}\": {}",
                                local_dir_path.display(),
                                err
                            ),
                        );
                        Err(err.to_string())
                    }
                }
            }
        };
        // Reload directory on local

        // if aborted; show alert
        if self.transfer.aborted() {
            // Log abort
            self.log(
                LogLevel::Warn,
                format!(
                    "Download aborted for \"{}\"!",
                    entry.get_abs_path().display()
                ),
            );
        }
        result
    }

    pub fn filetransfer_recv_dir_as_zip(&mut self, dir_to_copy: &FsDirectory, local_path: &Path) -> FileTransferResult<()> {
        //obter lista de diretorio recursivamente
        match self.client.list_dir_recursively(&dir_to_copy.abs_path.clone()) {
            Ok(it) => {
                let dst_file_writer = File::create(local_path.join("result.zip")).unwrap();
                let mut zip_writer = zip::ZipWriter::new(dst_file_writer);

                let mut buffer = Vec::new();

                for entry in it {
                    let options = zip::write::FileOptions::default()
                        .compression_method(zip::CompressionMethod::Stored)
                        .unix_permissions(0o755);
                    match entry {
                        FsEntry::File(remote) => {

                            let path = &remote.abs_path;
                            //remove a parte inicial do caminho
                            let name = path.strip_prefix(&dir_to_copy.abs_path).unwrap();
                            debug!("source: {}",name.display());

                            match self.client.recv_file(&remote) {
                                Ok(mut rhnd) => {
                                    #[allow(deprecated)]
                                        zip_writer.start_file_from_path(name, options).unwrap();

                                    rhnd.read_to_end(&mut buffer).unwrap();
                                    zip_writer.write_all(&*buffer).unwrap();
                                    buffer.clear();
                                }
                                Err(err) if err.kind() == FileTransferErrorType::UnsupportedFeature => {
                                    error!("FileTransferErrorType::UnsupportedFeature");
                                }
                                Err(err) => {
                                    error!("FileTransferError {:?}",err);
                                }
                            }
                        }
                        FsEntry::Directory(dir) => {}
                    }
                }
                zip_writer.finish().unwrap();
                Ok(())
            }
            Err(err) => {
                self.log(
                    LogLevel::Error,
                    format!(
                        "Failed list dir recursively \"{}\": {}",
                        dir_to_copy.abs_path.display(),
                        err
                    ),
                );
                Err(err)
            }
        }
    }
    //


    /// ### filetransfer_recv_one
    /// Receive file from remote and write it to local path
    fn filetransfer_recv_one(
        &mut self,
        local: &Path,
        remote: &FsFile,
        file_name: String,
    ) -> Result<(), TransferErrorReason> {
        // Try to open local file
        match self.host.open_file_write(local) {
            Ok(local_file) => {
                // Download file from remote
                match self.client.recv_file(remote) {
                    Ok(rhnd) => self.filetransfer_recv_one_with_stream(
                        local, remote, file_name, rhnd, local_file,
                    ),
                    Err(err) if err.kind() == FileTransferErrorType::UnsupportedFeature => {
                        self.filetransfer_recv_one_wno_stream(local, remote, file_name)
                    }
                    Err(err) => Err(TransferErrorReason::FileTransferError(err)),
                }
            }
            Err(err) => Err(TransferErrorReason::HostError(err)),
        }
    }

    /// ### filetransfer_recv_one_with_stream
    ///
    /// Receive an `FsEntry` from remote using stream
    fn filetransfer_recv_one_with_stream(
        &mut self,
        local: &Path,
        remote: &FsFile,
        file_name: String,
        mut reader: Box<dyn Read>,
        mut writer: File,
    ) -> Result<(), TransferErrorReason> {
        let mut total_bytes_written: usize = 0;
        // Init transfer
        self.transfer.partial.init(remote.size);
        // Write local file
        let mut last_progress_val: f64 = 0.0;
        let mut last_input_event_fetch: Option<Instant> = None;
        // While the entire file hasn't been completely read,
        // Or filetransfer has been aborted
        while total_bytes_written < remote.size && !self.transfer.aborted() {
            // Handle input events (each 500 ms) or is None
            if last_input_event_fetch.is_none()
                || last_input_event_fetch
                .unwrap_or_else(Instant::now)
                .elapsed()
                .as_millis()
                >= 500
            {
                // Read events
                //self.read_input_event();
                // Reset instant
                last_input_event_fetch = Some(Instant::now());
            }
            // Read till you can
            let mut buffer: [u8; 65536] = [0; 65536];
            let delta: usize = match reader.read(&mut buffer) {
                Ok(bytes_read) => {
                    total_bytes_written += bytes_read;
                    if bytes_read == 0 {
                        continue;
                    } else {
                        let mut delta: usize = 0;
                        while delta < bytes_read {
                            // Write bytes
                            match writer.write(&buffer[delta..bytes_read]) {
                                Ok(bytes) => delta += bytes,
                                Err(err) => {
                                    return Err(TransferErrorReason::LocalIoError(err));
                                }
                            }
                        }
                        delta
                    }
                }
                Err(err) => {
                    return Err(TransferErrorReason::RemoteIoError(err));
                }
            };
            // Set progress
            self.transfer.partial.update_progress(delta);
            self.transfer.full.update_progress(delta);
            // Draw only if a significant progress has been made (performance improvement)
            if last_progress_val < self.transfer.partial.calc_progress() - 0.01 {
                // Draw
                //self.update_progress_bar(format!("Downloading \"{}\"", file_name));

                last_progress_val = self.transfer.partial.calc_progress();
            }
        }
        // Finalize stream
        if let Err(err) = self.client.on_recv(reader) {
            self.log(
                LogLevel::Warn,
                format!("Could not finalize remote stream: \"{}\"", err),
            );
        }
        // If download was abrupted, return Error
        if self.transfer.aborted() {
            return Err(TransferErrorReason::Abrupted);
        }
        // Apply file mode to file
        #[cfg(target_family = "unix")]
        if let Some((owner, group, others)) = remote.unix_pex {
            if let Err(err) = self
                .host
                .chmod(local, (owner.as_byte(), group.as_byte(), others.as_byte()))
            {
                self.log(
                    LogLevel::Error,
                    format!(
                        "Could not apply file mode {:?} to \"{}\": {}",
                        (owner.as_byte(), group.as_byte(), others.as_byte()),
                        local.display(),
                        err
                    ),
                );
            }
        }
        // Log
        self.log(
            LogLevel::Info,
            format!(
                "Saved file \"{}\" to \"{}\" (took {} seconds; at {}/s)",
                remote.abs_path.display(),
                local.display(),
                fmt_millis(self.transfer.partial.started().elapsed()),
                ByteSize(self.transfer.partial.calc_bytes_per_second()),
            ),
        );
        Ok(())
    }


    /// ### filetransfer_recv_one_with_stream
    ///
    /// Receive an `FsEntry` from remote without using stream
    fn filetransfer_recv_one_wno_stream(
        &mut self,
        local: &Path,
        remote: &FsFile,
        file_name: String,
    ) -> Result<(), TransferErrorReason> {
        // Init transfer
        self.transfer.partial.init(remote.size);
        // Draw before transfer update_progress_bar


        // recv wno stream
        if let Err(err) = self.client.recv_file_wno_stream(remote, local) {
            return Err(TransferErrorReason::FileTransferError(err));
        }
        // Update progress at the end
        self.transfer.partial.update_progress(remote.size);
        self.transfer.full.update_progress(remote.size);
        // Draw after transfer update_progress_bar


        // Apply file mode to file
        #[cfg(target_family = "unix")]
        if let Some((owner, group, others)) = remote.unix_pex {
            if let Err(err) = self
                .host
                .chmod(local, (owner.as_byte(), group.as_byte(), others.as_byte()))
            {
                self.log(
                    LogLevel::Error,
                    format!(
                        "Could not apply file mode {:?} to \"{}\": {}",
                        (owner.as_byte(), group.as_byte(), others.as_byte()),
                        local.display(),
                        err
                    ),
                );
            }
        }
        // Log
        self.log(
            LogLevel::Info,
            format!(
                "Saved file \"{}\" to \"{}\" (took {} seconds; at {}/s)",
                remote.abs_path.display(),
                local.display(),
                fmt_millis(self.transfer.partial.started().elapsed()),
                ByteSize(self.transfer.partial.calc_bytes_per_second()),
            ),
        );
        Ok(())
    }

    /// ### get_total_transfer_size_local
    ///
    /// Get total size of transfer for localhost
    fn get_total_transfer_size_local(&mut self, entry: &FsEntry) -> usize {
        match entry {
            FsEntry::File(file) => file.size,
            FsEntry::Directory(dir) => {
                // List dir
                match self.host.scan_dir(dir.abs_path.as_path()) {
                    Ok(files) => files
                        .iter()
                        .map(|x| self.get_total_transfer_size_local(x))
                        .sum(),
                    Err(err) => {
                        self.log(
                            LogLevel::Error,
                            format!(
                                "Could not list directory {}: {}",
                                dir.abs_path.display(),
                                err
                            ),
                        );
                        0
                    }
                }
            }
        }
    }

    /// ### get_total_transfer_size_remote
    ///
    /// Get total size of transfer for remote host
    fn get_total_transfer_size_remote(&mut self, entry: &FsEntry) -> usize {
        match entry {
            FsEntry::File(file) => file.size,
            FsEntry::Directory(dir) => {
                // List directory
                match self.client.list_dir(dir.abs_path.as_path()) {
                    Ok(files) => files
                        .iter()
                        .map(|x| self.get_total_transfer_size_remote(x))
                        .sum(),
                    Err(err) => {
                        self.log(
                            LogLevel::Error,
                            format!(
                                "Could not list directory {}: {}",
                                dir.abs_path.display(),
                                err
                            ),
                        );
                        0
                    }
                }
            }
        }
    }

    // -- file exist

    pub(crate) fn local_file_exists(&mut self, p: &Path) -> bool {
        self.host.file_exists(p)
    }

    pub(crate) fn remote_file_exists(&mut self, p: &Path) -> bool {
        self.client.stat(p).is_ok()
    }

    /// ### log
    ///
    /// Add message to log events
    pub fn log(&mut self, level: LogLevel, msg: String) {
        // Log to file
        match level {
            LogLevel::Error => error!("{}", msg),
            LogLevel::Info => info!("{}", msg),
            LogLevel::Warn => warn!("{}", msg),
        }
    }

    /// ### get_remote_hostname
    ///
    /// Get remote hostname
    pub fn get_remote_hostname(&self) -> String {
        let ft_params = self.protocol_params.clone();
        match &ft_params {
            ProtocolParams::Generic(params) => params.address.clone(),
            ProtocolParams::AwsS3(params) => params.bucket_name.clone(),
        }
    }

    /// ### notify_transfer_completed
    ///
    /// Send notification regarding transfer completed
    /// The notification is sent only when these conditions are satisfied:
    ///
    /// - notifications are enabled
    /// - transfer size is greater or equal than notification threshold
    pub fn notify_transfer_completed(&self, payload: &TransferPayload) {
        println!("fn notify_transfer_completed");
    }

    /// ### notify_transfer_error
    ///
    /// Send notification regarding transfer error
    /// The notification is sent only when these conditions are satisfied:
    ///
    /// - notifications are enabled
    /// - transfer size is greater or equal than notification threshold
    pub fn notify_transfer_error(&self, msg: &str) {
        println!("fn notify_transfer_error");
    }
}