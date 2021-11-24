use super::FileTransferProtocol;

use std::path::{Path, PathBuf};

/// ### FileTransferParams
///
/// Holds connection parameters for file transfers
#[derive(Debug, Clone)]
pub struct FileTransferParams {
    pub protocol: FileTransferProtocol,
    pub params: ProtocolParams,
    pub entry_directory: Option<PathBuf>,
}

/// ## ProtocolParams
///
/// Container for protocol params
#[derive(Debug, Clone)]
pub enum ProtocolParams {
    Generic(GenericProtocolParams),
    AwsS3(AwsS3Params),
}

/// ## GenericProtocolParams
///
/// Protocol params used by most common protocols
#[derive(Debug, Clone)]
pub struct GenericProtocolParams {
    pub address: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// ## AwsS3Params
///
/// Connection parameters for AWS S3 protocol
#[derive(Debug, Clone)]
pub struct AwsS3Params {
    pub bucket_name: String,
    pub region: String,
    pub profile: Option<String>,
}

impl FileTransferParams {
    /// ### new
    ///
    /// Instantiates a new `FileTransferParams`
    pub fn new(protocol: FileTransferProtocol, params: ProtocolParams) -> Self {
        Self {
            protocol,
            params,
            entry_directory: None,
        }
    }

    /// ### entry_directory
    ///
    /// Set entry directory
    pub fn entry_directory<P: AsRef<Path>>(mut self, dir: Option<P>) -> Self {
        self.entry_directory = dir.map(|x| x.as_ref().to_path_buf());
        self
    }
}

impl Default for FileTransferParams {
    fn default() -> Self {
        Self::new(FileTransferProtocol::Scp, ProtocolParams::default())
    }
}

impl Default for ProtocolParams {
    fn default() -> Self {
        Self::Generic(GenericProtocolParams::default())
    }
}

impl ProtocolParams {
    /// ### generic_params
    ///
    /// Retrieve generic parameters from protocol params if any
    pub fn generic_params(&self) -> Option<&GenericProtocolParams> {
        match self {
            ProtocolParams::Generic(params) => Some(params),
            _ => None,
        }
    }

    pub fn mut_generic_params(&mut self) -> Option<&mut GenericProtocolParams> {
        match self {
            ProtocolParams::Generic(params) => Some(params),
            _ => None,
        }
    }

    /// ### s3_params
    ///
    /// Retrieve AWS S3 parameters if any
    pub fn s3_params(&self) -> Option<&AwsS3Params> {
        match self {
            ProtocolParams::AwsS3(params) => Some(params),
            _ => None,
        }
    }
}

// -- Generic protocol params

impl Default for GenericProtocolParams {
    fn default() -> Self {
        Self {
            address: "localhost".to_string(),
            port: 22,
            username: None,
            password: None,
        }
    }
}

impl GenericProtocolParams {
    /// ### address
    ///
    /// Set address to params
    pub fn address<S: AsRef<str>>(mut self, address: S) -> Self {
        self.address = address.as_ref().to_string();
        self
    }

    /// ### port
    ///
    /// Set port to params
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// ### username
    ///
    /// Set username for params
    pub fn username<S: AsRef<str>>(mut self, username: Option<S>) -> Self {
        self.username = username.map(|x| x.as_ref().to_string());
        self
    }

    /// ### password
    ///
    /// Set password for params
    pub fn password<S: AsRef<str>>(mut self, password: Option<S>) -> Self {
        self.password = password.map(|x| x.as_ref().to_string());
        self
    }
}

// -- S3 params

impl AwsS3Params {
    /// ### new
    ///
    /// Instantiates a new `AwsS3Params` struct
    pub fn new<S: AsRef<str>>(bucket: S, region: S, profile: Option<S>) -> Self {
        Self {
            bucket_name: bucket.as_ref().to_string(),
            region: region.as_ref().to_string(),
            profile: profile.map(|x| x.as_ref().to_string()),
        }
    }
}
