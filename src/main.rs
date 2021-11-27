#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unused_variables)]

//importações para o log
#[macro_use]
extern crate log;
extern crate simplelog;

use std::cell::RefCell;
use simplelog::*;

// Include
mod filetransfer;
mod fs;
mod utils;
mod host;
mod activities;

use std::path::{Path, PathBuf};
use crate::filetransfer::*;
use crate::filetransfer::params::GenericProtocolParams;
//use crate::fs::*;
use crate::fs::{FsDirectory, FsEntry, FsFile};
use crate::utils::*;
use crate::host::*;
use std::fs::File;
use std::io::Read;
use std::process;
use std::time::SystemTime;

use failure::{format_err, Fallible};
use crate::activities::filetransfer_activiy::{FileTransferActivity, TransferPayload};

fn main() {
    //configure log
    CombinedLogger::init(
        vec![
            TermLogger::new(LevelFilter::Debug, Config::default(), TerminalMode::Mixed, ColorChoice::Auto),
            // WriteLogger::new(LevelFilter::Info, Config::default(), File::create("my_rust_binary.log").unwrap()),
        ]
    ).unwrap();
    //configure host
    let localhost = Localhost::new(PathBuf::from(r"C:\MyRustProjects\fsbackup_engine")).unwrap();

    //connection setup
    let config = ProtocolParams::Generic(GenericProtocolParams {
        address: "192.168.133.13".to_string(),
        port: 22,
        username: Some(String::from("isaque.neves")),
        password: Some(String::from("Ins257257")),
    });

    let mut activity = FileTransferActivity::new(localhost, FileTransferProtocol::Scp, config);
    activity.connect();

    //let file_to_download = FsEntry::File(FsFile::from_str("/var/www/.profile"));
    let dir_to_download = FsEntry::Directory(FsDirectory::from_str("/var/www/html/Alex"));
    let dest_dir_path = r"C:\MyRustProjects\fsbackup_engine\download";
    let destiny = PathBuf::from(dest_dir_path);
    //create directory if it doesn't exist
    std::fs::create_dir_all(dest_dir_path).expect(format!("Failed to create directory: {}", dest_dir_path).as_str());

   // match activity.filetransfer_recv(TransferPayload::Any(dir_to_download), &destiny, None) {
    match activity.filetransfer_recv_dir_as_zip(&FsDirectory::from_str("/var/www/html/Alex"), &destiny) {
        Ok(result) => {
            println!("result: {:?}", result);
        }
        Err(e) => {
            println!("error: {:?}", e);//eprintln!()
            process::exit(0);//1
        }
    }
}

