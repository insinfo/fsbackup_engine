#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unused_variables)]

//importações para o log
#[macro_use]
extern crate log;
extern crate simplelog;

use simplelog::*;

// Include
mod filetransfer;
mod fs;
mod utils;
mod host;

use std::path::{Path, PathBuf};
use crate::filetransfer::*;
use crate::filetransfer::params::GenericProtocolParams;
//use crate::fs::*;
use crate::fs::{FsEntry, FsFile};
use crate::utils::*;
use crate::host::*;
use std::fs::File;
use std::io::Read;
use std::time::SystemTime;

fn main() {
    //configura log
    CombinedLogger::init(
        vec![
            TermLogger::new(LevelFilter::Error, Config::default(), TerminalMode::Mixed, ColorChoice::Auto),
            // WriteLogger::new(LevelFilter::Info, Config::default(), File::create("my_rust_binary.log").unwrap()),
        ]
    ).unwrap();

    let config = ProtocolParams::Generic(GenericProtocolParams {
        address: "192.168.133.13".to_string(),
        port: 22,
        username: Some(String::from("isaque.neves")),
        password: Some(String::from("Ins257257")),
    });

    let mut scp = ScpFileTransfer::new();
    let is_connected = match scp.connect(&config) {
        Ok(ban) => true,
        Err(error) => false
    };

    let path = Path::new("/var/www");
    let dir = match scp.list_dir(&path) {
        Ok(item) => item,
        Err(error) => {
            println!("error {}", error);
            Vec::with_capacity(0)
        }
    };
    /*for item in dir.iter() {
        if item.get_name().contains("profile") {
            println!("item:: {:?}", item);
        }
    }*/

    println!("is_connected: {}", is_connected);
    let remote_path = FsFile{
        name: ".profile".to_string(),
        abs_path: PathBuf::from("/var/www/.profile"),
        last_change_time: SystemTime::now(),
        last_access_time: SystemTime::now(),
        creation_time: SystemTime::now(),
        size: 0,//182,
        ftype: None,
        symlink: None,
        user: None,
        group: None,
        unix_pex: None
    };
    //let fs_ent = FsEntry::File(remote);
    let mut remote_file = scp.recv_file(&remote_path).unwrap();
    let mut buf = Vec::new();
    remote_file.read_to_end(&mut buf).unwrap();

    // Close the channel and wait for the whole content to be tranferred
    //remote_file.send_eof().unwrap();
    //remote_file.wait_eof().unwrap();
    //remote_file.close().unwrap();
    //remote_file.wait_close().unwrap();

    let s = String::from_utf8_lossy(&buf);

    println!("result: {}", s);

    scp.try_disconnect();
}
