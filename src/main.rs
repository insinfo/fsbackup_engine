#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unused_variables)]

// Include
/*mod filetransfer;
mod fs;
mod utils;

use std::path::PathBuf;
use filetransfer::FileTransferParams;
use crate::filetransfer::{FileTransfer, FileTransferProtocol, ProtocolParams, ScpFileTransfer};
use crate::filetransfer::params::GenericProtocolParams;
use crate::utils::*;*/

use std::net::TcpStream;
use ssh2::Session;

fn main() {

   /* let  config =ProtocolParams::Generic(GenericProtocolParams{
            address: "192.168.133.13".to_string(),
            port: 22,
            username: Some(String::from("isaque.neves")),
            password: Some(String::from("Ins257257"))
        });

    let mut scp = ScpFileTransfer::new();
    scp.connect(&config);*/



    let tcp = TcpStream::connect("192.168.133.13:22").unwrap();
    let mut sess = Session::new().unwrap();
    sess.set_tcp_stream(tcp);
    sess.handshake().unwrap();

    sess.userauth_password("isaque.neves", "Ins257257").unwrap();

    println!("Hello, world! {}",sess.authenticated());
}
