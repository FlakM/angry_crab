use anyhow::Result;

use common::domain::{Identity, IpWithCidr, Peer};
use common::keys;
use controller::{LocalSettings, WgController};
use std::io::{prelude::*, BufReader};
use std::net::TcpStream;

pub fn main() -> Result<()> {
    let mut stream = TcpStream::connect("demo.wireguard.com:42912")?;

    let private_key = keys::generate_private_key();
    let public = keys::public_key_for_secret(private_key)?;
    stream.write_all(format!("{}\n", base64::encode(&public)).as_bytes())?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();

    reader.read_line(&mut response)?;
    println!("read rsp: {}", &response);

    let response: Vec<&str> = response.trim().split(':').collect();
    let (server_pubkey, server_port, internal_ip) = (response[1], response[2], response[3]);

    let settings = LocalSettings {
        private_key: &private_key,
        listen_port: None,
        preshared_key: None,
        interface_name: Some("wg_demo"),
    };

    let mut controller = WgController::new(&settings)?;

    controller.add_single_peer(Peer {
        id: Identity {
            public_key: base64::decode(server_pubkey)?[..].try_into()?,
        },
        endpoint: Some(format!("demo.wireguard.com:{}", server_port).parse()?),
        keep_alive: Some(25),
        allowed_ips: vec![IpWithCidr {
            ip: "0.0.0.0".parse()?,
            cidr_mask: Some(0),
        }],
    })?;

    let device = controller.get_device()?;
    println!("device: {:?}", device);
    println!("add valid rules for internal ip: {}", internal_ip);
    Ok(())
}
