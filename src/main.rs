use anyhow::Result;
pub mod domain;
use colored::Colorize;
use domain::WgInstanceUpdateSettings;
use wireguard_uapi::get::{AllowedIp, Device, Peer};
use wireguard_uapi::{DeviceInterface, RouteSocket, WgSocket};
mod keys;
use crate::domain::LocalSettings;
fn main() -> Result<()> {
    let mut wg = WgSocket::connect()?;
    let device = wg.get_device(DeviceInterface::from_name("wg0"))?;
    print_device(&device);

    let local_settings = LocalSettings {
        endpoint: "127.0.0.1:9999".parse()?,
        private_key: &[1; 32],
        preshared_key: None,
    };

    let update = WgInstanceUpdateSettings { peers: vec![] };

    std::thread::sleep_ms(1000 * 3);
    println!("updating interface");

    let updated = domain::apply_update(&device, &update, &local_settings)?;

    wg.set_device(updated)?;
    println!("wg should be empty");
    Ok(())
}

fn print_device(device: &Device) {
    println!("{}: {}", "interface".green(), device.ifname.green());
    if let Some(public_key) = &device.public_key {
        println!(
            "  {}: {}",
            "public key".black().bold(),
            base64::encode(public_key)
        );
    }

    if device.listen_port != 0 {
        println!("  {}: {}", "listen port".black().bold(), device.listen_port);
    }

    for peer in &device.peers {
        println!();
        print_peer(peer);
    }
}

#[cfg(target_os = "linux")]
fn print_peer(peer: &Peer) {
    println!(
        "{}: {}",
        "peer".yellow(),
        base64::encode(&peer.public_key).yellow()
    );
    if let Some(endpoint) = peer.endpoint {
        println!("  {}: {}", "endpoint".black().bold(), endpoint);
    }

    print!("  {}: ", "allowed ips".black().bold());
    for (i, allowed_ip) in peer.allowed_ips.iter().enumerate() {
        print_allowed_ip(allowed_ip);
        if i < peer.allowed_ips.len() - 1 {
            print!(", ");
        }
    }
    println!();
}

#[cfg(target_os = "linux")]
fn print_allowed_ip(allowed_ip: &AllowedIp) {
    print!(
        "{}{}{}",
        allowed_ip.ipaddr,
        "/".cyan(),
        allowed_ip.cidr_mask
    );
}
