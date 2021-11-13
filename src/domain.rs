use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::vec::Vec;
use wireguard_uapi::get::Device;
use wireguard_uapi::set::WgPeerF;

#[derive(Serialize, Deserialize)]
pub struct WgInstanceUpdateSettings {
    pub peers: Vec<PeerUpdate>,
}

#[derive(Serialize, Deserialize)]
pub enum PeerUpdate {
    Update(Peer),
    Remove(Identity),
}

#[derive(Serialize, Deserialize)]
pub struct IpWithCidr {
    pub ip: IpAddr,
    pub cidr_mask: Option<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct Identity {
    pub public_key: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct Peer {
    pub id: Identity,
    pub public_key: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    pub keep_alive: Option<u16>,
    pub allowed_ips: Vec<IpWithCidr>,
}

pub struct LocalSettings<'a> {
    pub private_key: &'a [u8; 32],
    pub preshared_key: Option<&'a [u8; 32]>,
    pub endpoint: SocketAddr,
}

fn get_peer_to_set(peer: &wireguard_uapi::get::Peer) -> wireguard_uapi::set::Peer {
    let mut set = wireguard_uapi::set::Peer {
        public_key: &peer.public_key,
        allowed_ips: vec![],
        endpoint: peer.endpoint.as_ref(),
        flags: vec![],
        preshared_key: Some(&peer.preshared_key),
        protocol_version: Some(peer.protocol_version),
        persistent_keepalive_interval: Some(peer.persistent_keepalive_interval),
    };
    for ip in &peer.allowed_ips {
        set.allowed_ips.push(wireguard_uapi::set::AllowedIp {
            ipaddr: &ip.ipaddr,
            cidr_mask: Some(ip.cidr_mask),
        });
    }
    set
}

pub fn apply_update<'a>(
    device: &'a Device,
    update: &'a WgInstanceUpdateSettings,
    local_settings: LocalSettings<'a>,
) -> Result<wireguard_uapi::set::Device<'a>> {
    let current_peers = &device.peers;
    let mut new_peers: Vec<wireguard_uapi::set::Peer> = vec![];
    for update in update.peers.iter() {
        match update {
            PeerUpdate::Update(peer) => {
                match current_peers
                    .iter()
                    .find(|p| p.public_key == peer.public_key)
                {
                    Some(already_present_peer) => {
                        let mut updated = get_peer_to_set(already_present_peer);
                        updated.allowed_ips = peer
                            .allowed_ips
                            .iter()
                            .map(|i| wireguard_uapi::set::AllowedIp {
                                ipaddr: &i.ip,
                                cidr_mask: i.cidr_mask,
                            })
                            .collect();
                        updated.flags = vec![WgPeerF::ReplaceAllowedIps];
                        new_peers.push(updated);
                    }
                    None => {
                        new_peers.push(wireguard_uapi::set::Peer {
                            allowed_ips: peer
                                .allowed_ips
                                .iter()
                                .map(|i| wireguard_uapi::set::AllowedIp {
                                    ipaddr: &i.ip,
                                    cidr_mask: i.cidr_mask,
                                })
                                .collect(),
                            public_key: &peer.public_key,
                            flags: vec![],
                            persistent_keepalive_interval: peer.keep_alive,
                            protocol_version: None,
                            preshared_key: local_settings.preshared_key,
                            endpoint: peer.endpoint.as_ref(),
                        });
                    }
                }
            }
            PeerUpdate::Remove(Identity { public_key }) => {
                match current_peers.iter().find(|p| &p.public_key == public_key) {
                    Some(peer) => {
                        let mut set_peer = get_peer_to_set(peer);
                        set_peer.flags = vec![WgPeerF::RemoveMe];
                        new_peers.push(set_peer);
                    }
                    None => eprint!(
                        "tired to remove peer with public key {:?} that does not exist!",
                        public_key
                    ),
                }
            }
        }
    }
    let mut final_device = wireguard_uapi::set::Device {
        listen_port: Some(device.listen_port),
        flags: vec![wireguard_uapi::set::WgDeviceF::ReplacePeers],
        fwmark: Some(device.fwmark),
        interface: wireguard_uapi::linux::DeviceInterface::Name(device.ifname.clone().into()),
        peers: vec![], // this will be filled later
        private_key: Some(local_settings.private_key),
    };

    // remove all peers that were not included in current update but present for a device
    for peer in device.peers.iter() {
        let defined = new_peers.iter().find(|n| n.public_key == &peer.public_key);
        if defined.is_some() {
            let mut to_be_removed = get_peer_to_set(peer);
            to_be_removed.flags = vec![wireguard_uapi::set::WgPeerF::RemoveMe];
            final_device.peers.push(to_be_removed);
        }
    }

    for p in new_peers.into_iter() {
        final_device.peers.push(p);
    }
    Ok(final_device)
}
