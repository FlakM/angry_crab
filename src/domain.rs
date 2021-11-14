use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::convert::From;
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct IpWithCidr {
    pub ip: IpAddr,
    pub cidr_mask: Option<u8>,
}

impl From<wireguard_uapi::get::AllowedIp> for IpWithCidr {
    fn from(ip: wireguard_uapi::get::AllowedIp) -> Self {
        IpWithCidr {
            ip: ip.ipaddr,
            cidr_mask: Some(ip.cidr_mask),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeviceView {
    pub ifindex: u32,
    pub ifname: String,
    pub public_key: Option<[u8; 32]>,
    pub listen_port: u16,
    pub fwmark: u32,
    pub peers: Vec<Peer>,
}

impl From<wireguard_uapi::get::Device> for DeviceView {
    fn from(d: wireguard_uapi::get::Device) -> Self {
        DeviceView {
            public_key: d.public_key,
            peers: d.peers.into_iter().map(|p| p.into()).collect(),
            fwmark: d.fwmark,
            listen_port: d.listen_port,
            ifname: d.ifname,
            ifindex: d.ifindex,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub public_key: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub id: Identity,
    pub endpoint: Option<SocketAddr>,
    pub keep_alive: Option<u16>,
    pub allowed_ips: Vec<IpWithCidr>,
}

impl From<wireguard_uapi::get::Peer> for Peer {
    fn from(p: wireguard_uapi::get::Peer) -> Self {
        Peer {
            id: Identity {
                public_key: p.public_key,
            },
            endpoint: p.endpoint,
            allowed_ips: p.allowed_ips.into_iter().map(|p| p.into()).collect(),
            keep_alive: Some(p.persistent_keepalive_interval),
        }
    }
}

pub struct LocalSettings<'a> {
    pub interface_name: Option<&'a str>,
    pub private_key: &'a [u8; 32],
    pub preshared_key: Option<&'a [u8; 32]>,
    pub endpoint: SocketAddr,
}

fn into_set_peer(peer: &wireguard_uapi::get::Peer) -> wireguard_uapi::set::Peer {
    wireguard_uapi::set::Peer {
        public_key: &peer.public_key,
        allowed_ips: peer
            .allowed_ips
            .iter()
            .map(|ip| wireguard_uapi::set::AllowedIp {
                ipaddr: &ip.ipaddr,
                cidr_mask: Some(ip.cidr_mask),
            })
            .collect(),
        endpoint: peer.endpoint.as_ref(),
        flags: vec![],
        preshared_key: Some(&peer.preshared_key),
        protocol_version: Some(peer.protocol_version),
        persistent_keepalive_interval: Some(peer.persistent_keepalive_interval),
    }
}

pub fn apply_update<'a>(
    device: &'a Device,
    update: &'a WgInstanceUpdateSettings,
    local_settings: &'a LocalSettings<'a>,
    remove_not_included_peers: bool,
) -> Result<wireguard_uapi::set::Device<'a>> {
    let current_peers = &device.peers;
    let mut new_peers: Vec<wireguard_uapi::set::Peer> = vec![];
    for update in &update.peers {
        match update {
            PeerUpdate::Update(peer) => {
                match current_peers
                    .iter()
                    .find(|p| p.public_key == peer.id.public_key)
                {
                    Some(already_present_peer) => {
                        let mut updated = into_set_peer(already_present_peer);
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
                            public_key: &peer.id.public_key,
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
                        let mut set_peer = into_set_peer(peer);
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
    if remove_not_included_peers {
        for peer in &device.peers {
            let defined = new_peers.iter().find(|n| n.public_key == &peer.public_key);
            if defined.is_some() {
                let mut to_be_removed = into_set_peer(peer);
                to_be_removed.flags = vec![wireguard_uapi::set::WgPeerF::RemoveMe];
                final_device.peers.push(to_be_removed);
            }
        }
    }

    for p in new_peers {
        final_device.peers.push(p);
    }

    Ok(final_device)
}

#[cfg(test)]
mod tests {
    use wireguard_uapi::get::Device;

    use super::*;
    fn device() -> Device {
        Device {
            peers: vec![],
            public_key: None,
            private_key: None,
            ifname: "wg0".into(),
            fwmark: 1,
            listen_port: 9999,
            ifindex: 1,
        }
    }

    fn local_settings() -> LocalSettings<'static> {
        LocalSettings {
            private_key: &[0; 32],
            interface_name: Some("wg0"),
            endpoint: "127.0.0.1:9999".parse().unwrap(),
            preshared_key: None,
        }
    }

    fn peer() -> Peer {
        Peer {
            endpoint: None,
            keep_alive: None,
            allowed_ips: vec![],
            id: Identity {
                public_key: [0; 32],
            },
        }
    }

    fn allowed_ip_set_eq(
        one: &wireguard_uapi::set::AllowedIp<'_>,
        two: &wireguard_uapi::set::AllowedIp<'_>,
    ) -> bool {
        one.ipaddr == two.ipaddr && one.cidr_mask == two.cidr_mask
    }

    #[test]
    pub fn empty_operation() {
        let device = device();
        let update = WgInstanceUpdateSettings { peers: vec![] };
        let settings = local_settings();
        let updates = apply_update(&device, &update, &settings).unwrap();

        assert_eq!(updates.peers.len(), 0)
    }

    #[test]
    pub fn add_single_peer() {
        let device = device();
        let mut single_peer = peer();
        single_peer.allowed_ips.push(IpWithCidr {
            ip: "127.0.0.1".parse().unwrap(),
            cidr_mask: Some(24),
        });
        let update = WgInstanceUpdateSettings {
            peers: vec![PeerUpdate::Update(single_peer.clone())],
        };

        let settings = local_settings();
        let updates = apply_update(&device, &update, &settings).unwrap();

        assert_eq!(updates.peers.len(), 1);
        assert_eq!(updates.peers[0].public_key, &single_peer.id.public_key);

        assert!(allowed_ip_set_eq(
            &updates.peers[0].allowed_ips[0],
            &wireguard_uapi::set::AllowedIp {
                ipaddr: &"127.0.0.1".parse().unwrap(),
                cidr_mask: Some(24)
            }
        ));
    }

    #[test]
    pub fn remove_by_id() {
        unimplemented!()
    }

    #[test]
    pub fn change_single_ip_for_node_and_remove_not_mentioned() {
        unimplemented!()
    }
}
