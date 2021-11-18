use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::vec::Vec;

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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeviceView {
    pub ifindex: u32,
    pub ifname: String,
    pub public_key: Option<[u8; 32]>,
    pub listen_port: u16,
    pub fwmark: u32,
    pub peers: Vec<Peer>,
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
