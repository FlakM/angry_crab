use wireguard_uapi::DeviceInterface;
use wireguard_uapi::RouteSocket;
use wireguard_uapi::WgSocket;

use crate::domain;
use crate::domain::LocalSettings;
use crate::domain::Peer;
use crate::domain::WgInstanceUpdateSettings;
use anyhow::Result;

struct WgController<'a> {
    pub socket: WgSocket,
    pub local_settings: &'a LocalSettings<'a>,
}

const DEFAULT_INTERFACE_NAME: &'static str = "wg0";

impl<'a> WgController<'a> {
    fn get_device_interface_name(&self) -> &str {
        self.local_settings
            .interface_name
            .unwrap_or(DEFAULT_INTERFACE_NAME)
    }

    pub fn new(local_settings: &'a LocalSettings) -> Result<WgController<'a>> {
        let wg = WgSocket::connect()?;
        let mut route_socket = RouteSocket::connect()?;

        let present_device_names = route_socket.list_device_names()?;

        let interface_name = local_settings
            .interface_name
            .unwrap_or(DEFAULT_INTERFACE_NAME);
        if present_device_names
            .iter()
            .find(|n| n == &interface_name)
            .is_none()
        {
            route_socket.add_device(interface_name)?;
        }

        Ok(WgController {
            socket: wg,
            local_settings,
        })
    }

    fn update(
        &mut self,
        update: WgInstanceUpdateSettings,
        remove_not_included_peers: bool,
    ) -> Result<()> {
        let device = self.socket.get_device(DeviceInterface::Name(
            self.get_device_interface_name().into(),
        ))?;
        let update_definition = domain::apply_update(
            &device,
            &update,
            self.local_settings,
            remove_not_included_peers,
        )?;
        self.socket
            .set_device(update_definition)
            .map_err(|er| er.into())
    }

    pub fn update_all(&mut self, update: WgInstanceUpdateSettings) -> Result<()> {
        self.update(update, true)
    }

    pub fn remove_single_peer(&mut self, peer: domain::Peer) -> Result<()> {
        self.update(
            WgInstanceUpdateSettings {
                peers: vec![domain::PeerUpdate::Remove(domain::Identity {
                    public_key: peer.id.public_key,
                })],
            },
            false,
        )
    }

    pub fn add_single_peer(&mut self, peer: Peer) -> Result<()> {
        self.update(
            WgInstanceUpdateSettings {
                peers: vec![domain::PeerUpdate::Update(peer)],
            },
            false,
        )
    }

    pub fn get_device(&mut self) -> Result<domain::DeviceView> {
        self.socket
            .get_device(DeviceInterface::Name(
                self.local_settings.interface_name.unwrap_or("wg0").into(),
            ))
            .map_err(|e| e.into())
            .map(|result| result.into())
    }
}
