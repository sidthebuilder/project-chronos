use anyhow::Result;
use libp2p::{
    gossipsub, kad, noise, swarm::NetworkBehaviour, swarm::SwarmEvent, tcp, yamux, Multiaddr,
    PeerId, Swarm, SwarmBuilder,
};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    time::Duration,
};
use tokio::sync::mpsc;

#[derive(NetworkBehaviour)]
pub struct ChronosBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
}

pub struct NetworkService {
    pub swarm: Swarm<ChronosBehaviour>,
}

impl NetworkService {
    pub fn new() -> Result<Self> {
        let mut swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                // Setup Gossipsub
                let message_id_fn = |message: &gossipsub::Message| {
                    let mut s = DefaultHasher::new();
                    message.data.hash(&mut s);
                    gossipsub::MessageId::from(s.finish().to_string())
                };

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(10))
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .message_id_fn(message_id_fn)
                    .build()
                    .map_err(|msg| std::io::Error::new(std::io::ErrorKind::Other, msg))?;

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .map_err(|msg| std::io::Error::new(std::io::ErrorKind::Other, msg))?;

                // Setup Kademlia DHT
                let local_peer_id = PeerId::from(key.public());
                let store = kad::store::MemoryStore::new(local_peer_id);
                let kademlia = kad::Behaviour::new(local_peer_id, store);

                Ok(ChronosBehaviour {
                    gossipsub,
                    kademlia,
                })
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        // Subscribe to a generic compute topic
        let topic = gossipsub::IdentTopic::new("chronos-compute-tasks");
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

        Ok(Self { swarm })
    }

    pub fn listen_on(&mut self, addr: Multiaddr) -> Result<()> {
        self.swarm.listen_on(addr)?;
        Ok(())
    }

    pub fn dial(&mut self, addr: Multiaddr) -> Result<()> {
        self.swarm.dial(addr)?;
        Ok(())
    }

    pub fn broadcast_task(&mut self, task_data: &[u8]) -> Result<()> {
        let topic = gossipsub::IdentTopic::new("chronos-compute-tasks");
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic, task_data)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_service_creation() {
        let service = NetworkService::new();
        assert!(service.is_ok(), "Failed to create NetworkService");
    }

    #[tokio::test]
    async fn test_listen_on_tcp_address() {
        let mut service = NetworkService::new().unwrap();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let result = service.listen_on(addr);
        assert!(result.is_ok(), "Failed to listen on tcp address");
    }

    #[tokio::test]
    async fn test_broadcast_task() {
        let mut service = NetworkService::new().unwrap();
        let result = service.broadcast_task(b"test task data");
        // Because there are no peers connected, publish might return an error like InsufficientPeers,
        // but we just check that the function executes without panicking.
        let _ = result;
    }
}
