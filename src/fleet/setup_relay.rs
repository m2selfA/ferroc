//! Explicit native setup adapter for existing /ws. No HTTP route/tool/IO authority.
use super::{Connected, Outbound, Relay};
use crate::fleet::setup_broker::{Delivery, Peer, SetupBroker};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{sync::Arc, time::Instant};
use uuid::Uuid;

const MAX_ENVELOPE: usize = 2 * crate::fleet::setup::MAX_SETUP_MESSAGE + 4096;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    #[serde(rename = "type")]
    kind: String,
    request: Request,
}
#[derive(Deserialize)]
#[serde(tag = "stage", rename_all = "camelCase", deny_unknown_fields)]
enum Request {
    Offer {
        id: Uuid,
        #[serde(rename = "peerDevice")]
        peer_device: String,
        payload: String,
    },
    Response {
        id: Uuid,
        payload: String,
    },
    Confirmation {
        id: Uuid,
        payload: String,
    },
}
/// Current token row AND device tokenHash/not-paused are mandatory, even if the
/// underlying legacy /ws accepted the token at its initial upgrade.
pub(super) fn device_valid(relay: &Relay, id: &str, token_hash: &str) -> Result<()> {
    let row = relay
        .store
        .get("device_token", token_hash)?
        .context("native setup credential revoked")?;
    ensure!(
        row["deviceId"].as_str() == Some(id),
        "native setup credential mismatch"
    );
    let device = relay
        .store
        .get("device", id)?
        .context("native setup device revoked")?;
    ensure!(
        device["paused"] != true && device["tokenHash"].as_str() == Some(token_hash),
        "native setup device paused/credential rotated"
    );
    Ok(())
}
fn current(relay: &Relay, broker: &SetupBroker, peer: &Peer) -> Result<Connected> {
    let row = relay
        .devices
        .lock()
        .map_err(|_| anyhow::anyhow!("device registry poisoned"))?
        .get(&peer.device)
        .cloned()
        .context("native setup device offline")?;
    ensure!(
        row.generation == peer.generation && row.setup_scope == Some(broker.scope()),
        "native setup stale/unconfigured connection"
    );
    device_valid(relay, &peer.device, &row.token_hash)?;
    Ok(row)
}
pub(super) fn forward(
    relay: &Arc<Relay>,
    broker: &Arc<SetupBroker>,
    device: &str,
    generation: &str,
    raw: &str,
) -> Result<()> {
    ensure!(raw.len() <= MAX_ENVELOPE, "native setup envelope too large");
    let envelope: Envelope = serde_json::from_str(raw)?;
    ensure!(
        envelope.kind == "fleetSetup",
        "unexpected native setup envelope"
    );
    let actor = Peer::new(device, generation)?;
    current(relay, broker, &actor)?;
    let now = Instant::now();
    let delivery = match envelope.request {
        Request::Offer {
            id,
            peer_device,
            payload,
        } => {
            let target = relay
                .devices
                .lock()
                .map_err(|_| anyhow::anyhow!("device registry poisoned"))?
                .get(&peer_device)
                .cloned()
                .context("native setup peer offline")?;
            let target = Peer::new(&peer_device, &target.generation)?;
            current(relay, broker, &target)?;
            broker.offer(id, actor, target, payload, now)?
        }
        Request::Response { id, payload } => broker.response(id, &actor, payload, now)?,
        Request::Confirmation { id, payload } => broker.confirmation(id, &actor, payload, now)?,
    };
    let recipient = match current(relay, broker, delivery.recipient()) {
        Ok(row) => row,
        Err(error) => {
            broker.failed(&delivery);
            return Err(error);
        }
    };
    // Do not await queue capacity while holding the socket's reader loop; fail
    // closed, retain spent history, and never reconstruct/retry this message.
    if let Err(error) = recipient.tx.try_send(Outbound::Setup(delivery)) {
        let packet = error.into_inner();
        if let Outbound::Setup(delivery) = packet {
            broker.failed(&delivery)
        }
        anyhow::bail!("native setup recipient queue unavailable");
    }
    Ok(())
}
pub(super) fn may_deliver(
    relay: &Relay,
    broker: &SetupBroker,
    delivery: &Delivery,
    recipient_device: &str,
    recipient_generation: &str,
) -> Result<()> {
    ensure!(
        delivery.recipient() == &Peer::new(recipient_device, recipient_generation)?,
        "native setup wrong recipient queue"
    );
    current(relay, broker, delivery.sender())?;
    current(relay, broker, delivery.recipient())?;
    broker.delivery_allowed(delivery, Instant::now())
}
#[cfg(test)]
#[path = "setup_relay_tests.rs"]
mod tests;
