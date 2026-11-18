//! Authenticated current /ws identity, never identity supplied in the body.
use super::{Connected, Outbound, Relay, setup_control};
use crate::fleet::{
    route_control::{RouteControl, RouteDelivery},
    setup_broker::Peer,
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{sync::Arc, time::Instant};
use uuid::Uuid;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Presentation {
    #[serde(rename = "type")]
    kind: String,
    id: Uuid,
    grant_digest: [u8; 32],
    resume: Option<crate::fleet::resume_route::RoleResumeProof>,
}
fn current(relay: &Relay, c: &RouteControl, p: &Peer) -> Result<Connected> {
    let row = relay
        .devices
        .lock()
        .map_err(|_| anyhow::anyhow!("devices poisoned"))?
        .get(&p.device)
        .cloned()
        .context("DATA peer offline")?;
    ensure!(
        row.generation == p.generation
            && row.route_scope == Some(c.scope())
            && row.setup_scope == Some(c.scope()),
        "DATA peer stale/unnegotiated"
    );
    setup_control::device_valid(relay, &p.device, &row.token_hash)?;
    Ok(row)
}
pub(super) fn forward(
    relay: &Arc<Relay>,
    c: &Arc<RouteControl>,
    device: &str,
    generation: &str,
    raw: &str,
) -> Result<()> {
    ensure!(raw.len() <= 1024, "DATA presentation too large");
    let r: Presentation = serde_json::from_str(raw)?;
    ensure!(r.kind == "fleetRoute", "unexpected DATA presentation");
    let actor = Peer::new(device, generation)?;
    current(relay, c, &actor)?;
    if let Some(deliveries) =
        c.present_resume(r.id, r.grant_digest, actor, Instant::now(), r.resume)?
    {
        let result = (|| -> Result<()> {
            for p in c.peers(r.id)? {
                current(relay, c, &p)?;
            }
            for d in deliveries {
                let row = current(relay, c, d.recipient())?;
                row.tx
                    .try_send(Outbound::Data(d))
                    .map_err(|_| anyhow::anyhow!("DATA ticket queue unavailable"))?;
            }
            Ok(())
        })();
        if result.is_err() {
            c.failed(r.id);
        }
        result?;
    }
    Ok(())
}
pub(super) fn may_deliver(
    relay: &Relay,
    c: &RouteControl,
    d: &RouteDelivery,
    device: &str,
    generation: &str,
) -> Result<()> {
    ensure!(
        d.recipient() == &Peer::new(device, generation)?,
        "DATA ticket wrong recipient"
    );
    for p in c.peers(d.id())? {
        current(relay, c, &p)?;
    }
    c.may_deliver(d, Instant::now())
}
