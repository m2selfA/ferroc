use super::*;
use crate::fleet::{
    auth::IdentityKey,
    relay_io::{Renewal, RenewalProvider, run_source_with_renewal, run_target_with_renewal},
    renewal::successor,
};
/// Stands in for a coordinating control plane: both hosts derive the SAME
/// successor from seed+generation, and it registers the offer with the relay so
/// the pumps' own presentation calls have something to adopt.
///
/// Fixture-supplied and NOT proven for two hosts: the signatures (one process
/// holds both identities) and the offer registration (a real run needs an
/// out-of-band control plane). What IS under test is the ordering: present →
/// relay adopts → advance → target confirms → source resumes.
#[cfg(windows)]
struct Fixture {
    registry: Arc<FleetRelay>,
    current: ValidatedGrant,
    seed: [u8; 32],
    step: u64,
    generation: u64,
}
#[cfg(windows)]
impl Fixture {
    fn material(&self, current: &ValidatedGrant, next: &ValidatedGrant, g: u64) -> Renewal {
        let sk = IdentityKey::from_test_seed([0x11; 32]);
        let tk = IdentityKey::from_test_seed([0x22; 32]);
        let s = EphemeralKey::from_test_bytes([0x70 + g as u8; 32]);
        let t = EphemeralKey::from_test_bytes([0x80 + g as u8; 32]);
        let tr = Transcript::for_grant(next, sk.public(), tk.public(), s.public(), t.public());
        let source_signature = sk.sign(&tr, Direction::SourceToTarget).unwrap();
        let target_signature = tk.sign(&tr, Direction::TargetToSource).unwrap();
        let _ = current;
        Renewal {
            grant: next.clone(),
            generation: g,
            source_key: s,
            target_key: t,
            transcript: tr,
            source_signature,
            target_signature,
        }
    }
    /// Derive generation `generation` and register the offer with the relay.
    fn prepare(&mut self, generation: u64) -> Result<Renewal> {
        let next = successor(
            &self.current,
            &self.seed,
            generation,
            self.current.grant().issued_at_ms + 10,
            50_000,
        )?;
        // Both sides may reach this; only the first registration wins.
        let _ = self.registry.offer_renewal(&self.current, &next);
        let material = self.material(&self.current.clone(), &next, generation);
        Ok(material)
    }
}
#[cfg(windows)]
impl RenewalProvider for Fixture {
    fn rotate_source(&mut self, progress: u64) -> Option<Renewal> {
        if progress < (self.generation + 1) * self.step {
            return None;
        }
        let generation = self.generation + 1;
        let material = self.prepare(generation).ok()?;
        self.current = material.grant.clone();
        self.generation = generation;
        Some(material)
    }
    fn accept_offer(&mut self, offer: &crate::fleet::control::RenewOffer) -> Option<Renewal> {
        let generation = self.generation + 1;
        let material = self.prepare(generation).ok()?;
        let binding = &material.grant.grant().binding;
        if binding.authorization_id != offer.next_authorization_id
            || binding.key_epoch != offer.next_key_epoch
        {
            return None;
        }
        self.current = material.grant.clone();
        self.generation = generation;
        Some(material)
    }
}
/// Opt-in. Rotation is NOT part of the single-user profile: it exists for
/// unpredictable transfer length + mid-transfer revocation + an external
/// adversary. All three are absent when one person runs both ends, and the
/// ordering constraints it imposes are pure cost there. Run explicitly with
/// `--ignored` when working on the multi-host profile.
#[cfg(windows)]
#[ignore = "opt-in: renewal rotation is off by default (single-user profile)"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pumps_rotate_through_the_handshake_and_still_settle() {
    const CHUNK: usize = 65536;
    const CHUNKS: usize = 40;
    const STEP: u64 = (8 * CHUNK) as u64;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    make_directory(&root.join("source")).unwrap();
    make_directory(&root.join("target")).unwrap();
    let data = vec![0x5a; CHUNKS * CHUNK];
    std::fs::write(root.join("source/input.bin"), &data).unwrap();
    drop(new_private(&root.join("target/host.db")).unwrap());
    let g = grant(&root, &data);
    let registry = Arc::new(FleetRelay::new());
    let (url, _relay, server_task) = server(&root, Some(registry.clone())).await;
    let tickets = registry
        .approve_local(&g, "source-A", "target-B", Duration::from_secs(120))
        .unwrap();
    let source_link = link(
        &url,
        tickets.source.expose_secret(),
        &g,
        Direction::SourceToTarget,
    )
    .await
    .unwrap();
    let target_link = link(
        &url,
        tickets.target.expose_secret(),
        &g,
        Direction::TargetToSource,
    )
    .await
    .unwrap();
    let rt = Runtime::new(Policy::new(vec![root.join("target")], false).unwrap());
    let host = rt
        .open_fleet_host(&root.join("target/host.db"), InventoryLimits::default())
        .unwrap();
    host.resume().unwrap();
    let receiver = host
        .admit_receiver(records(&g, Direction::TargetToSource))
        .unwrap();
    let srt = Runtime::new(Policy::new(vec![root.join("source")], false).unwrap());
    let window = SourceWindow::new(
        srt.open_fleet_source(records(&g, Direction::SourceToTarget))
            .unwrap(),
        4,
    )
    .unwrap();
    let mut source_fixture = Fixture {
        registry: registry.clone(),
        current: g.clone(),
        seed: [0x3c; 32],
        step: STEP,
        generation: 0,
    };
    let mut target_fixture = Fixture {
        registry: registry.clone(),
        current: g.clone(),
        seed: [0x3c; 32],
        step: STEP,
        generation: 0,
    };
    let source = run_source_with_renewal(window, source_link, &mut source_fixture);
    let target = run_target_with_renewal(receiver, target_link, &mut target_fixture);
    let (observation, receipt) = tokio::join!(source, target);
    match (&observation, &receipt) {
        (Ok(_), Ok(_)) => {}
        _ => panic!(
            "source={:?} target={:?}",
            observation.as_ref().err().map(|e| format!("{e:#}")),
            receipt.as_ref().err().map(|e| format!("{e:#}"))
        ),
    }
    let observation = observation.unwrap();
    let receipt = receipt.unwrap();
    assert_eq!(receipt.size, (CHUNKS * CHUNK) as u64);
    assert_eq!(receipt.sha256, g.job().sha256);
    assert_eq!(observation.receipt().receipt_id, receipt.receipt_id);
    let written = std::fs::read(root.join("target/output.bin")).unwrap();
    assert_eq!(written, data);
    assert!(
        source_fixture.generation >= 3,
        "rotated={}",
        source_fixture.generation
    );
    assert_eq!(
        source_fixture.generation, target_fixture.generation,
        "both hosts must agree on the installed generation"
    );
    server_task.abort();
    let _ = server_task.await;
}
