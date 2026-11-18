# Fleet routing renewal: relay-side presentation endpoint

Status: **candidate increment**. It closes the relay half of "a transfer longer
than the lease can survive". It does NOT by itself make ≥1 GiB pass, because
nobody mints successor grants yet.

## The gap it closes

`MAX_LEASE_MS = 60_000` and a routing TTL ceiling of 300 s mean any transfer
longer than the lease must rotate its binding mid-flight. Renewal existed only
as library calls (`SourceWindow::renew`, `HostReceiver::renew`,
`FleetRelay::advance_local`), and `advance_local` is a local registry decision
with no authenticated wire form: a remote peer could not ask the relay to
rotate, so a two-host transfer could never renew at all.

## What was added

`POST /fleet/renew` on the SAME relay listener and router as `/fleet/ws`, and
only when `router_with_fleet` is used. Default router still returns 404.

- Authenticates the caller exactly like a fleet join: bearer device token, live
  `device_token` row, matching `deviceId`, device not paused and token hash
  unchanged. An `Origin` header is refused.
- Body is a minimal successor descriptor (current + next authorization id and
  key epoch). It is **not** a grant and carries no path, size, SHA or permission.
- The successor must already be **offered** by the relay's own control plane
  (`FleetRelay::offer_renewal`). An offer is refused up front unless
  `Route::advance` would accept it, so a peer never holds a successor the route
  would reject later. Offers are bounded (8 per pair) and de-duplicated.
- The route advances only after **both** roles present the same successor on
  their own authenticated calls. One side alone, or one side twice, returns
  `{"advanced": false}` and changes nothing. When the second role presents, the
  offer is consumed and the route now validates only the successor binding.
- Adoption rotates authorization id + key epoch, keeps job digest, chunk ceiling
  and total, and forbids reuse of any earlier binding (history bounded at 1024).

## What this still is not

- **No issuer.** The relay does not mint grants; `offer_renewal` takes a
  `ValidatedGrant` the caller built. Nothing in the product creates successor
  grants, so a real long transfer still needs a control plane that does.
- **No signature check.** The relay cannot verify a renewal signature or
  trusted time. Both peers must still authenticate the successor end-to-end;
  this endpoint is a routing decision, not an authorization.
- **No pump-driven renewal.** `run_source` / `run_target` never call it. Until
  they do at a safe boundary (window empty, coverage equal to the encoded
  prefix), a transfer still dies at lease expiry.
- The body names bindings only. It is not replayable into a route change on its
  own: a stale current binding is refused, and an unoffered successor is
  refused.

## Tests (7 in `fleet::relay_channel::tests::renewal`)

Registry: not-offered presentation refused; one role insufficient; same role
twice insufficient; both roles advance; offer consumed; old binding no longer
routable while successor is; non-rotating successor refused; stranger device
refused; stale current binding refused.

Endpoint: absent on the default router (404); unknown bearer token → 401; two
authenticated roles advance exactly once over real HTTP; paused device → 401
even with a valid token.

## Still open

Grant issuance for successors; pump-driven renewal at a safe boundary;
`send_file` / `sync_dir` / `transfer_get` / `transfer_cancel` MCP surface;
directory-level apply; non-loopback TLS; restart-resume; production acceptance.
