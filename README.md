# HereOnly

**Make your LAN a vault.** Zero dependencies. No agent, no cloud, no IdP.

HereOnly is a lightweight access-control layer that gates any locally hosted
service to the **physical network segment it lives on**. A request is allowed
only if the client device is provably on the **same Layer-2 broadcast domain**
as the host — verified by ARP/NDP adjacency, bound to a network fingerprint, and
pinned to a session token tied to the device's MAC. Every decision is written to
a tamper-evident physical-access log.

```bash
# Gate any local server, in any language, with no install:
npx github:fizzexual/HereOnly proxy --target http://127.0.0.1:3000 --port 7000
```

> A mesh VPN dissolves the network boundary so a service follows you anywhere.
> **HereOnly does the opposite** — it hardens the boundary so a service stays
> put, reachable only from the cable or Wi-Fi it's plugged into, even if the host
> is accidentally exposed to the public internet.

---

## Why it's different

HereOnly occupies a niche that identity-based VPNs structurally can't:

- **No agent, nothing to install on the client.** Being on the same segment *is*
  the credential. That means it works for devices that can never run a VPN
  client — IoT gadgets, smart TVs, printers, embedded boards, a guest's laptop.
- **Physical presence, not just identity.** A VPN proves *who* you are. HereOnly
  proves *where* you are. You cannot fake being on the same Ethernet segment from
  across the internet, even with stolen credentials.
- **No control plane.** There is no coordination server, no DERP relay, no cloud
  account. It runs air-gapped, in a bunker, on a plane. Deploy once; it keeps
  working with nothing to phone home to.
- **Hardware-bound sessions.** Session tokens are pinned to the device's MAC and
  to the network fingerprint — a stolen cookie is dead the moment it leaves the
  segment, and useless from any other device.
- **Drop into any stack.** Use it as Express middleware, a standalone reverse
  proxy, or a forward-auth endpoint that nginx / Caddy / Traefik can call.
- **Topology-aware.** Bind a service to a specific network fingerprint (subnets +
  gateway MAC + SSID). Even a cloned MAC on a different broadcast domain produces
  a different fingerprint and is rejected.
- **Physical-access audit trail.** An append-only, optionally HMAC-signed,
  hash-chained log of every attempt — IP, MAC, verdict, and whether the device
  was actually present — that no VPN can produce.
- **No SSO dependency.** No Google/Microsoft/OIDC in your trust chain.

## How it works

Each request passes a stack of checks before reaching your app:

1. **Deny list** — explicit CIDR denials, first.
2. **Loopback & host-self** — the host itself (`127.0.0.0/8`, `::1`, and any of
   the host's own interface IPs) is always allowed.
3. **Allow list** — explicit CIDR allowances (an administrative bypass).
4. **Rate limit** *(optional)* — a per-client token bucket throttles abuse.
5. **Session token** — a valid, MAC-bound, network-bound token takes a fast path
   (the device's live MAC is re-checked).
6. **ARP / NDP adjacency** — *the core gate.* The client IP must resolve to a real
   **unicast** neighbor in the host's table. This only happens for devices in the
   same broadcast domain: a remote attacker's packets arrive via the gateway, so
   the host has a neighbor entry for the **gateway**, never for the attacker.
   Off-segment ⇒ no entry ⇒ denied. (Multicast/broadcast/incomplete entries are
   rejected — only a genuine resolved device counts.)
7. **Network approval** *(optional)* — pin to an allow-list of approved networks
   by fingerprint, SSID, or gateway MAC.

The **TCP source address** is authoritative throughout — never a spoofable
`X-Forwarded-For` (except behind a proxy you explicitly trust).

## Install

Not on the npm registry yet — install from GitHub:

```bash
npm install github:fizzexual/HereOnly      # as a dependency
npm install -g github:fizzexual/HereOnly   # for the `hereonly` CLI
npx github:fizzexual/HereOnly --help       # or run with no install
```

Requires Node ≥ 18.17. Zero runtime dependencies.

## Usage

### Segment hub — start it, see every service on the LAN

```bash
hereonly hub        # then open http://<this-host>:7080 from any on-segment device
```

Run `hereonly hub` on one or more machines. They **auto-discover each other over
the LAN** (UDP multicast, TTL 1 — so it never leaves the segment), each
advertises its hostname and the HTTP services it runs (auto-detected from its own
listening ports, plus anything you name with `--service grafana=3000`), and every
on-segment device gets **one gated page listing every machine and service**, with
a direct link and a click-through proxy for each.

No accounts, no coordination server, no config — discovery rides the segment
itself, and the directory page is gated by the same ARP/NDP check, so only
on-segment devices can even load it. It's the easy, "everything just shows up"
experience of a mesh VPN, scoped to the one network you're physically on.

**Stable private addresses.** Each machine also gets a persistent HereOnly name
and a stable IP derived from a saved id, so it survives reboots and DHCP changes.
The address space is configurable (`--addr-range`) and defaults to the reserved
`240.0.0.0/8` block — never routed on the public internet and collision-free with
normal LANs (and with Tailscale's `100.x`):

- `class-e` *(default)* — `240.x.y.z`, reserved / private
- `cgnat` — `100.64.0.0/10`, Tailscale-style
- `ula` — an IPv6 `fd…::/48` whose prefix is derived from your `--hub-secret`, so
  the address space itself is **unguessable without the secret** — a private world
  nothing outside knows about
- any custom CIDR, e.g. `--addr-range 10.77.0.0/16`

Reach any device through the hub by name or address —
`http://<hub>:7080/go/beta/3000/` or `…/go/240.233.101.239/3000/`. No overlay, no
network reconfig: the hub routes to the right peer. (Typing the address *directly*
into a browser, bypassing the hub, needs the opt-in interface-alias mode — admin
only, since it adds a real IP to the NIC.)

```bash
hereonly hub --service nas=5000 --service jellyfin=8096   # name extra services
hereonly hub --hub-secret s3cret                          # private hub (shared secret)
hereonly hub --no-scan                                    # advertise only named services
```

### Reverse proxy (any language)

```bash
hereonly proxy --target http://127.0.0.1:3000 --port 7000
```

Bind your app to `127.0.0.1:3000`; expose `:7000` to the LAN. HTTP + WebSockets.

### Forward-auth for nginx / Caddy / Traefik

Run the auth server, then point your proxy's subrequest auth at it:

```bash
hereonly auth --port 7001        # returns 204 (allow) / 403 (deny)
```

Ready-to-paste snippets are in [`integrations/`](integrations/) — nginx
`auth_request`, Caddy `forward_auth`, Traefik `ForwardAuth`, and a
`docker-compose` (note: run with `network_mode: host` so HereOnly reads the real
segment, not a container bridge).

### Express / Connect middleware

```js
const { hereonly } = require('hereonly/middleware');
app.use(hereonly());                                   // gate everything
app.use('/admin', hereonly({ network: { allowedSsids: ['Ops'] } })); // tighter
```

### Raw Node http (no framework)

```js
const { hereonly } = require('hereonly');
const guard = hereonly({ audit: { file: '.hereonly/audit.log', sign: true } });
http.createServer((req, res) => guard(req, res, () => res.end('on-segment'))).listen(7000);
```

### Programmatic

```js
const { createVerifier } = require('hereonly');
const verifier = createVerifier();
const v = await verifier.verify({ ip: '192.168.1.42' });
// { allow, reason, ip, mac, present, via, token, network, checks }
```

## Physical-access audit log

```bash
hereonly proxy -t http://127.0.0.1:3000 --audit --sign-audit
hereonly audit --denies --tail 20      # who was turned away
hereonly audit --verify                # confirm the chain is intact
```

Each entry records `ip`, `mac`, `verdict`, `reason`, the network fingerprint, and
`present` (was the device physically on-segment). With `--sign-audit` every entry
is chained to the previous via an HMAC hash, so you cannot alter or delete an
entry — or splice the log across restarts — without breaking verification.

## CLI

```
hereonly proxy   --target <url> [--port 7000]      gate a local server
hereonly auth    [--port 7001]                     forward-auth for a reverse proxy
hereonly hub     [--port 7080] [--service n=port]  zero-config LAN service directory
hereonly doctor                                    network identity + sample checks
hereonly status                                    dashboard + audit summary
hereonly check   <ip>                              verify one IP (exit 0/1)
hereonly audit   [--tail N --denies --mac X --verify]
```

Key flags: `--allow-ssid` / `--allow-gw-mac` / `--allow-fingerprint` (network
pinning), `--allow-cidr` / `--deny-cidr`, `--rate-limit`, `--audit` /
`--sign-audit`, `--secret-file` (token-secret persistence), `--no-require-arp`
(subnet-only fallback), `--trust-forwarded`, `--config <file>`.

## Configuration

`createVerifier(options)` / proxy / middleware / auth accept:

| Option | Default | Meaning |
|--------|---------|---------|
| `requireArp` | `true` | ARP/NDP adjacency is the gate |
| `allowSelf` | `true` | the host's own interface IPs count as on-segment |
| `failClosed` | `true` | deny if the neighbor table can't be read |
| `network` | `{}` | `{ allowedSsids, allowedGatewayMacs, allowedFingerprints }` |
| `rateLimit` | `null` | `true` / `{ capacity, refillPerSec }` |
| `audit` | `null` | `true` / `{ file, sign, secret }` |
| `policies` | `[]` | per-resource overrides (match `path`/`host`/`method`) |
| `extraAllowCidrs` / `denyCidrs` | `[]` | static allow / deny |
| `tokenTtlSeconds` | `1800` | session-token lifetime |
| `secret` / `staticIdentity` / `ownIps` | — | pin secret / network / self set |

Config can also be a JSON file (`--config`) or `HEREONLY_*` env vars — see
[`examples/hereonly.config.example.json`](examples/hereonly.config.example.json).

## Threat model — read this

**HereOnly stops *off-segment* access.** It defeats a host accidentally exposed
to the internet, casual access from other VLANs/routed segments, and token replay
from a different device or network.

**It does NOT defend against an attacker already on your Layer-2 segment.** If
they share your broadcast domain they can ARP-spoof, MAC-spoof, and sniff.
HereOnly is a network-segment boundary, not a substitute for app auth or TLS —
use it *with* them for defense in depth. The honest one-liner: HereOnly shrinks
your exposure from "the entire internet" to "the wire you're plugged into." A
large, useful, and bounded reduction.

## Platform support

| | ARP (v4) | NDP (v6) | Gateway | Wi-Fi |
|-|----------|----------|---------|-------|
| **Windows** | `arp -a` | `netsh interface ipv6 show neighbors` | `route print` | `netsh wlan` |
| **Linux** | `ip neigh` (+`/proc/net/arp`) | `ip neigh` | `ip route` | `nmcli`/`iwgetid` |
| **macOS** | `arp -an` | `ndp -an` | `route -n get` | `airport`/`networksetup` |

Wi-Fi is optional everywhere; wired hosts fingerprint on gateway MAC + subnets.

## Development

```bash
npm test                 # 75 unit + integration tests (Node's built-in runner)
node bin/hereonly.js doctor
```

## License

MIT © Fizzexual
