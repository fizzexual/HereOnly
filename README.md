# HereOnly

**Subnet-locked access control for local web servers.** Zero dependencies.

HereOnly is a lightweight middleware (and standalone reverse proxy) that
enforces **physical-network-segment access control** on any locally hosted
site. A request is allowed only if the client device is provably on the **same
Layer-2 segment** as the host — verified by ARP/NDP adjacency, bound to a
network fingerprint, and pinned to a session token tied to the device's MAC.

> The inverse of a tunnel like Tailscale. Tailscale makes a service reachable
> from *anywhere*. HereOnly makes a service reachable from **here only** — the
> network you're physically on — and nowhere else, even if the host is
> accidentally exposed to the public internet.

```bash
# Put HereOnly in front of any local server, in any language:
npx hereonly proxy --target http://127.0.0.1:3000 --port 7000
#   :7000  ->  reachable only by on-segment devices
#   :3000  ->  your raw app (bind it to localhost)
```

---

## Why

You start a dev server, a dashboard, a home-lab panel, a local LLM, a file
share. It binds to `0.0.0.0`. Now anything that can route a packet to that
machine can hit it: a forgotten port-forward, a coffee-shop network that
doesn't isolate clients, a compromised router, a cloud VM with a loose security
group, an SSRF in another service on the box.

- *Bind to localhost* is too restrictive — you can't reach it from your phone on
  the same Wi-Fi.
- *Bind to `0.0.0.0` + a password* is one leaked secret away from the whole
  internet.

HereOnly draws the boundary where you actually want it: **the local network
segment you are physically on.**

## How it works

Each request passes a configurable stack of checks before reaching your app:

1. **Loopback fast-path** — requests from the host itself (`127.0.0.0/8`, `::1`)
   are always allowed.
2. **Subnet membership** — the client's TCP source address must fall in one of
   the host's interface subnets. Cheap; advisory.
3. **ARP / NDP adjacency** — *the core check.* The client IP must resolve to a
   real **unicast** MAC in the host's neighbor table. This is the property that
   can't be forged from off-segment: ARP/NDP only resolves for devices in the
   same broadcast domain. A remote attacker's packets arrive via the gateway, so
   the host has a neighbor entry for the **gateway** — never for the attacker's
   IP. Off the segment ⇒ no entry ⇒ denied. (Multicast/broadcast/incomplete
   entries are rejected — only a genuine resolved device counts.)
4. **Network fingerprint** *(optional)* — the host's network is fingerprinted
   from stable signals (default-gateway IP **and gateway MAC**, local subnets,
   Wi-Fi SSID when present). You can pin access to an allow-list of networks.
5. **Session token** — on first pass, HereOnly issues a signed, expiring token
   bound to `(client IP, client MAC, network fingerprint)`. A token stolen by
   another device on the LAN is useless (its MAC won't match); a token carried
   to another network is useless (the fingerprint won't match); a replayed token
   expires.

The **TCP source address** (`req.socket.remoteAddress`) is used throughout —
never a spoofable `X-Forwarded-For`.

## Install

```bash
npm install hereonly        # library + middleware + proxy
# or run the proxy without installing:
npx hereonly proxy --target http://127.0.0.1:3000
```

Requires Node ≥ 18.17. No runtime dependencies.

## Usage

### As a reverse proxy (any language)

```bash
hereonly proxy --target http://127.0.0.1:3000 --port 7000
```

Bind your real app to `127.0.0.1:3000` and expose `:7000` to the LAN. Supports
HTTP and WebSocket upgrades.

### As Express / Connect middleware

```js
const { hereonly } = require('hereonly/middleware');

app.use(hereonly());                  // gate the whole app
app.use('/admin', hereonly());        // …or just a subtree
```

### In a raw Node http server (no framework)

```js
const http = require('http');
const { hereonly } = require('hereonly');
const guard = hereonly();

http.createServer((req, res) => {
  guard(req, res, () => {
    res.end('You are on the segment. ' + JSON.stringify(req.hereonly));
  });
}).listen(7000);
```

### Programmatic verification

```js
const { createVerifier } = require('hereonly');
const verifier = createVerifier();

const verdict = await verifier.verify({ ip: '192.168.1.42' });
// { allow, reason, ip, mac, via, token, network, checks }
```

## CLI

```
hereonly proxy   --target <url> [--port 7000] [options]   run the gating proxy
hereonly doctor                                           print network identity + sample checks
hereonly check <ip>                                       verify one IP (exit 0=allow, 1=deny)
```

Useful proxy options:

| Flag | Meaning |
|------|---------|
| `-t, --target <url>` | local server to protect |
| `-p, --port <n>` | listen port (default 7000) |
| `--allow-ssid <ssid>` | pin to an approved Wi-Fi SSID (repeatable) |
| `--allow-gw-mac <mac>` | pin to an approved gateway MAC (repeatable) |
| `--allow-cidr <cidr>` / `--deny-cidr <cidr>` | static allow / deny |
| `--secret-file <path>` | persist the token secret across restarts |
| `--no-require-arp` | subnet-only mode (weaker; for hosts that can't read ARP) |
| `--fail-open` | allow when the neighbor table can't be read (unsafe) |
| `--trust-forwarded` | trust `X-Forwarded-For` (only behind a trusted proxy) |

`hereonly doctor` is the fastest way to see what HereOnly sees:

```
subnets    : 192.168.100.0/24
gateway    : 192.168.100.1 (58:72:c9:41:36:94)
wifi       : (no wifi / wired)
fingerprint: 071f9afe5cc4d11e23b8edfd34b4aafc

sample verifications:
  ALLOW  127.0.0.1            loopback
  ALLOW  192.168.100.1        arp-verified  mac=58:72:c9:41:36:94
  DENY   8.8.8.8              no-arp-entry
```

## Configuration

`createVerifier(options)` / proxy / middleware accept:

| Option | Default | Meaning |
|--------|---------|---------|
| `requireArp` | `true` | ARP/NDP adjacency is the gate |
| `requireSubnet` | `true` | subnet check (active gate only when `requireArp` is false) |
| `failClosed` | `true` | deny if the neighbor table can't be read |
| `includeWifi` | `true` | include Wi-Fi SSID in the fingerprint |
| `tokenTtlSeconds` | `1800` | session-token lifetime |
| `revalidateArpWithToken` | `true` | re-check live ARP even on the token fast-path |
| `extraAllowCidrs` | `[]` | always-allow CIDRs (bypass ARP) |
| `denyCidrs` | `[]` | always-deny CIDRs |
| `network` | `{}` | `{ allowedSsids, allowedGatewayMacs, allowedFingerprints }` |
| `secret` | random | HMAC secret for tokens (Buffer/string) |
| `staticIdentity` | — | pin the network identity (skip live probing) |

Config can also come from a JSON file (`--config`) or `HEREONLY_*` env vars. See
[`examples/hereonly.config.example.json`](examples/hereonly.config.example.json).

## Threat model — read this

**HereOnly stops *off-segment* access.** What it defeats:

- A host accidentally exposed to the internet (port-forward, public IP, leaky
  cloud SG): remote clients have no neighbor entry ⇒ denied.
- Casual access from other VLANs / routed segments in an office or campus.
- Token replay from a *different* device or *different* network.

**What it does NOT defend against** (and never claims to):

- An attacker already on your Layer-2 segment. If they share your broadcast
  domain they can ARP-spoof, MAC-spoof, and sniff. HereOnly is a network-segment
  boundary, not a substitute for app auth, TLS, or a hostile-LAN posture.
- Use HereOnly **with** normal authentication for defense in depth, not instead
  of it.

The honest one-liner: **HereOnly shrinks your exposure from "the internet" to
"the cable/Wi-Fi you're plugged into."** A large, useful reduction — and a
bounded one.

### Notes & limitations

- The TCP source address is authoritative. Don't enable `--trust-forwarded`
  unless a proxy *you control* sits in front; otherwise the check applies to the
  proxy, not the client.
- IPv4 ARP is read on all platforms. IPv6 NDP is read on Linux (`ip neigh`) and
  macOS; on Windows the v1 neighbor read is IPv4-focused — IPv6-only clients on
  Windows hosts fall back to the subnet check.
- Reading the neighbor table shells out to `arp` / `ip` / `netsh`; results are
  cached briefly (default 2 s) so this is cheap per request.

## Platform support

| | ARP/NDP | Gateway | Wi-Fi SSID |
|-|---------|---------|-----------|
| **Windows** | `arp -a` | `route print` | `netsh wlan` |
| **Linux** | `ip neigh` (+`/proc/net/arp`) | `ip route` | `nmcli` / `iwgetid` |
| **macOS** | `arp -an` | `route -n get` | `airport` / `networksetup` |

Wi-Fi is optional everywhere; wired hosts fingerprint on gateway MAC + subnets.

## Development

```bash
npm test                 # all unit + integration tests (Node's built-in runner)
npm run test:unit
npm run test:integration
node bin/hereonly.js doctor
```

## License

MIT © Fizzexual
