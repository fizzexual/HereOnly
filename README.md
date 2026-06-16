# HereOnly

**Subnet-locked access control for local web servers.**

HereOnly is a lightweight, zero-dependency middleware (and standalone reverse
proxy) that enforces **physical-network-segment access control** on any locally
hosted site. A request is only allowed if the client device is provably on the
**same Layer-2 network segment** as the host — verified by ARP/NDP adjacency,
bound to a network fingerprint, and pinned to a session token tied to the
device's MAC.

> Think of it as the inverse of a tunnel like Tailscale. Tailscale's job is to
> make a service reachable from *anywhere*. HereOnly's job is to make a service
> reachable from *here only* — the room you're standing in — and nowhere else,
> even if the host is accidentally exposed to the public internet.

---

## Why?

You spin up a dev server, a dashboard, a home-lab admin panel, a local LLM, a
file share. It binds to `0.0.0.0`. Now anything that can route a packet to that
machine can hit it: a misconfigured port-forward, a hotel/coffee-shop network
that doesn't isolate clients, a compromised router, a cloud VM with a leaky
security group, an SSRF in another service on the box.

"Bind to localhost" is too restrictive (you can't reach it from your phone on
the same Wi-Fi). "Bind to 0.0.0.0 + a password" is a single secret away from
the whole internet. HereOnly draws the boundary where you actually want it:
**the local network segment you are physically on.**

## How it works

A request must pass a configurable stack of checks before it reaches your app:

1. **Loopback fast-path** — requests from the host itself (`127.0.0.0/8`, `::1`)
   are always allowed.
2. **Subnet membership** — the client's TCP source address must fall inside one
   of the host's own interface subnets. (Cheap, necessary, not sufficient.)
3. **ARP / NDP adjacency** *(the core check)* — the client IP must resolve to a
   real MAC in the host's neighbor table. This is the property that can't be
   forged from off-segment: ARP/NDP only resolves for devices in the same
   broadcast domain. A remote attacker's packets arrive via the gateway, so the
   host has **no neighbor entry for their IP** — only for the gateway's. Off the
   segment ⇒ no entry ⇒ denied.
4. **Network fingerprint** *(optional)* — the host's current network is
   fingerprinted from stable signals (default-gateway IP **and gateway MAC**,
   local subnets, and Wi-Fi SSID/BSSID when present). You can pin access to an
   allow-list of approved networks.
5. **Session token** — on first pass, HereOnly issues a signed, expiring token
   bound to `(client IP, client MAC, network fingerprint)`. Subsequent requests
   present it and are re-validated cheaply; a token stolen by another device on
   the LAN is useless because its MAC won't match, and a token carried to
   another network is useless because the fingerprint won't match.

Because the TCP source address (`req.socket.remoteAddress`) is used — never a
spoofable `X-Forwarded-For` header — these checks bind to the actual peer.

## Threat model (read this)

**HereOnly stops *off-segment* access.** What it defeats:

- A host accidentally exposed to the internet (port-forward, public IP, leaky
  cloud SG): remote clients have no neighbor entry ⇒ denied.
- Casual access from other VLANs / routed segments inside an office or campus.
- Token replay from a *different* device or a *different* network.

**What it does NOT defend against** (and never claims to):

- An attacker already on your Layer-2 segment. If they share your broadcast
  domain they can ARP-spoof, MAC-spoof, and sniff. HereOnly is a network-segment
  boundary, not a substitute for app-level auth, TLS, or a hostile-LAN posture.
- Use HereOnly *with* normal authentication for defense in depth, not instead
  of it.

The honest one-liner: **HereOnly shrinks your exposure from "the internet" to
"the cable/Wi-Fi you're plugged into."** That is a large, useful reduction — and
a bounded one.

## Status

🚧 Under active construction. See [tasks/](#) and commit history for progress.

## License

MIT © Fizzexual
