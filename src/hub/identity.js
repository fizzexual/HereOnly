'use strict';

/**
 * Stable per-device hub identity.
 *
 * Each machine gets a persistent id, a friendly name, and a stable address in
 * the 100.64.0.0/10 range (the same CGNAT space Tailscale uses) — derived
 * deterministically from the id, so it never changes even as DHCP reshuffles
 * the machine's real LAN IP. The hub routes by this name/address, so you get a
 * stable handle for every device without any overlay or network reconfig.
 *
 * The address is decentralized-by-construction (hash of the id), which keeps the
 * "no control plane" promise. Collisions are astronomically unlikely on a LAN;
 * the discovery layer can still detect and rederive on the rare clash.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const DEFAULT_ID_FILE = '.hereonly/hub-id.json';

/** Deterministic 100.64.0.0/10 address from a device id. */
function addrFromId(id) {
  const h = crypto.createHash('sha256').update('hereonly-addr:' + String(id)).digest();
  const second = 64 | (h[0] & 0x3f); // 64..127  -> stays inside /10
  const third = h[1];
  let fourth = h[2];
  if (fourth === 0) fourth = 1;
  if (fourth === 255) fourth = 254;
  return `100.${second}.${third}.${fourth}`;
}

/**
 * Load (or create + persist) this host's stable identity.
 * @returns {{ id: string, name: string, addr: string }}
 */
function loadOrCreateIdentity(file, hostname, nameOverride) {
  const target = file || DEFAULT_ID_FILE;
  let id = null;
  let name = null;
  try {
    const j = JSON.parse(fs.readFileSync(target, 'utf8'));
    if (j && typeof j.id === 'string') {
      id = j.id;
      name = j.name || null;
    }
  } catch {
    /* not created yet */
  }
  if (!id) {
    id = crypto.randomBytes(8).toString('hex');
    name = nameOverride || hostname;
    try {
      fs.mkdirSync(path.dirname(path.resolve(target)), { recursive: true });
      fs.writeFileSync(target, JSON.stringify({ id, name }, null, 2));
    } catch {
      /* ephemeral identity if the path isn't writable */
    }
  }
  return { id, name: nameOverride || name || hostname, addr: addrFromId(id) };
}

module.exports = { addrFromId, loadOrCreateIdentity, DEFAULT_ID_FILE };
