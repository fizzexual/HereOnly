'use strict';

/**
 * Express usage. Requires express (NOT a dependency of HereOnly):
 *   npm install express
 *   node examples/protect-express.js             # listens on :3000
 */

const express = require('express');
const { hereonly } = require('hereonly/middleware'); // or require('../src').hereonly

const app = express();

// Gate the whole app to the local segment.
app.use(hereonly({ logLevel: 'info' }));

// Tighten a subtree to an approved Wi-Fi network with its own verifier:
//   app.use('/admin', hereonly({ network: { allowedSsids: ['Ops'] } }));

app.get('/', (req, res) => {
  res.send(`<h1>Hello, on-segment device</h1><p>verified via: ${req.hereonly.reason}` + (req.hereonly.mac ? ` (${req.hereonly.mac})` : '') + `</p>`);
});

app.listen(3000, () => console.log('express app (HereOnly-protected) on http://localhost:3000'));
