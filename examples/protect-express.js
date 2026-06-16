'use strict';

/**
 * Express usage. Requires `express` to be installed (it is NOT a dependency of
 * HereOnly itself):  npm install express
 *
 *   node examples/protect-express.js             # listens on :3000
 */

const express = require('express');
const { hereonly } = require('hereonly/middleware'); // or: require('../src').hereonly

const app = express();

// Gate the whole app to the local network segment.
app.use(hereonly({ logLevel: 'info' }));

// Or gate only a subtree:
//   app.use('/admin', hereonly());

app.get('/', (req, res) => {
  res.send(`<h1>Hello, on-segment device</h1><p>verified via: ${req.hereonly.reason}</p>`);
});

app.listen(3000, () => console.log('express app (HereOnly-protected) on http://localhost:3000'));
