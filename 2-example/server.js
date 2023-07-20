'use strict';

const http = require('node:http');
const  BlockListManager = require('./blockListManager.js');
const { firewall, initFirewall } = require('./firewall.js');

const now = Date.now();

const exampleData = [
  {
    ip: '1.1.1.1', ipv: 'ipv4', banned: true, count: 3,
    reqTime: 1687943365795, blockEnd: 1687945365795,
  },
  {
    ip: '1.1.1.2', ipv: 'ipv4', banned: true, count: 3,
    reqTime: 1687943365795,  blockEnd: 1687945365795,
  },
  {
    ip: '::1', ipv: 'ipv6', banned: true, count: 3,
    reqTime: 1687943365795, blockEnd: now + 10000,
  },
];

const routing = {
  '/': '<h1>welcome to homepage</h1><hr>',
};

const types = {
  object: JSON.stringify,
  string: (s) => s,
  undefined: () => 'not found',
  function: (fn, req, res) => JSON.stringify(fn(req, res)),
};

const options = { maxReqCount: 3, reqInterval: 5000, banMonths: 3 };

const blockList = new BlockListManager();
blockList.addAddress('1.2.3.4', 'ipv4');

const fw = firewall(options, blockList);

http.createServer((req, res) => {
  console.log({ blockList });
  const url = req.url;
  const ip = req.socket.remoteAddress;
  const ipv = ip.includes(':') ? 'ipv6' : 'ipv4';
  const inBlockList = blockList.check(ip, ipv);
  if (inBlockList) {
    return void res.end('You are a in blacklist!');
  }
  const isBanned = fw({ url, ip });
  if (isBanned) {
    return void res.end('You are banned! :(');
  }
  const data = routing[req.url];
  const type = typeof data;
  const serializer = types[type];
  const result = serializer(data, req, res);
  res.end(result);
}).listen(8000, () => {
  initFirewall(exampleData, blockList);
  console.log('Listening on port:', 8000);
});
