'use strict';

const http = require('node:http');
const firewall = require('./firewall.js');

const routing = {
  '/': '<h1>welcome to homepage</h1><hr>',
};

const types = {
  object: JSON.stringify,
  string: (s) => s,
  undefined: () => 'not found',
  function: (fn, req, res) => JSON.stringify(fn(req, res)),
};

const fwConfig = { maxReqCount: 3, reqInterval: 5000, banMonths: 3 };

http.createServer((req, res) => {
  const isBanned = firewall(req, fwConfig);
  if (isBanned) {
    res.end('You are banned! :(');
    return;
  }
  const data = routing[req.url];
  const type = typeof data;
  const serializer = types[type];
  const result = serializer(data, req, res);
  res.end(result);
}).listen(8000);
