'use strict';

const http = require('node:http');
const Firewall = require('./firewall.js');

const exampleData = [
  {
    ip: '1.1.1.1', ipv: 'ipv4', reqCount: 3, reqTime: 1687943365795
  },
  {
    ip: '1.1.1.2', ipv: 'ipv4', reqCunt: 3, reqTime: 1687943365795
  },
  {
    ip: '::1', ipv: 'ipv6', reqCount: 6, reqTime: 1687943365795,
  }
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

const options = { maxReqCount: 5, reqInterval: 5000 };

const firewall = new Firewall(options);

http.createServer((req, res) => {
  const url = req.url;
  const ip = req.socket.remoteAddress;
  const isDenied = firewall.check({ url, ip });
  if (isDenied) {
    res.writeHead(403);
    return void res.end('You are banned! :(');
  }
  const data = routing[req.url];
  const type = typeof data;
  const serializer = types[type];
  const result = serializer(data, req, res);
  res.end(result);
}).listen(8000, () => {
  firewall.init(exampleData);
  console.log('Listening on port:', 8000);
});
