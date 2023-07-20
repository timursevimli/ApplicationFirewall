'use strict';

const http = require('node:http');
const { BlockList } = require('node:net');
const Firewall = require('./firewall.js');

const exampleData = [{
  ip: '1.1.1.1', ipv: 'ipv4', banned: true, reqCount: 3, reqTime: 1687943365795
},
{
  ip: '1.1.1.2', ipv: 'ipv4', banned: true, reqCunt: 3, reqTime: 1687943365795
},
{
  ip: '::1', ipv: 'ipv6', banned: true, reqCount: 3, reqTime: 1687943365795,
}];

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

const blockList = new BlockList();
blockList.addAddress('1.2.3.4', 'ipv4');

const firewall = new Firewall(options, blockList);

http.createServer((req, res) => {
  console.log({ blockList });
  const url = req.url;
  const ip = req.socket.remoteAddress;
  const isDenied = firewall.validateAndDenyAccess({ url, ip });
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
  firewall.initFirewall(exampleData);
  console.log('Listening on port:', 8000);
});
