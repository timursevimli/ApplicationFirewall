
'use strict';

const assert = require('node:assert');
const test = require('node:test');
const { BlockList } = require('node:net');
const suspiciousUrls = require('../../suspiciousUrls.js');
const Firewall = require('../Firewall.js');

const now = Date.now();
const exampleData = [
  { ip: '127.0.0.1', ipv: 'ipv4', banned: true, reqCount: 3, reqTime: now },
  { ip: '127.0.0.2', ipv: 'ipv4', banned: true, reqCount: 3, reqTime: now   },
  { ip: '::1', ipv: 'ipv6', banned: true, reqCount: 3, reqTime: now },
];

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

test('Throw exception if IP address is invalid', () => {
  const fw = new Firewall();
  const error = () => fw.validateAndDenyAccess({ url: '/', ip: '7.7.7.1234' });
  assert.throws(error, 'Wrong IP Format!');
});

test('Check suspicious urls', () => {
  let i = 0;
  const fw = new Firewall({ maxReqCount: 0 });
  for (const url of suspiciousUrls) {
    const req = { url, ip: `10.10.0.${i++}` };
    const result = fw.validateAndDenyAccess(req);
    assert.strictEqual(result, true);
  }
});

test('Non-suspicious request', () => {
  const req = { url: '/home', ip: '127.0.0.1' };
  const fw = new Firewall();
  const result = fw.validateAndDenyAccess(req);
  assert.strictEqual(result, false);
});

test('Non-blocking request', () => {
  const req = { url: '/home', ip: '127.0.0.1' };
  const fw = new Firewall({ maxReqCount: 0 });
  const result = fw.validateAndDenyAccess(req);
  assert.strictEqual(result, false);
});

test('Blocking request', () => {
  const req = { url: '/admin', ip: '127.0.0.1' };
  const fw = new Firewall({ maxReqCount: 0 });
  const result = fw.validateAndDenyAccess(req);
  assert.strictEqual(result, true);
});

test('Requests with count', () => {
  const req = { url: '/admin', ip: '127.0.0.1' };
  const fw = new Firewall({ maxReqCount: 1 });
  const res1 = fw.validateAndDenyAccess(req);
  const res2 = fw.validateAndDenyAccess(req);
  assert.strictEqual(res1, false);
  assert.strictEqual(res2, true);
});

test('More requests with count', () => {
  const req = { url: '/admin', ip: '127.0.0.1' };
  const count = 1000;
  const fw = new Firewall({ maxReqCount: count });
  for (let i = 0; i < count; i++) {
    const result = fw.validateAndDenyAccess(req);
    assert.strictEqual(result, false);
  }
  const last = fw.validateAndDenyAccess(req);
  assert.strictEqual(last, true);
});

test('Whitelist', () => {
  const req = { url: '/admin', ip: '127.0.0.1' };
  const options = { maxReqCount: 0 };
  const fw = new Firewall(options);
  fw.addAddressToWhiteList(req.ip);
  const result = fw.validateAndDenyAccess(req);
  assert.strictEqual(result, false);
});

test('Validate blockList (give wrong instance)', () => {
  const blockList = [];
  const init = () => new Firewall({}, blockList);
  assert.throws(init, {
    message: 'Firewall only works with BlockList instance'
  });
});

test('Blocklist for IPv4', () => {
  const req = { url: '/admin', ip: '127.0.0.1' };
  const blockList = new BlockList();
  const fw = new Firewall({ maxReqCount: 1 }, blockList);

  fw.validateAndDenyAccess(req);
  const res1 = blockList.check(req.ip);
  assert.strictEqual(res1, false);

  fw.validateAndDenyAccess(req);
  const res2 = blockList.check(req.ip);
  assert.strictEqual(res2, true);
});

test('Non-Blocking IPv6 request', () => {
  const req = { url: '/home', ip: '::1' };
  const fw = new Firewall({ maxReqCount: 0 });
  const result = fw.validateAndDenyAccess(req);
  assert.strictEqual(result, false);
});

test('Blocking IPv6 request', () => {
  const req = { url: '/admin', ip: '::1' };
  const fw = new Firewall({ maxReqCount: 0 });
  const result = fw.validateAndDenyAccess(req);
  assert.strictEqual(result, true);
});

test('Blocklist for IPv6', () => {
  const req = { url: '/admin', ip: '::1' };
  const blockList = new BlockList();
  const fw = new Firewall({ maxReqCount: 1 }, blockList);

  fw.validateAndDenyAccess(req);
  const res1 = blockList.check(req.ip, 'ipv6');
  assert.strictEqual(res1, false);

  fw.validateAndDenyAccess(req);
  const res2 = blockList.check(req.ip, 'ipv6');
  assert.strictEqual(res2, true);
});

test('Initialization firewall without blocklist', () => {
  const fw = new Firewall({ maxReqCount: 0 });
  fw.initFirewall(exampleData);

  for (const data of exampleData) {
    const { ip } = data;
    const res = fw.validateAndDenyAccess({ url: '/home', ip });
    assert.strictEqual(res, true);
  }
});

test('Initialization firewall with blocklist', () => {
  const blockList = new BlockList();
  const fw = new Firewall({ maxReqCount: 0 }, blockList);
  fw.initFirewall(exampleData);

  for (const data of exampleData) {
    const { ip, ipv } = data;

    const check = blockList.check(ip, ipv);
    assert.strictEqual(check, true);

    const res = fw.validateAndDenyAccess({ url: '/home', ip });
    assert.strictEqual(res, true);
  }
});

test('Add address to block list', () => {
  const blockList = new BlockList();

  blockList.addAddress('127.0.0.1');
  blockList.addAddress('127.0.0.2', 'ipv4');
  blockList.addAddress('::1', 'ipv6');

  const res1 = blockList.rules.includes('Address: IPv4 127.0.0.1');
  const res2 = blockList.rules.includes('Address: IPv6 ::1');
  const res3 = blockList.check('127.0.0.2', 'ipv4');

  assert.strictEqual(res1, true);
  assert.strictEqual(res2, true);
  assert.strictEqual(res3, true);
});

test('Non-blocking interval request', async () => {
  const req = { url: '/admin', ip: '127.0.0.1' };
  const options = { maxReqCount: 3, reqInterval: 1000 };
  const fw = new Firewall(options);
  for (let i = 0; i <= options.maxReqCount; i++) {
    const result = fw.validateAndDenyAccess(req);
    assert.strictEqual(result, false);
    await sleep(options.reqInterval + 50);
  }
});

test('Blocking interval request', async () => {
  const req = { url: '/admin', ip: '127.0.0.1' };
  const options = { maxReqCount: 1, reqInterval: 1000 };
  const fw = new Firewall(options);
  for (let i = 0; i < 3; i++) {
    const result = fw.validateAndDenyAccess(req);
    if (i < options.maxReqCount) {
      assert.strictEqual(result, false);
    } else {
      assert.strictEqual(result, true);
    }
    await sleep(options.reqInterval - 50);
  }
});

test('End', () => {
  process.exit(0);
});
