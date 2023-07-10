
'use strict';

const assert = require('node:assert');
const test = require('node:test');
const { BlockList } = require('node:net');
const suspiciousUrls = require('../../suspiciousUrls.js');
const Firewall = require('../Firewall.js');

const now = Date.now();
const exampleData = [
  { ip: '1.1.1.1', ipv: 'ipv4', banned: true, reqCount: 3, reqTime: now },
  { ip: '1.1.1.2', ipv: 'ipv4', banned: true, reqCount: 3, reqTime: now   },
  { ip: '::1', ipv: 'ipv6', banned: true, reqCount: 3, reqTime: now },
];

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

test('Check suspicious urls', () => {
  const fw = new Firewall({ maxReqCount: 0 });
  let i = 0;
  for (const url of suspiciousUrls) {
    const ip = `10.10.10.${i++}`;
    const result = fw.interceptor({ url, ip });
    assert.strictEqual(result, true);
  }
});

test('Non-suspicious request', () => {
  const req = { url: '/home', ip: '127.0.0.0' };
  const fw = new Firewall();
  const result = fw.interceptor(req);
  assert.strictEqual(result, false);
});

test('Non-blocking request', () => {
  const req = { url: '/home', ip: '127.0.0.0' };
  const fw = new Firewall({ maxReqCount: 0 });
  const result = fw.interceptor(req);
  assert.strictEqual(result, false);
});

test('Blocking request', () => {
  const req = { url: '/admin', ip: '127.0.0.0' };
  const fw = new Firewall({ maxReqCount: 0 });
  const result = fw.interceptor(req);
  assert.strictEqual(result, true);
});

test('Requests with count', () => {
  const req = { url: '/admin', ip: '127.0.0.0' };
  const fw = new Firewall({ maxReqCount: 1 });
  const res1 = fw.interceptor(req);
  const res2 = fw.interceptor(req);
  assert.strictEqual(res1, false);
  assert.strictEqual(res2, true);
});

test('More requests with count', () => {
  const req = { url: '/admin', ip: '127.0.0.0' };
  const count = 1000;
  const fw = new Firewall({ maxReqCount: count });
  for (let i = 0; i < count; i++) {
    const result = fw.interceptor(req);
    assert.strictEqual(result, false);
  }
  const last = fw.interceptor(req);
  assert.strictEqual(last, true);
});

test('Whitelist', () => {
  const req = { url: '/admin', ip: '1.1.1.1' };
  const options = { maxReqCount: 0 };
  const fw = new Firewall(options);
  fw.addAddressToWhiteList(req.ip);
  const result = fw.interceptor(req);
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
  const req = { url: '/admin', ip: '127.0.0.0' };
  const blockList = new BlockList();
  const fw = new Firewall({ maxReqCount: 1 }, blockList);

  fw.interceptor(req);
  const res1 = blockList.check(req.ip);
  assert.strictEqual(res1, false);

  fw.interceptor(req);
  const res2 = blockList.check(req.ip);
  assert.strictEqual(res2, true);
});

test('Non-Blocking IPv6 request', () => {
  const req = { url: '/home', ip: '::1' };
  const fw = new Firewall({ maxReqCount: 0 });
  const result = fw.interceptor(req);
  assert.strictEqual(result, false);
});

test('Blocking IPv6 request', () => {
  const req = { url: '/admin', ip: '::1' };
  const fw = new Firewall({ maxReqCount: 0 });
  const result = fw.interceptor(req);
  assert.strictEqual(result, true);
});

test('Blocklist for IPv6', () => {
  const req = { url: '/admin', ip: '::1' };
  const blockList = new BlockList();
  const fw = new Firewall({ maxReqCount: 1 }, blockList);

  fw.interceptor(req);
  const res1 = blockList.check(req.ip, 'ipv6');
  assert.strictEqual(res1, false);

  fw.interceptor(req);
  const res2 = blockList.check(req.ip, 'ipv6');
  assert.strictEqual(res2, true);
});

test('Initialization firewall without blocklist', () => {
  const fw = new Firewall({ maxReqCount: 0 });
  fw.initFirewall(exampleData);

  const res1 = fw.interceptor({ url: '/home', ip: '1.1.1.1' });
  const res2 = fw.interceptor({ url: '/home', ip: '1.1.1.2' });
  const res3 = fw.interceptor({ url: '/home', ip: '::1' });

  assert.strictEqual(res1, true);
  assert.strictEqual(res2, true);
  assert.strictEqual(res3, true);
});

test('Initialization firewall with blocklist', () => {
  const blockList = new BlockList();
  const fw = new Firewall({ maxReqCount: 0 }, blockList);
  fw.initFirewall(exampleData);

  const check1 = blockList.check('1.1.1.1');
  const check2 = blockList.check('1.1.1.2', 'ipv4');
  const check3 = blockList.check('::1', 'ipv6');

  assert.strictEqual(check1, true);
  assert.strictEqual(check2, true);
  assert.strictEqual(check3, true);

  const res1 = fw.interceptor({ url: '/home', ip: '1.1.1.1' });
  const res2 = fw.interceptor({ url: '/home', ip: '1.1.1.2' });
  const res3 = fw.interceptor({ url: '/home', ip: '::1' });

  assert.strictEqual(res1, true);
  assert.strictEqual(res2, true);
  assert.strictEqual(res3, true);
});

test('Add address to block list', () => {
  const blockList = new BlockList();

  blockList.addAddress('1.1.1.1');
  blockList.addAddress('1.1.1.2', 'ipv4');
  blockList.addAddress('::1', 'ipv6');

  const res1 = blockList.rules.includes('Address: IPv4 1.1.1.1');
  const res2 = blockList.rules.includes('Address: IPv6 ::1');
  const res3 = blockList.check('1.1.1.2', 'ipv4');

  assert.strictEqual(res1, true);
  assert.strictEqual(res2, true);
  assert.strictEqual(res3, true);
});

test('Non-blocking interval request', async () => {
  const req = { url: '/admin', ip: '1.1.1.1' };
  const options = { maxReqCount: 3, reqInterval: 1000 };
  const fw = new Firewall(options);
  for (let i = 0; i <= options.maxReqCount; i++) {
    const result = fw.interceptor(req);
    assert.strictEqual(result, false);
    await sleep(options.reqInterval + 50);
  }
});

test('Blocking interval request', async () => {
  const req = { url: '/admin', ip: '1.1.1.1' };
  const options = { maxReqCount: 1, reqInterval: 1000 };
  const fw = new Firewall(options);
  for (let i = 0; i < 3; i++) {
    const result = fw.interceptor(req);
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
