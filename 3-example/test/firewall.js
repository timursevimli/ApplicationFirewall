
'use strict';

const assert = require('node:assert');
const test = require('node:test');
const suspiciousUrls = require('../../suspiciousUrls.js');
const Firewall = require('../firewall.js');

const now = Date.now();

const exampleData = [
  { ip: '127.0.0.1', ipv: 'ipv4', reqCount: 3, reqTime: now },
  { ip: '127.0.0.2', ipv: 'ipv4', reqCount: 3, reqTime: now   },
  { ip: '::1', ipv: 'ipv6', reqCount: 3, reqTime: now },
];

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

const getRandomIPv4 = () =>
  Array.from({ length: 4 }, () => Math.floor(Math.random() * 256)).join('.');

test('No validating wrong ip formats', () => {
  const fw = new Firewall();
  const result = fw.check({ url: '/', ip: '7.7.7.1234' });
  assert.strictEqual(result, false);
});

test('Check suspicious urls', () => {
  const length = suspiciousUrls.length;
  const fw = new Firewall({ maxReqCount: 0 });
  for (let i = 0; i < length; i++) {
    const req = { url: suspiciousUrls[i], ip: getRandomIPv4() };
    const result = fw.check(req);
    assert.strictEqual(result, true);
  }
});

test('Non-suspicious request', () => {
  const req = { url: '/home', ip: '127.0.0.1' };
  const fw = new Firewall();
  const result = fw.check(req);
  assert.strictEqual(result, false);
});

test('Non-blocking request', () => {
  const req = { url: '/home', ip: '127.0.0.1' };
  const fw = new Firewall({ maxReqCount: 0 });
  const result = fw.check(req);
  assert.strictEqual(result, false);
});

test('Blocking request', () => {
  const req = { url: '/admin', ip: '127.0.0.1' };
  const fw = new Firewall({ maxReqCount: 0 });
  const result = fw.check(req);
  assert.strictEqual(result, true);
});

test('Requests with count', () => {
  const req = { url: '/admin', ip: '127.0.0.1' };
  const fw = new Firewall({ maxReqCount: 1 });
  const res1 = fw.check(req);
  const res2 = fw.check(req);
  assert.strictEqual(res1, false);
  assert.strictEqual(res2, true);
});

test('More requests with count', () => {
  const req = { url: '/admin', ip: '127.0.0.1' };
  const count = 1000;
  const fw = new Firewall({ maxReqCount: count });
  for (let i = 0; i < count; i++) {
    const result = fw.check(req);
    assert.strictEqual(result, false);
  }
  const last = fw.check(req);
  assert.strictEqual(last, true);
});

test('If include whitelist, no block request', () => {
  const req = { url: '/admin', ip: '127.0.0.1' };
  const options = { maxReqCount: 0 };
  const fw = new Firewall(options);
  fw.addToWhiteList(req.ip);
  const result = fw.check(req);
  assert.strictEqual(result, false);
});

test('Whitelist priority than blacklist', () => {
  const req = { url: '/admin', ip: '127.0.0.1' };
  const options = { maxReqCount: 0 };
  const fw = new Firewall(options);
  fw.addToBlockList(req.ip);
  fw.addToWhiteList(req.ip);
  const result = fw.check(req);
  assert.strictEqual(result, false);
});

test('Non-Blocking IPv6 request', () => {
  const req = { url: '/home', ip: '::1' };
  const fw = new Firewall({ maxReqCount: 0 });
  const result = fw.check(req);
  assert.strictEqual(result, false);
});

test('Blocking IPv6 request', () => {
  const req = { url: '/admin', ip: '::1' };
  const fw = new Firewall({ maxReqCount: 0 });
  const result = fw.check(req);
  assert.strictEqual(result, true);
});

test('Initialization firewall', () => {
  const fw = new Firewall({ maxReqCount: 0 }).init(exampleData);
  for (const data of exampleData) {
    const { ip } = data;
    const res = fw.check({ url: '/home', ip });
    assert.strictEqual(res, true);
  }
});

test('Non-blocking interval request', async () => {
  const req = { url: '/admin', ip: '127.0.0.1' };
  const options = { maxReqCount: 3, reqInterval: 1000 };
  const fw = new Firewall(options);
  for (let i = 0; i <= options.maxReqCount; i++) {
    const result = fw.check(req);
    assert.strictEqual(result, false);
    await sleep(options.reqInterval + 50);
  }
});

test('Blocking interval request', async () => {
  const req = { url: '/admin', ip: '127.0.0.1' };
  const options = { maxReqCount: 1, reqInterval: 1000 };
  const fw = new Firewall(options);
  for (let i = 0; i < 3; i++) {
    const result = fw.check(req);
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
