'use strict';

const assert = require('node:assert');
const test = require('node:test');
const suspiciousUrls = require('../../suspiciousUrls.js');
const { firewall, initFirewall } = require('../firewall.js');
const BlockListManager = require('../BlockListManager.js');

const sleep = (msec) => new Promise((resolve) => setTimeout(resolve, msec));

test('Check suspicious urls', () => {
  let i = 0;
  const fw = firewall({ maxReqCount: 0 });
  for (const url of suspiciousUrls) {
    const req = { url, ip: `10.10.0.${i++}` };
    const result = fw(req);
    assert.strictEqual(result, true);
  }
});

test('Non-suspicious request', () => {
  const req = { url: '/home', ip: '127.0.0.0' };
  const fw = firewall();
  assert.strictEqual(fw(req), false);
});

test('Non-blocking request', () => {
  const req = { url: '/home', ip: '127.0.0.1' };
  const fw = firewall({ maxReqCount: 0 });
  const result = fw(req);
  assert.strictEqual(result, false);
});

test('Blocking request', () => {
  const req = { url: '/admin', ip: '127.0.0.2' };
  const fw = firewall({ maxReqCount: 0 });
  const result = fw(req);
  assert.strictEqual(result, true);
});

test('Requests with count', () => {
  const req = { url: '/admin', ip: '127.0.0.3' };
  const fw = firewall({ maxReqCount: 1 });
  const res1 = fw(req);
  const res2 = fw(req);
  assert.strictEqual(res1, false);
  assert.strictEqual(res2, true);
});

test('More requests with count', () => {
  const req = { url: '/admin', ip: '127.0.0.4' };
  const count = 1000;
  const fw = firewall({ maxReqCount: count });
  for (let i = 0; i < count; i++) {
    const result = fw(req);
    assert.strictEqual(result, false);
  }
  const last = fw(req);
  assert.strictEqual(last, true);
});

test('Blocklist for IPv4', () => {
  const req = { url: '/admin', ip: '127.0.0.5' };
  const blockList = new BlockListManager();
  const fw = firewall({ maxReqCount: 1 }, blockList);

  fw(req);
  const res1 = blockList.check(req.ip);
  assert.strictEqual(res1, false);

  fw(req);
  const res2 = blockList.check(req.ip);
  assert.strictEqual(res2, true);
});

test('Non-Blocking IPv6 request', () => {
  const req = { url: '/home', ip: '::1'  };
  const fw = firewall({ maxReqCount: 0 });
  const result = fw(req);
  assert.strictEqual(result, false);
});

test('Blocking IPv6 request', () => {
  const req = { url: '/admin', ip: '::2' };
  const fw = firewall({ maxReqCount: 0 });
  const result = fw(req);
  assert.strictEqual(result, true);
});

test('Blocklist for IPv6', () => {
  const req = { url: '/admin', ip: '::3' };
  const blockList = new BlockListManager();
  const fw = firewall({ maxReqCount: 1 }, blockList);

  fw(req);
  const res1 = blockList.check(req.ip, 'ipv6');
  assert.strictEqual(res1, false);

  fw(req);
  const res2 = blockList.check(req.ip, 'ipv6');
  assert.strictEqual(res2, true);
});

test('Initialization without of firewall data', () => {
  const now = Date.now();
  const data = [
    {
      ip: '1.1.1.1', ipv: 'ipv4', banned: true, count: 3,
      reqTime: now, blockEnd: now + 10000,
    },
    {
      ip: '1.1.1.2', ipv: 'ipv4', banned: true, count: 3,
      reqTime: now, blockEnd: now + 10000,
    },
    {
      ip: '::4', ipv: 'ipv6', banned: true, count: 3,
      reqTime: now, blockEnd: now + 10000,
    },
  ];

  initFirewall(data);

  const req1 = { url: '/home', ip: '1.1.1.1' };
  const req2 = { url: '/home', ip: '1.1.1.2'  };
  const req3 = { url: '/home', ip: '::4'  };

  const fw = firewall();

  const res1 = fw(req1);
  const res2 = fw(req2);
  const res3 = fw(req3);

  assert.strictEqual(res1, true);
  assert.strictEqual(res2, true);
  assert.strictEqual(res3, true);
});

test('Initialization with of firewall data', () => {
  const blockList = new BlockListManager();
  const now = Date.now();
  const data = [
    {
      ip: '1.1.1.3', ipv: 'ipv4', banned: true, count: 3,
      reqTime: now, blockEnd: now + 10000,
    },
    {
      ip: '1.1.1.4', ipv: 'ipv4', banned: true, count: 3,
      reqTime: now, blockEnd: now + 10000,
    },
    {
      ip: '::5', ipv: 'ipv6', banned: true, count: 3,
      reqTime: now, blockEnd: now + 10000,
    },
  ];

  initFirewall(data, blockList);

  const res1 = blockList.check('1.1.1.3');
  const res2 = blockList.check('1.1.1.4', 'ipv4');
  const res3 = blockList.check('::5', 'ipv6');

  assert.strictEqual(res1, true);
  assert.strictEqual(res2, true);
  assert.strictEqual(res3, true);
});

test('Add address to block list', () => {
  const blockList = new BlockListManager();
  blockList.addAddress('1.1.1.1');
  blockList.addAddress('::1', 'ipv6');
  const realBlockList = blockList.blockList;
  const res1 = realBlockList.rules.includes('Address: IPv4 1.1.1.1');
  const res2 = realBlockList.rules.includes('Address: IPv6 ::1');
  assert.strictEqual(res1, true);
  assert.strictEqual(res2, true);
});

test('Remove from block list', () => {
  const blockList = new BlockListManager();
  blockList.addAddress('1.1.1.1');
  assert.strictEqual(blockList.check('1.1.1.1'), true);
  blockList.removeAndUpdate('1.1.1.1');
  assert.strictEqual(blockList.check('1.1.1.1'), false);
});

test('Remove ban with timer', async () => {
  const req = { url: '/home', ip: '1.1.1.5' };
  const now = Date.now();
  const data = [{
    ip: '1.1.1.5', ipv: 'ipv4', banned: true, count: 3,
    reqTime: now, blockStart: now, blockEnd: now + 3000,
  }];

  const blockList = new BlockListManager();
  initFirewall(data, blockList);

  const fw = firewall(blockList);

  const before1 = blockList.check('1.1.1.5');
  const before2 = fw(req);

  assert.strictEqual(before1, true);
  assert.strictEqual(before2, true);

  await sleep(3100);

  const after1 = blockList.check('1.1.1.5');
  const after2 = fw(req);

  assert.strictEqual(after1, false);
  assert.strictEqual(after2, false);
});

test('Non-blocking interval request', async () => {
  const req = { url: '/admin', ip: '1.1.1.6'  };
  const config = { maxReqCount: 3, reqInterval: 1000 };
  const fw = firewall(config);
  for (let i = 0; i < config.maxReqCount + 1; i++) {
    const result = fw(req);
    assert.strictEqual(result, false);
    await sleep(1000);
  }
});

test('Blocking interval request', async () => {
  const req = { url: '/admin', ip: '1.1.1.7'  };
  const config = { maxReqCount: 1, reqInterval: 2000 };
  const fw = firewall(config);
  for (let i = 0; i < 3; i++) {
    const result = fw(req);
    if (i < config.maxReqCount) assert.strictEqual(result, false);
    else assert.strictEqual(result, true);
    await sleep(1000);
  }
});

test('End', () => {
  process.exit(0);
});
