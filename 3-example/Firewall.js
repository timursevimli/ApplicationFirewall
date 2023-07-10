'use strict';

const { BlockList } = require('node:net');
const suspiciousUrls = require('../suspiciousUrls.js');

const MAX_REQ_COUNT = 5;
const REQ_INTERVAL_MS = 10000;

const createStub = (instance) => {
  const stub = Object.create(null);
  const proto = Object.getPrototypeOf(instance);
  const methods = Object.getOwnPropertyNames(proto);
  methods.forEach((method) => stub[method] = () => {});
  return stub;
};

const blockListValidate = (blockList) => {
  if (!blockList) return createStub(new BlockList());
  if (blockList instanceof BlockList) return blockList;
  throw new Error('Firewall only works with BlockList instance');
};

const generateSuspicious = ({ ip, ipv, reqCount, reqTime, banned }) => ({
  ip, ipv: ipv ? ipv : ip.includes(':') ? 'ipv6' : 'ipv4',
  reqCount: reqCount || 1,
  reqTime: reqTime || Date.now(),
  banned: banned || false,
});

class Firewall {
  constructor(options = {}, blockList) {
    this.maxReqCount = options.maxReqCount ?? MAX_REQ_COUNT;
    this.reqInterval = options.reqInterval ?? REQ_INTERVAL_MS;
    this.suspiciousUrls = options.urls ?? suspiciousUrls;
    this.blockList = blockListValidate(blockList);
    this.whiteList = new Set();
    this.suspiciousRequests = new Map();
    this.suspiciousUrls = options.urls ?? suspiciousUrls;
    this.createSuspicious = (data) => generateSuspicious(data);
  }

  interceptor({ url, ip }) {
    if (this.whiteList.has(ip)) return false;
    const ipv = ip.includes(':') ? 'ipv6' : 'ipv4';
    const blocked = this.blockList.check(ip, ipv);
    if (blocked) return true;
    const suspicious = this.suspiciousRequests.get(ip);
    if (!this.suspiciousUrls.includes(url) && !suspicious) return false;
    return suspicious ?
      this.handleExistingSuspicious(suspicious) :
      this.handleNewSuspicious(ip);
  }

  banSuspicious(suspicious) {
    suspicious.banned = true;
    const { ip, ipv } = suspicious;
    this.blockList.addAddress(ip, ipv);
    return true;
  }

  handleExistingSuspicious(suspicious) {
    if (suspicious.banned) return true;
    const now = new Date().getTime();
    const lastReqTime = suspicious.reqTime;
    suspicious.reqTime = now;
    const diff = now - lastReqTime;
    if (diff <= this.reqInterval) suspicious.reqCount++;
    if (suspicious.reqCount <= this.maxReqCount) return false;
    return this.banSuspicious(suspicious);
  }

  handleNewSuspicious(ip) {
    const suspicious = this.createSuspicious({ ip });
    this.suspiciousRequests.set(ip, suspicious);
    if (suspicious.reqCount <= this.maxReqCount) return false;
    return this.banSuspicious(suspicious);
  }

  addAddressToWhiteList(address) {
    this.whiteList.add(address);
  }

  initFirewall(datas) {
    for (const data of datas) {
      const suspicious = this.createSuspicious(data);
      const { ip, ipv } = suspicious;
      this.suspiciousRequests.set(ip, suspicious);
      this.blockList.addAddress(ip, ipv);
    }
  }
}

module.exports = Firewall;
