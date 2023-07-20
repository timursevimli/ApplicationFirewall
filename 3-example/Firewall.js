'use strict';

const net = require('node:net');
const suspiciousUrls = require('../suspiciousUrls.js');

const MAX_REQ_COUNT = 5;
const REQ_INTERVAL_MS = 10000;

const getIPv = (ip) => {
  if (net.isIPv4(ip)) return 'ipv4';
  if (net.isIPv6(ip)) return 'ipv6';
};

const generateSuspicious = (data) => {
  if (typeof data === 'object') return data;
  const { ip } = data;
  return {
    ip,
    ipv: getIPv(ip),
    reqCount: 1,
    reqTime: Date.now(),
    banned: false
  };
};

class Firewall {
  constructor(options = {}) {
    this.maxReqCount = options.maxReqCount ?? MAX_REQ_COUNT;
    this.reqInterval = options.reqInterval ?? REQ_INTERVAL_MS;
    this.suspiciousUrls = options.urls ?? suspiciousUrls;
    this.suspiciousRequests = new Map();
    this.whiteList = new Set();
    this.blockList = new net.BlockList();
  }

  hasWhiteList(ip) {
    return this.whiteList.has(ip);
  }

  hasBlockList(ip, ipv) {
    return this.blockList.check(ip, ipv ?? getIPv(ip));
  }

  getSuspicious(ip) {
    return this.suspiciousRequests.get(ip);
  }

  isSuspicious(url) {
    return this.suspiciousUrls.includes(url);
  }

  isValidFormat(ip) {
    return !!getIPv(ip);
  }

  check({ url, ip }) {
    if (!this.isValidFormat(ip)) return false;
    if (this.hasWhiteList(ip)) return false;
    if (this.hasBlockList(ip)) return true;
    const suspicious = this.getSuspicious(ip);
    if (!this.isSuspicious(url) && !suspicious) return false;
    return suspicious ?
      this.handleExisting(suspicious) :
      this.handleNew(ip);
  }
  //TODO ban logic
  ban(suspicious) {
    suspicious.banned = true;
    const { ip, ipv } = suspicious;
    this.addToBlockList(ip, ipv);
    this.suspiciousRequests.delete(ip);
    return true;
  }

  handleExisting(suspicious) {
    if (suspicious.banned) {
      const { ip, ipv } = suspicious;
      return this.hasBlockList(ip, ipv) ? true : this.ban(suspicious);
    }
    const now = new Date().getTime();
    const lastReqTime = suspicious.reqTime;
    suspicious.reqTime = now;
    const diff = now - lastReqTime;
    if (diff <= this.reqInterval) suspicious.reqCount++;
    if (suspicious.reqCount <= this.maxReqCount) return false;
    return this.ban(suspicious);
  }

  handleNew(ip) {
    const suspicious = generateSuspicious({ ip });
    this.suspiciousRequests.set(ip, suspicious);
    if (suspicious.reqCount <= this.maxReqCount) return false;
    return this.ban(suspicious);
  }

  addToWhiteList(ip) {
    this.whiteList.add(ip);
  }

  addToBlockList(ip, ipv) {
    this.blockList.addAddress(ip, ipv ?? getIPv(ip));
  }

  init(datas) {
    for (const suspicious of datas) {
      this.suspiciousRequests.set(suspicious.ip, suspicious);
      this.handleExisting(suspicious);
    }
  }
}

module.exports = Firewall;
