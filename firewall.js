'use strict';

const { BlockList } = require('node:net');
const { getSuspiciousUrls, isValidFormat, getIPv } = require('./utils.js');

const MAX_REQ_COUNT = 5;
const REQ_INTERVAL_MS = 10000;

const generateSuspicious = (ip) => ({
  ip,
  ipv: getIPv(ip),
  reqCount: 1,
  reqTime: Date.now(),
});

class Firewall {
  constructor(options = {}) {
    this.maxReqCount = options.maxReqCount ?? MAX_REQ_COUNT;
    this.reqInterval = options.reqInterval ?? REQ_INTERVAL_MS;
    this.suspiciousUrls = options.urls ?? getSuspiciousUrls('default-urls.txt');
    this.suspiciousRequests = new Map();
    this.whiteList = new Set();
    this.blockList = new BlockList();
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

  check({ url, ip }) {
    if (!isValidFormat(ip)) return false;
    if (this.hasWhiteList(ip)) return false;
    if (this.hasBlockList(ip)) return true;
    const suspicious = this.getSuspicious(ip);
    if (!this.isSuspicious(url) && !suspicious) return false;
    return suspicious ? this.handleExisting(suspicious) : this.handleNew(ip);
  }

  ban(suspicious) {
    const { ip, ipv } = suspicious;
    this.addToBlockList(ip, ipv);
    this.suspiciousRequests.delete(ip);
    return true;
  }

  handleInit(suspicious) {
    if (this.maxRequestReached(suspicious)) return this.ban(suspicious);
    this.suspiciousRequests.set(suspicious.ip, suspicious);
  }

  maxRequestReached({ reqCount }) {
    return reqCount > this.maxReqCount;
  }

  handleExisting(suspicious) {
    const now = new Date().getTime();
    const lastReqTime = suspicious.reqTime;
    suspicious.reqTime = now;
    const diff = now - lastReqTime;
    if (diff <= this.reqInterval) suspicious.reqCount++;
    if (!this.maxRequestReached(suspicious)) return false;
    return this.ban(suspicious);
  }

  handleNew(ip) {
    const suspicious = generateSuspicious(ip);
    this.suspiciousRequests.set(ip, suspicious);
    if (!this.maxRequestReached(suspicious)) return false;
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
      this.handleInit(suspicious);
    }
    return this;
  }
}

module.exports = Firewall;
