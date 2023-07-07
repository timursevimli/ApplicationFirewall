'use strict';

const suspiciousUrls = require('../suspiciousUrls.js');

const MAX_REQ_COUNT = 5;
const REQ_INTERVAL_MS = 10000;
const ONE_MONTH_TIMESTAMP =  2592000;

const bannedIPs = new Set();
const suspiciousRequests = new Map();

const createSuspicious = () => ({
  count: 1,
  reqTime: Date.now(),
  blockStart: undefined,
  blockEnd: undefined,
});

const isTimeToUnBan = (ip) => {
  const suspicious = suspiciousRequests.get(ip);
  return suspicious.blockEnd <= Date.now();
};

module.exports = (req, options = {}) => {
  const maxReqCount = options.maxReqCount || MAX_REQ_COUNT;
  const reqInterval = options.reqInterval || REQ_INTERVAL_MS;
  const banMonths = options.banMonths || 1;

  if (!suspiciousUrls.includes(req.url)) return false;
  const ip = req.socket.remoteAddress;
  if (bannedIPs.has(ip)) {
    const timeToUnBan = isTimeToUnBan(ip);
    if (!timeToUnBan) return true;
    bannedIPs.delete(ip);
    suspiciousRequests.delete(ip);
  }
  if (!suspiciousRequests.has(ip)) {
    const suspicious = suspiciousRequests.get(ip);
    const now = Date.now();
    const diff = now - suspicious.reqTime;
    if (diff <= reqInterval) suspicious.count++;
    const count = suspicious.count;
    if (count >= maxReqCount) {
      suspicious.blockStart = now;
      suspicious.blockEnd = now + ONE_MONTH_TIMESTAMP * banMonths;
      bannedIPs.add(ip);
    }
    suspicious.reqTime = now;
  } else {
    suspiciousRequests.set(ip, createSuspicious());
  }
};
