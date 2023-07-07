'use strict';

const BlockListManager = require('./BlockListManager.js');
const Suspicious = require('./Suspicious.js');
const suspiciousUrls = require('../suspiciousUrls.js');
const suspiciousRequests = require('./suspiciousRequests.js');

const MAX_REQ_COUNT = 5;
const REQ_INTERVAL_MS = 10000;

// TODO: If unblock req without timer, check timer and remove from timers
const createTimers = () => {
  const timers = [];
  return (fn, msec, ...args) =>  {
    const timer = setTimeout(() => {
      fn(...args);
      const index = timers.indexOf(timer);
      if (index > -1) timers.splice(index, 1);
    }, msec);
    timers.push(timer);
  };
};

const timerHandler = createTimers();

const createStub = (instance) => {
  const stub = Object.create(null);
  const proto = Object.getPrototypeOf(instance);
  const methods = Object.getOwnPropertyNames(proto);
  methods.forEach((method) => stub[method] = () => {});
  return stub;
};

const blockListValidate = (blockList) => {
  if (!blockList) return createStub(new BlockListManager());
  if (blockList instanceof BlockListManager) return blockList;
  throw new Error('Firewall only works with BlockListManager instance');
};

const initFirewall = (datas, blockList) => {
  const validatedBList = blockListValidate(blockList);
  for (const data of datas) {
    const suspicious = new Suspicious(data);
    const { ip, ipv } = suspicious;
    const timeToUnban = suspicious.isReadyToUnban();
    if (!timeToUnban) {
      suspiciousRequests.set(ip, suspicious);
      validatedBList.addAddress(ip, ipv);
      const timer = () => {
        if (suspiciousRequests.has(ip)) {
          suspiciousRequests.delete(ip);
        }
        if (validatedBList.check(ip, ipv)) {
          validatedBList.removeAndUpdate(ip, ipv);
        }
      };
      timerHandler(timer, suspicious.getRemainingBanTime());
    }
  }
};

const firewall = (options = {}, blockList) => {
  const validatedBList = blockListValidate(blockList);

  const {
    maxReqCount = MAX_REQ_COUNT,
    reqInterval = REQ_INTERVAL_MS,
    banMonths = 1
  } = options;

  const interceptor = ({ url, ip }) => {
    const suspicious = suspiciousRequests.get(ip);
    if (!suspiciousUrls.includes(url) && !suspicious) return false;
    if (suspicious)  {
      const now = new Date().getTime();
      const reqTime = suspicious.getReqTime();
      suspicious.updateReqTime();
      if (suspicious.isBanned()) {
        if (!suspicious.isReadyToUnban()) return true;
        suspiciousRequests.delete(ip);
        validatedBList.removeAndUpdate(ip, suspicious.ipv);
        return interceptor({ url, ip });
      }
      const diff = now - reqTime;
      if (diff <= reqInterval) suspicious.incCount();
      if (suspicious.getReqCount() >= maxReqCount) {
        suspicious.ban(banMonths);
        validatedBList.addAddress(ip, suspicious.ipv);
        const timer = () => {
          if (suspiciousRequests.has(ip)) {
            suspiciousRequests.delete(ip);
          }
          if (validatedBList.check(ip, suspicious.ipv)) {
            validatedBList.removeAndUpdate(ip, suspicious.ipv);
          }
        };
        timerHandler(timer, suspicious.getRemainingBanTime());
        return true;
      }
    } else {
      const suspicious = new Suspicious({ ip });
      suspiciousRequests.set(ip, suspicious);
      if (suspicious.getReqCount() >= maxReqCount) {
        suspicious.ban(banMonths);
        validatedBList.addAddress(ip, suspicious.ipv);
        const timer = () => {
          if (suspiciousRequests.has(ip)) {
            suspiciousRequests.delete(ip);
          }
          if (validatedBList.check(ip, suspicious.ipv)) {
            validatedBList.removeAndUpdate(ip, suspicious.ipv);
          }
        };
        timerHandler(timer, suspicious.getRemainingBanTime());
        return true;
      }
    }
    return false;
  };
  return interceptor;
};

module.exports = { firewall, initFirewall };
