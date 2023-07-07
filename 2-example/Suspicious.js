'use strict';

const ONE_MONTH_TIMESTAMP =  2592000;

class Suspicious {
  constructor({ ip, ipv, count, reqTime, blockEnd, banned }) {
    this.ip = ip;
    this.ipv = ipv ? ipv : ip.includes(':') ? 'ipv6' : 'ipv4';
    this.count = count || 0;
    this.reqTime = reqTime || Date.now();
    this.blockEnd = blockEnd || undefined;
    this.banned = banned || false;
  }

  getReqCount() {
    return this.count;
  }

  getReqTime() {
    return this.reqTime;
  }

  getRemainingBanTime() {
    return this.blockEnd - new Date().getTime();
  }

  isBanned() {
    return this.banned;
  }

  ban(months = 0) {
    const now = new Date().getTime();
    this.banned = true;
    this.unBlockTs = now + ONE_MONTH_TIMESTAMP * months;
    // this.blockEnd = now + 10000 + months; // Use for tests!
  }

  updateReqTime() {
    this.reqTime = new Date().getTime();
  }

  incCount() {
    this.count++;
  }

  isReadyToUnban() {
    return this.blockEnd <= new Date().getTime();
  }
}

module.exports = Suspicious;
