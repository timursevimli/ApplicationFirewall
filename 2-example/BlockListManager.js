'use strict';

const { BlockList } = require('node:net');

class BlockListManager {
  constructor(rules) {
    this.blockList = new BlockList();
    this.rules = rules || [];
    this.update();
  }

  check(ip, ipv = 'ipv4') {
    return this.blockList.check(ip, ipv);
  }

  addAddress(ip, ipv = 'ipv4') {
    this.blockList.addAddress(ip, ipv);
    this.rules.push(ip + ' ' + ipv);
  }

  update() {
    this.blockList = new BlockList();
    const { rules } = this;
    if (rules.length > 0) {
      for (const rule of rules) {
        const [ip, ipv] = rule.split(' ');
        this.blockList.addAddress(ip, ipv);
      }
    }
  }

  removeAddress(ip, ipv = 'ipv4') {
    const index = this.rules.indexOf(ip + ' ' + ipv);
    if (index > -1) {
      this.rules.splice(index, 1);
      return true;
    }
    return false;
  }

  removeAndUpdate(ip, ipv = 'ipv4') {
    const removed = this.removeAddress(ip, ipv);
    if (removed) this.update();
  }
}

module.exports = BlockListManager;
