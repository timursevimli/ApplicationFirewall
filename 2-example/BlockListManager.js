'use strict';

const { BlockList } = require('node:net');

class BlockListManager {
  constructor(rules) {
    this.blockList = new BlockList();
    if (rules) this.update(rules);
  }

  check(ip, ipv = 'ipv4') {
    return this.blockList.check(ip, ipv);
  }

  addAddress(ip, ipv = 'ipv4') {
    this.blockList.addAddress(ip, ipv);
  }

  update(rules) {
    this.blockList = new BlockList();
    if (rules.length > 0) {
      for (const rule of rules) {
        const [ipv, ip] = rule.split(' ').slice(1);
        this.blockList.addAddress(ip, ipv.toLowerCase());
      }
    }
  }

  removeAddress(ip, ipv = 'ipv4') {
    const hasRule = this.check(ip, ipv);
    if (!hasRule) return;
    const { rules } = this.blockList;
    const newRules = rules.filter((rule) => !rule.includes(ip));
    this.update(newRules);
  }
}

module.exports = BlockListManager;
