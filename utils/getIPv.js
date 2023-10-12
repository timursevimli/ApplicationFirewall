'use strict';

const net = require('node:net');

const getIPv = (ip) => {
  if (net.isIPv4(ip)) return 'ipv4';
  if (net.isIPv6(ip)) return 'ipv6';
};

module.exports = { getIPv };
