'use strict';

const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');

const getIPv = (ip) => {
  if (net.isIPv4(ip)) return 'ipv4';
  if (net.isIPv6(ip)) return 'ipv6';
};

const isValidFormat = (ip) => !!getIPv(ip);

const getSuspiciousUrls = (file) => {
  const filePath = path.join(process.cwd(), file);
  const data = fs.readFileSync(filePath, 'utf8');
  const lines = data.split('\n').filter((s) => !!s);
  const urls = [];
  for (const line of lines) {
    if (!line.startsWith('/')) continue;
    urls.push(line);
  }
  return urls;
};

module.exports = {
  getSuspiciousUrls,
  getIPv,
  isValidFormat,
};
