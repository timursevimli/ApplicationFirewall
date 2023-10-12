'use strict';

const { getIPv } = require('./getIPv');

const isValidFormat = (ip) => !!getIPv(ip);

module.exports = { isValidFormat };
