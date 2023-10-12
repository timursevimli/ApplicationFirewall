'use strict';

module.exports = {
  ...require('./getSuspiciousUrls.js'),
  ...require('./isValidFormat.js'),
  ...require('./getIPv.js'),
};
