var loopback = require('loopback');
module.exports = require('../lib/index');

// setup default data sources
loopback.setDefaultDataSourceForType('db', {
  connector: loopback.Memory
});

loopback.setDefaultDataSourceForType('mail', {
  connector: loopback.Mail,
  transports: [
    {type: 'STUB'}
  ]
});

// auto attach data sources to models
loopback.autoAttach();