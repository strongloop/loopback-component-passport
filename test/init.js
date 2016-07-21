// Copyright IBM Corp. 2014,2016. All Rights Reserved.
// Node module: loopback-component-passport
// This file is licensed under the Artistic License 2.0.
// License text available at https://opensource.org/licenses/Artistic-2.0

'use strict';
var loopback = require('loopback');
module.exports = require('../lib/index');

// setup default data sources
loopback.setDefaultDataSourceForType('db', {
  connector: loopback.Memory,
});

loopback.setDefaultDataSourceForType('mail', {
  connector: loopback.Mail,
  transports: [
    {type: 'STUB'},
  ],
});

// auto attach data sources to models
loopback.autoAttach();
