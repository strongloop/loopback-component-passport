var uid = require('./models/user-identity');
exports.UserIdentity = uid.UserIdentity;
exports.UserCredential = uid.UserCredential;
exports.ApplicationCredential = require('./models/application-credential');

exports.UserIdentity.autoAttach = 'db';
exports.UserCredential.autoAttach = 'db';
exports.ApplicationCredential.autoAttach = 'db';

exports.PassportConfigurator = require('./passport-configurator');