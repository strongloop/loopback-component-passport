exports.UserIdentity = require('./models/user-identity').UserIdentity;
exports.UserCredential = require('./models/user-identity').UserCredential;
exports.ApplicationCredential = require('./models/application-credential');

exports.UserIdentity.autoAttach = 'db';
exports.UserCredential.autoAttach = 'db';
exports.ApplicationCredential.autoAttach = 'db';
