var loopback = require('loopback');
var DataModel = loopback.PersistedModel || loopback.DataModel;

function loadModel(jsonFile) {
  var modelDefinition = require(jsonFile);
  return DataModel.extend(modelDefinition.name,
    modelDefinition.properties,
    {
      relations: modelDefinition.relations
    });
}

var UserIdentityModel = loadModel('./models/user-identity.json');
var UserCredentialModel = loadModel('./models/user-credential.json');
var ApplicationCredentialModel = loadModel('./models/application-credential.json');

exports.UserIdentity = require('./models/user-identity')(UserIdentityModel);
exports.UserCredential = require('./models/user-credential')(UserCredentialModel);
exports.ApplicationCredential = require('./models/application-credential')(ApplicationCredentialModel);

exports.UserIdentity.autoAttach = 'db';
exports.UserCredential.autoAttach = 'db';
exports.ApplicationCredential.autoAttach = 'db';

exports.PassportConfigurator = require('./passport-configurator');
