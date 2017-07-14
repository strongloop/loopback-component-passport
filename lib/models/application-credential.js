// Copyright IBM Corp. 2014,2016. All Rights Reserved.
// Node module: loopback-component-passport
// This file is licensed under the Artistic License 2.0.
// License text available at https://opensource.org/licenses/Artistic-2.0

'use strict';
var utils = require('./utils');

module.exports = ApplicationCredential;

/**
 * @class
 * @classdesc Credentials associated with the LoopBack client application, such as oAuth 2.0
 * client ID/secret, or SSL keys
 *
 * @param{String} provider: The auth provider name, such as facebook, google, twitter, linkedin
 * @param{String} authScheme: The auth scheme, such as oAuth, oAuth 2.0, OpenID, OpenID Connect
 * @param{Object} credentials: Provider-specific credentials.  Actual properties depend on scheme being used:
 *
 *   - openId: {returnURL: String, realm: String}
 *   - oAuth2: {clientID: String, clientSecret: String, callbackURL: String}
 *   - oAuth: {consumerKey: String, consumerSecret: String, callbackURL: String}
 * @param{Date} created: The created date
 * @param{Date} modified: The last modified date
 * @inherits {DataModel}
 */
function ApplicationCredential(ApplicationCredential) {
  /**
  * Link a third-party application credential with the LoopBack application.
  * @param {String} appId The LoopBack application iID.
  * @param {String} provider The third party provider name.
  * @param {String} authScheme The authentication scheme.
  * @param {Object} credentials Credentials for the given scheme.
  * @callback {Function} cb The callback function.
  * @param {Error|String} err The error object or string.
  * @param {Object} user The user object.
  * @param {Object} [info] The auth info object.
  *
  * -  identity: UserIdentity object
  * -  accessToken: AccessToken object
  */
  ApplicationCredential.link = function(appId, provider, authScheme, credentials, cb) {
    var appCredentialModel = utils.getModel(this, ApplicationCredential);
    appCredentialModel.findOne({where: {
      appId: appId,
      provider: provider,
    }}, function(err, extCredential) {
      if (err) {
        return cb(err);
      }

      var date = new Date();
      if (extCredential) {
        // Find the app for the given extCredential
        extCredential.credentials = credentials;
        return extCredential.updateAttributes({
          credentials: credentials, modified: date}, cb);
      }

      // Create the linked account
      appCredentialModel.create({
        provider: provider,
        authScheme: authScheme,
        credentials: credentials,
        appId: appId,
        created: date,
        modified: date,
      }, function(err, i) {
        cb(err, i);
      });
    });
  };
  return ApplicationCredential;
};
