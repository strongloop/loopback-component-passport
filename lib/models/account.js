'use strict';

function getUrl(env, settings) {
  return !settings.clientPort ? `${settings.clientHost}` : `${settings.clientHost}:${settings.clientPort}`;
}

module.exports = function(Account) {
  Account.on('resetPasswordRequest', (info) => {

    let url = getUrl(process.env.NODE_ENV, Account.app.locals.settings);

    // info.email - the email of the requested user
    // info.accessToken.id - the temp access token to allow password reset

    if (info.email && info.accessToken.id) {

      url = `${url}/forgot/${info.accessToken.id}`;
      url = `We heard that you lost your MEVRIS password. Sorry about that! But don’t worry! You can use the following link to reset your password:<a href="${url}">Click this link !</a>`;
      Account.sendEmail(info.email, 'MEVRIS Reset Password', '', url, (err, response) => {
        console.log(err, response);
      });
    }
  });

  Account.sendEmail = function(to, subject, body, html, cb) {
    Account.app.models.Email.send({
      to,
      subject,
      text: body,
      html
    }, (err, mail) => {
      if (err) return cb(err);
      return cb(null, 'Email sent');
    });
  };

  Account.botLogin = function(botId, cb) {
    Account.app.models.SocialAccount.find({ where: { socialId: botId } }, (err, res) => {
      if (err) {
        cb(err, null);
      } else if (res && res.length > 0) {

        const accountId = res[0].accountId;

        Account.app.models.CustomAccessToken.create({ userId: accountId, principalType: 'Account' },
          (err, res) => { cb(err, res); });
      } else {
        cb(null, '');
      }
    });
  };

  Account.remoteMethod('botLogin', {
    accepts: [
      { arg: 'botId', type: 'string', required: true },
    ],
    returns: { arg: 'accessToken', type: 'string' }
  });
};
