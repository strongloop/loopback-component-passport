# loopback-component-passport

**NOTE: This module supersedes [loopback-passport](https://www.npmjs.org/package/loopback-passport). Please update your package.json accordingly.**

The module provides integration between [LoopBack](http://loopback.io) and
[Passport](http://passportjs.org) to support third-party login and account 
linking for LoopBack applications.

<img src="./ids_and_credentials.png" width="600px" />

> Please see the [official documentation](http://docs.strongloop.com/pages/viewpage.action?pageId=3836277) for more information.

## All local accounts requires verification

### All third party accounts will login with an email of `uniqueID@loopback.provider.com` example `123456@loopback.facebook.com`

which will allow the user to link the social media accounts that they want as well as the users could sign up with the same email account that is used for facebook/twitter/google/local if they wish to keep them separate.

If more info is required from the Facebook profile such as email, it could still be obtained. In `node_modules\passport-facebook\lib\strategy.js`, replace:

```
this._profileURL = options.profileURL || 'https://graph.facebook.com/me';
```

with

```
this._profileURL = options.profileURL ||
    'https://graph.facebook.com/v2.2/me?fields=first_name,gender,last_name,link,locale,name,timezone,verified,email,updated_time';
```

All user required info including the email will be available, but the main email for the account will remain `uniqueID@loopback.facebook.com`.
