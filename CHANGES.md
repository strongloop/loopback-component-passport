2016-03-18, Version 2.1.0
=========================

 * Update deps (Raymond Feng)

 * Fix email validation for LDAP issue 1963 (Loay Gewily)

 * Fix getting AuthStrategy directly from package when Strategy key is not here (Steve Grosbois)

 * Make `username` field optional in UserIdentity.login method (Vladimir Shushkov)

 * Throw softer error in `local` stragegy when trying to create `accessToken` with `"setAccessToken": true` option. In case when reason is wrong user password. (Vladimir Shushkov)

 * The name of provider can be configured in options. (Clark Wang)

 * Avoid duplicate user identities (Clark Wang)


2016-01-11, Version 2.0.0
=========================

 * Fix version Number Revert to proper version number (Loay Gewily)

 * Use Auto-generated email Using auto-generated email for 3rd party accounts & update version# (Loay Gewily)

 * Enforce email verification for local accounts (Loay Gewily)


2015-11-04, Version 1.6.0
=========================

 * Refer to licenses with a link (Sam Roberts)

 * Use strongloop conventions for licensing (Sam Roberts)

 * feature add failureFlash on link errors (Berkeley Martinez)

 * limit options to post and get and default to get (Jose Garcia)

 * customize callback HTTP method (Jose Garcia)

 * session.redirectTo erase after successful redirect (liba)

 * adding dynamic redirect after successful login (liba)

 * Fixed suspected typo in passport-configurator (Samuel Gaus)

 * Customize cookie for use with subdomain (Pongstr)

 * compatible with wechat's openid (Yorkie Liu)


2015-06-24, Version 1.5.0
=========================

 * Register passport with session:after phase (Raymond Feng)

 * Make sure passport is registered with session phase (Raymond Feng)

 * Error condition would yield multiple callbacks (Jonathan Sheely)


2015-06-17, Version 1.4.0
=========================

 * Make email optional (Berkeley Martinez)


2015-06-02, Version 1.3.1
=========================

 * Fix the maxAge for cookies (Raymond Feng)

 * Reformat code (Raymond Feng)


2015-04-22, Version 1.3.0
=========================

 * Update README.md (Rand McKinney)

 * 401 instead of redirect to failure (Pierre Gambarotto)

 * rename variables to camlCase form (Pierre Gambarotto)

 * ldap authentication (Pierre Gambarotto)


2015-03-08, Version 1.2.0
=========================

 * Update deps (Raymond Feng)

 * resolves inconsistency of info.accessToken.ttl (which is in seconds) and maxAge of res.cookie (which is in milliseconds) (Andrey Loukhnov)

 * support use of custom function for creating access token (Vine Brancho)

 * added support for username and email for logging in with local auth strategy (britztopher)


2015-01-13, Version 1.1.2
=========================

 * allow custom loginCallback function (Clark Wang)


2015-01-09, Version 1.1.1
=========================

 * Add timestamp (Raymond Feng)

 * AuthInfo must be enabled in order to pass the token on. (csvan)

 * Enable option for creating access token in conjunction with local login. (csvan)

 * Fix bad CLA URL in CONTRIBUTING.md (Ryan Graham)


2014-11-21, Version 1.1.0
=========================

 * Format the code (Raymond Feng)

 * Fix behaviour for custom user model, remove debug output (Pandaiolo)

 * Compliance with loopback 2.x models declaration (Pandaiolo)

 * Add contribution guidelines (Ryan Graham)

 * Use html to scale image (Rand McKinney)

 * Scale image (Rand McKinney)

 * Replace README with link to docs. (Rand McKinney)

 * Move the callback scope up one level so that customCallback option has access to res and req. Otherwise it's impossible to do anything like redirects within it. (Frank Carey)


2014-08-26, Version 1.0.6
=========================

 * Bump version (Raymond Feng)

 * Allow other option properties to pass through (Raymond Feng)


2014-07-31, Version 1.0.5
=========================

 * Bump version (Raymond Feng)

 * Allow LB user record to receive additional properties from social profile. Signed-off-by: Michael Lee <michael.lee@alumni.purdue.edu> (Michael Lee)

 * Add support for loopback 2.x (João Ribeiro)

 * Add support for noSession and JSON response (João Ribeiro)


2014-07-02, Version 1.0.4
=========================

 * Bump version (Raymond Feng)

 * Fix the cookie name for access token (Raymond Feng)


2014-07-01, Version 1.0.3
=========================

 * Bump version (Raymond Feng)

 * Rename loopback-passport to loopback-component-passport (Raymond Feng)


2014-06-27, Version 1.0.2
=========================

 * Bump version (Raymond Feng)

 * Fix #5 Signed-off-by: Alex <dtk077@gmail.com> (Alex P)

 * Pass-through successReturnToOrRedirect option (Fabien Franzen)

 * Handle passport-local form credentials POST - return passport instance from init() (Fabien Franzen)

 * Final fix up of JSDocs (crandmck)

 * Initial cleanup of JSDocs (crandmck)

 * Guess the authentication scheme (Raymond Feng)


2014-05-30, Version 1.0.1
=========================

 * Bump version (Raymond Feng)

 * Created a dummy e-mail if not present from the profile (Raymond Feng)


2014-05-29, Version 1.0.0
=========================

 * First release!
