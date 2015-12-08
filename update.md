# In order NOT to have 2 accounts with duplicate emails 
**Third party accounts will login with an email of "uniqueID@loopback.provider.com" example "123456@loopback.twitter.com" 

> In .lib/models/user-identity.js
is replaced 
```
   var email = profile.emails && profile.emails[0] && profile.emails[0].value;
    if (!email && !options.emailOptional) {
      // Fake an e-mail
      email = (profile.username || profile.id) + '@loopback.' +
              (profile.provider || provider) + '.com';
    }
```
with
```
     var  email = (profile.username || profile.id) + '@loopback.' +
              (profile.provider || provider) + '.com'; 
```
which will allow the user to link the social media accounts that they want as well as the users could sign up with 4 different accounts using the same email for facebook/twitter/google/local if they wish to keep them separate. 

###If info is required from the Facebook profile such as email, it could still be obtained. In node_modules\passport-facebook\lib\strategy.js , replace 
```
this._profileURL = options.profileURL || 'https://graph.facebook.com/me';
```
with 
```
this._profileURL = options.profileURL ||'https://graph.facebook.com/v2.2/me?fields=first_name,gender,last_name,link,locale,name,timezone,verified,email,updated_time'
```
All user required info including the email will be available, but the main email for the account will remain "uniqueID@loopback.facebook.com"
