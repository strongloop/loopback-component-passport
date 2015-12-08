# All local accounts requires verification. 
###In order to let third party accounts to login with an email of "uniqueID@loopback.provider.com" example "123456@loopback.twitter.com" 

> In .lib/models/user-identity.js
Replace 
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

###Assuming the client wants to get more info from the facebook profile or google profile. For example, the client modifies node_modules\passport-facebook\lib\strategy.js to use 

'https://graph.facebook.com/v2.2/me?fields=first_name,gender,last_name,link,locale,name,timezone,verified,email,updated_time'
they can get all user required info including the email, but the main email for the account will remain "uniqueID@loopback.faceboo.com"
