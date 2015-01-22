var passport = require('passport');
var extend = require('extend');
var LocalStrategy = require('passport-local').Strategy;
var auth = require('./auth');
var util = require('./util');

module.exports = function(options) {
  var localOptions = extend(true, { passReqToCallback: true, usernameField: 'email' }, options.passport);
  var errorMessage = 'Incorrect username or password';

  // Local Strategy
  passport.use('local', new LocalStrategy(localOptions,
    function(req, email, password, done) {
      var model = req.getModel();
      var query = { $limit: 1 };
      query['local.email'] = email.toLowerCase();
      var $userQuery = model.query(options.collection, query);

      model.fetch($userQuery, function(err) {
        if (err) { return done(err); }

        var user = $userQuery.get()[0];

        if (!user) {
          /*
            The hashing routine is set to take about 1500 ms
            We use a setTimeout below to replicate that.
            Otherwise, we return almost immediately on a bad username and much more slowly on a bad password
            This way, we make it harder to tell which field has been set incorrectly
          */
          return setTimeout(function () {
            done(null, false, { signinError: errorMessage });
          }, 1500);
        }

        if (user.local.salt.length == 10) {  //... they were hashed under the old scheme
          var passwordHash = util.encryptLegacyPassword(password, user.local.salt);
          if (user.local.passwordHash !== passwordHash) {
            return done(null, false, { signinError: errorMessage });
          }
          //they've got this far, they've been authed under the legacy hash, now generate a new hash
          var salt = util.makeSecureSalt();
          util.makeSecureHash(password, salt, function (err, hash) {
            //store...
            model.set('auths.' + user.id + '.local.salt', salt);
            model.set('auths.' + user.id + '.local.passwordHash', hash);
            //now proceed with login
            return done(null, user);
          });
        } else {  //auth under bcrypt
          util.compareSecureHash(password, user.local.passwordHash, function (err, res) {
            if (res == false) {
              return done(null, false, { signinError: errorMessage });
            } else {
              return done(null, user);
            }
          });
        }
      });
    }
  ));

  // Strategies
  for (var name in options.strategies) {
    var strategyObj = options.strategies[name];
    var conf = extend(true, {passReqToCallback: true}, strategyObj.conf);

    passport.use(new strategyObj.strategy(conf, function(req, accessToken, refreshToken, profile, done) {
      var model = req.getModel();
      var query = { $limit: 1 };
      query[profile.provider + '.id'] = profile.id;
      var $providerQuery = model.query(options.collection, query);

      var $user = model.at(options.collection + '.' + req.session.userId);

      model.fetch($providerQuery, $user, function(err) {
        if (err) return done(err);

        var user = $providerQuery.get()[0];
        if (user && user[profile.provider]) {
          return auth.login(user, req, done);
        }

        profile.accessToken = accessToken;
        profile.refreshToken = refreshToken;
        auth.registerProvider($user, profile.provider, profile, req, null, done);
      });
    }));
  }
}