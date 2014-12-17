var passport = require('passport');
var extend = require('extend');
var LocalStrategy = require('passport-local').Strategy;
var auth = require('./auth');
var util = require('./util');

module.exports = function(options) {
  var localOptions = extend(true, { passReqToCallback: true, usernameField: 'email' }, options.passport);

  // Local Strategy
  passport.use(new LocalStrategy(localOptions,
    function(req, email, password, done) {
      var model = req.getModel();
      var query = { $limit: 1 };
      query['local.email'] = email.toLowerCase();
      var $userQuery = model.query(options.collection, query);

      model.fetch($userQuery, function(err) {
        if (err) { return done(err); }

        var user = $userQuery.get()[0];

        if (!user) {
          return done(null, false, { email: 'Email is not registered' });
        }

        //re-salt legacy password hashes (we only get here if the legacy password worked)
        if (user.local.salt.length == 10) {
          var passwordHash = util.encryptLegacyPassword(password, user.local.salt);
          if (user.local.passwordHash !== passwordHash) {
            return done(null, false, { password: 'Incorrect password' });
          }
          var salt = util.makeSecureSalt();
          util.makeSecureHash(password, salt, function (err, hash) {
            model.set('auths.' + user.id + '.local.salt', salt);
            model.set('auths.' + user.id + '.local.passwordHash', hash);
            return done(null, user);
          });
        } else {
          util.compareSecureHash(password, user.local.passwordHash, function (err, res) {
            if (res == false) {
              return done(null, false, { password: 'Incorrect password' });
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