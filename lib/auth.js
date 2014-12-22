var passport = require('passport');
var util = require('./util');

var options = null;

module.exports = {
  init: init,
  changePassword: changePassword,
  login: login,
  register: register,
  registerProvider: registerProvider,
  sendPasswordReset: sendPasswordReset,
  getResetUser: getResetUser,
  resetPassword: resetPassword
}

function init(opts) {
  options = opts;
}

function changePassword(oldpassword, password, userId, model, done) {
  var $user = model.at(options.collection + '.' + userId);
  model.fetch($user, function(err) {
    if (err) return done(err);

    var user = $user.get();
    if (!user) {
      return done('You are not registered');
    }

    if (!user.local) {
      return done('You are not registered with password')
    }

    //check the old password
    util.compareSecureHash(oldpassword, user.local.passwordHash, function (err, res) {
      if (res == false) {
        return done({ oldpassword: 'Incorrect Old Password' });
      } else {
        var salt = util.makeSecureSalt();
        util.makeSecureHash(password, salt, function (err, hash) {
          $user.set('local.salt', salt);
          $user.set('local.passwordHash', hash, function(err) {
            if (err) return done(err);
            return done();
          });
        });
      }
    });
  });
}

function login(user, req, done) {
  req.session.userId = user.id;
  var model = req.getModel();
  if (typeof user.courses != 'undefined') {
    var key = Object.keys(model.get('auths'))[0];
    var query = { $limit: 1 };
    query['local.email'] = user.email;
    var $userQuery = model.query(options.collection, query);
    var $user = model.at(options.collection + '.' + user.id);
    model.fetch($user, function (err) {
      $user.set('courses', user.courses);
      if (req.isAuthenticated()) {
        done(null, user);
      } else {
        req.login(user, function(err) {
          if (err) return done(err);
          done(null, user);
        });
      }
    });
  }
}

function registerProvider($user, provider, profile, req, res, done, courseData) {
  var callback = function() {
    if (options.passport.registerCallback) {
      options.passport.registerCallback(req, res, $user.get(), function() {
        login($user.get(), req, done);
      });
    } else {
      login($user.get(), req, done);
    }
  }
  var user = $user.get();

  if (user) {
    $user.set(provider, profile, function(err) {
      if (err) return done(err);
      if (courseData) {
        $user.set('firstName', courseData.firstName);
        $user.set('lastName', courseData.lastName);
        if (courseData.courses) {
          $user.set('courses', courseData.courses);
        }
      }
      $user.set('timestamps.registered', +new Date(), callback);
    });
  /*} if (options.localFirst && provider !== 'local') {
    done(null, null, {});*/
  } else {
    var model = req.getModel();
    user = {
      id: model.id(),
      timestamps: {
        registered: +new Date()
      }
    };
    user[provider] = profile;
    if (courseData) {
      user.firstName = courseData.firstName;
      user.lastName = courseData.lastName;
      user.sfId = courseData.sfId;
      if (courseData.courses) {
          user.courses = courseData.courses;
        }
    }
    model.add(options.collection, user, function(err) {
      if (err) return done(err);

      $user = model.at(options.collection + '.' + user.id);
      callback();
    })
  }
}

function register(data, userId, model, req, res, done) {
  var email = data.email.toLowerCase();
  var password = data.password;

  var courseData = null;

  if (typeof data.firstName !== 'undefined' && typeof data.lastName !== 'undefined') {
    courseData = {
      firstName: data.firstName,
      lastName: data.lastName,
      sfId: data.sfId
    };
    if (typeof data.courses == 'object') {
      courseData.courses = data.courses;
    }
  }

  var query = { $limit: 1 };
  query['local.email'] = email;
  var $userQuery = model.query(options.collection, query);

  var $user = model.at(options.collection + '.' + userId);

  model.fetch($userQuery, $user, function(err) {
    if (err) return done(err);

    var user = $userQuery.get()[0];
    if (user) {
      return done({ email: 'User with this email already exists' });
    }

    if ($user.get('local')) {
      return done({ email: 'You are already registered' })
    }

    // Create local profile
    var salt = util.makeSecureSalt();
    util.makeSecureHash(password, salt, function (err, hash) {
      var profile = {
        email: email,
        salt: salt,
        passwordHash: hash
      };
      // Save user with profile
      registerProvider($user, 'local', profile, req, res, done, courseData);
    });
  });
}

function sendPasswordReset(email, model, req, res, done) {
  email = email.toLowerCase();

  var $query = model.query(options.collection, {
    $limit: 1,
    'local.email': email
  });

  model.fetch($query, function(err) {
    if (err) return done(err);

    var user = $query.get()[0];
    if (!user) {
      return done({email: 'There is no user with this email'});
    }

    var $user = model.at(options.collection + '.' + user.id),
      resetId = model.id();
    $user.set('local.pwResetId', resetId, function(err) {
      if (err) return done(err);

      options.resetPassword.email(email, resetId, done);
    });
  });
}

function getResetUser(resetId, model, done) {
  var $query = model.query(options.collection, {
    $limit: 1,
    'local.pwResetId': resetId
  });

  model.fetch($query, function(err) {
    if (err) return done(err);

    if ($query.get()) {
      return done(null, $query.get()[0]);
    } else {
      return done(null, undefined);
    }

    model.unfetch($query);
  });
}


function resetPassword(resetId, password, model, done) {
  var $query = model.query(options.collection, {
    $limit: 1,
    'local.pwResetId': resetId
  });

  model.fetch($query, function(err) {
    if (err) return done(err);

    if (!$query.get() || !$query.get()[0]) return done('Your password reset form has expired');

    var user = $query.get()[0],
      $user = model.at(options.collection + '.' + user.id);

    $user.del('local.pwResetId', function(err) {
      if (err) return done(err);

      var passwordHash = util.encryptPassword(password, user.local.salt);
      $user.set('local.passwordHash', passwordHash, done);
    });
  });
}
