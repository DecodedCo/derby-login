var debug = require('debug')('auth:routes');
var passport = require('passport');
var auth = require('./auth');
var validation = require('./validation');

module.exports = function (options) {

  function parseError(err, redirectData) {
    var data = {};
    if (!err) {
      if (redirectData && redirectData.registrationData){
        return { success: true, url: '/course-project/' + redirectData.registrationData.courseId + '/' + redirectData.registrationData.courseName };
      } else {
        return { success: true, url: options.passport.successRedirect };
      }
    }
    else if (err instanceof Error) data.error = err.message;
    else if (typeof err === 'string') data.error = err;
    else if (err.message) data.error = err.message;
    else data = err;
    debug('error', data);
    return data;
  }

  return function(req, res, next) {
    var parts = req.path.slice(1).split('/');
    var method = parts[1];
    debug('routes', parts);
    if (parts[0] === 'auth') {
      switch (method) {

        case 'changepassword':
          var model = req.getModel();

          var data = {
            oldpassword: req.body.oldpassword,
            password: req.body.password,
            confirm: req.body.confirm
          }
          var errors = validation.validate(data);
          if (validation.any(errors)) return res.json(errors);

          auth.changePassword(data.oldpassword, data.password, req.session.userId, model, function(err) {
            res.json(parseError(err));
          });
          break;

        case 'login':
          // Get user with local strategy
          passport.authenticate('local', options.passport, function(err, user, info) {
            // Error
            if (err || info) return res.json(parseError(err || info));
            //if they are on a course registration
            if (typeof req.body.courses != 'undefined'){
              user.courses = req.body.courses;
            }
            //if they are in through a partner
            if (typeof req.body.partnerData != 'undefined'){
              user.partners = req.body.partnerData;
            }
            // Success and actually login
            auth.login(user, req, function(err) {
              return res.json(parseError(err));
            });
          })(req, res);
          break;

        case 'course-login':
          passport.authenticate('local', options.passport, function(err, user, info) {
            if (err || info) return res.json(parseError(err || info));
            auth.login(user, req, function(err) {
              return res.json(parseError(err, req.body));
            });
          })(req, res);
          break;

        case 'logout':
          req.logout();
          delete req.session.userId;
          return res.redirect(options.passport.failureRedirect);
          break;

        case 'register':
          var model = req.getModel();

          var data = {
            email: req.body.email,
            password: req.body.password,
            confirm: req.body.confirm,
            courses: req.body.courses,
            sfId: req.body.sfId
          }
          if (req.body.firstName && req.body.lastName) {
            data.firstName = req.body.firstName;
            data.lastName = req.body.lastName;
          }
          var errors = validation.validate(data);
          if (validation.any(errors)) return res.json(errors);
          auth.register(data, req.session.userId, model, req, res, function(err) {
            res.json(parseError(err));
          });
          break;

        case 'resetrequest':
          var model = req.getModel(),
            data = {email: req.body.email},
            errors = validation.validate(data);

          if (validation.any(errors)) return res.json(errors);

          auth.sendPasswordReset(data.email, model, req, res, function(err) {
            if (err) return res.json(parseError(err));
            res.json({success: true});
          });

          break;

        case 'reset':
          var model = req.getModel(),
            data = {
              resetId: req.body.resetId,
              password: req.body.password,
              confirm: req.body.confirm
            }
            errors = validation.validate(data);

          if (validation.any(errors)) return res.json(errors);

          auth.resetPassword(data.resetId, data.password, model, function(err) {
            if (err) return res.json(parseError(err));
            res.json({success: true});
          });

          break;

        default:
          var strategy = options.strategies[method];
          if (typeof req.query.partner != 'undefined'){
            req.session.partnerData = {
              courseId: req.query.courseId,
              courseName: req.query.courseName,
              partner: req.query.partner,
              optin: req.query.optin
            };
           } 

          if (!strategy) {
            return next(new Error('Unknown auth strategy: ' + method));
          } else {
            var conf = strategy.conf || {};
            if (parts[2] === 'callback') {
              var loginOptions = {};
              if (req.session.partnerData) {
                loginOptions.successRedirect = '/partners/' + req.session.partnerData.partner + '/' + req.session.partnerData.courseId + '/' + req.session.partnerData.courseName + '?optin=' + req.session.partnerData.optin;
                loginOptions.failureRedirect = options.passport.failureRedirect;
                loginOptions.registerCallback = options.passport.registerCallback;
                delete req.session.partnerData; //make sure it doesn't hang around for this user
              } else {
                loginOptions = options.passport;
              }
              passport.authenticate(method, loginOptions)(req, res, function(req, res) {
                if (res) {
                  res.redirect(options.passport.successRedirect);
                }
              });
            } else {
              passport.authenticate(method, conf)(req, res, function() {});
            }
          }
      }

    } else {
      next();
    }
  }
}
