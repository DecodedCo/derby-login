var crypto = require('crypto');
var bcrypt = require('bcrypt');

var saltLength = 128;

module.exports = {
  encryptPassword: encryptPassword,
  encryptLegacyPassword: encryptLegacyPassword,
  makeSalt: makeSalt,
  makeSecureSalt: makeSecureSalt,
  makeSecureHash: makeSecureHash,
  compareSecureHash: compareSecureHash
}

function encryptPassword (password, salt) {
  return crypto.createHmac('sha512', salt).update(password).digest('hex');
}

function encryptLegacyPassword (password, salt) {
    return crypto.createHmac('sha1', salt).update(password).digest('hex');
}

function makeSalt () {
  return crypto.randomBytes(Math.ceil(saltLength / 2)).toString('hex').substring(0, saltLength);
}

function makeSecureSalt (next) {
    return bcrypt.genSaltSync(14);
}

function makeSecureHash (password, salt, next) {
    bcrypt.hash(password, salt, next);
}

function compareSecureHash (password, newHash, next) {
    bcrypt.compare(password, newHash, next);
}

