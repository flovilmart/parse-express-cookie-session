var Cookie = function(options){
  console.log(options);
}

module.exports = function (options) {
  options = options || {};
  var key = options.key || 'parse.sess';
  var cookieOptions = options.cookie || {};
  var forcedCookieOptions = { httpOnly: false, secure: false };
  // forcedCookieOptions will overwrite same keys in cookieOptions
  cookieOptions = Parse._.defaults(forcedCookieOptions, cookieOptions);

  return function parseExpressCookieSession(req, res, next) {

    ////////////////////////
    // Request path logic

    // Expect express.cookieParser to set req.secret before this middleware.
    var signatureSecret = req.secret;
    if (Parse._.isEmpty(signatureSecret)) {
      throw new Error('express.cookieParser middleware must be included' +
        'before this, and initialized with a signing secret');
    }
    var cookie = new Cookie(cookieOptions);

    // Ignore if cookie path does not match.
    if (req.originalUrl.indexOf(cookie.path) !== 0) {
      return next();
    }

    var encryptionSecret = Parse.Cloud._expressCookieEncryptionKey();

    // Decrypt and parse the signed cookie.
    // Assume express.cookieParser already verified the signature and put the
    // cookie's contents at req.signedCookies[key].
    var reqParseUserSession;
    var reqCookieJson;  // Used later to determine whether to set response cookie.
    var reqCookieBody = req.signedCookies[key];
    if (!Parse._.isEmpty(reqCookieBody)) {
      try {
        reqCookieJson = decrypt(reqCookieBody, encryptionSecret);
        if (!Parse._.isEmpty(reqCookieJson)) {
          reqParseUserSession = utils.parseJSONCookie(reqCookieJson);
        }
      } catch (e) {
        // Catch any decryption and JSON parsing exceptions.
        console.warn("Invalid Parse session cookie");
      }
    }

    setCurrentParseUser(reqParseUserSession);

    ////////////////////////
    // Response path logic
    res.on('header', function() {
      var resParseUserSession = getCurrentParseUserSession();

      // If user is logged out, clear cookie.
      if (Parse._.isUndefined(resParseUserSession)) {
        cookie.expires = new Date(0);
        res.setHeader('Set-Cookie', cookie.serialize(key, ''));
        return;
      }

      // Only send Parse session cookies via https connection.
      if (!req.secure) {
        console.warn('Skipped setting Parse session cookie because request is not https');
        return;
      }

      // Serialize. Prefix is Connect's convention for JSON in cookie.
      var resCookieJson = 'j:' + JSON.stringify(resParseUserSession);

      // Skip Set-Cookie if cookie is same as request.
      if (reqCookieJson !== resCookieJson) {
        // Encrypt and sign. Prefix is Connect's convention for signed cookie.
        var val = encrypt(resCookieJson, encryptionSecret);
        val = 's:' + signature.sign(val, signatureSecret);
        val = cookie.serialize(key, val);
        res.setHeader('Set-Cookie', val);
      }
    });

    if (options.fetchUser && !Parse._isNullOrUndefined(Parse.User.current())) {
      Parse.User.current().fetch().then(function(user) {
        next();
      }, function() {
        // If user from cookie is invalid, reset Parse.User.current() to null.
        Parse.User.logOut();
        next();
      });
    } else {
      next();
    }
  };
}