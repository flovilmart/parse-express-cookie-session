

var _ = require("underscore");
var Cookie = function(options){
  this.path = "/";
  this.maxAge = null;
  this.httpOnly = true;
  //if (options) _.merge(this, options);
}

var encode = encodeURIComponent;
var decode = decodeURIComponent;


Cookie.prototype.serialize = function(key, val){

  var serialize = function(name, val, opt){
    opt = opt || {};
    var enc = opt.encode || encode;
    var pairs = [name + '=' + enc(val)];

    if (opt.maxAge) pairs.push('Max-Age=' + opt.maxAge);
    if (opt.domain) pairs.push('Domain=' + opt.domain);
    if (opt.path) pairs.push('Path=' + opt.path);
    if (opt.expires) pairs.push('Expires=' + opt.expires.toUTCString());
    if (opt.httpOnly) pairs.push('HttpOnly');
    if (opt.secure) pairs.push('Secure');

    return pairs.join('; ');
};
  return serialize(key, val, this);
}

var setCurrentParseUser = function(userSession){
  if (!userSession || !userSession.id || !userSession.sessionToken) {
    // Force cleanup if invalid
    Parse.User.logOut();
    return;
  }
  Parse.User._currentUser = Parse.Object._create("_User");
  Parse.User._currentUser._isCurrentUser = true;
  Parse.User._currentUser.id = userSession.id;
  Parse.User._currentUser._sessionToken = userSession.sessionToken;
  Parse.User._currentUser._synchronizeAllAuthData();
  Parse.User._currentUser._refreshCache();
  Parse.User._currentUser._opSetQueue = [{}];
}

var getCurrentParseUserSession = function(){
  var u = Parse.User.current();
  if (!u) {
    return;
  }
  return {id:u.id, sessionToken: u.getSessionToken()};
}


module.exports = function (options) {
  options = options || {};
  var key = options.key || 'parse.sess';
  var cookieOptions = options.cookie || {};
  var forcedCookieOptions = { httpOnly: true, secure: true };
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
    var reqCookieBody = req.cookies[key];
    if (!Parse._.isEmpty(reqCookieBody)) {
      try {

        reqCookieJson = JSON.parse(reqCookieBody);
        //reqParseUserSession = JSON.parse(reqCookieBody);//decrypt(reqCookieBody, encryptionSecret);
        if (reqCookieJson && !reqCookieJson.id || !reqCookieJson.sessionToken) {
          throw "Invalid session";
        }
        /*if (!Parse._.isEmpty(reqCookieJson)) {
          reqParseUserSession = utils.parseJSONCookie(reqCookieJson);
        }*/
      } catch (e) {
        // Catch any decryption and JSON parsing exceptions.
        console.warn("Invalid Parse session cookie");
      }
    }
    setCurrentParseUser(reqCookieJson);
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
      /*if (!req.secure) {
        console.warn('Skipped setting Parse session cookie because request is not https');
        return;
      }*/

      // Serialize. Prefix is Connect's convention for JSON in cookie.
      resCookieJson = resParseUserSession;
      // Skip Set-Cookie if cookie is same as request.
      if (reqCookieJson !== resCookieJson) {
        var val = JSON.stringify(resParseUserSession);
        val = cookie.serialize(key, val);
        res.setHeader('Set-Cookie', val);
        // Encrypt and sign. Prefix is Connect's convention for signed cookie.
        //var val = encrypt(resCookieJson, encryptionSecret);
        //val = 's:' + signature.sign(val, signatureSecret);
        
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
