
module.exports = function (options) {
  return function parseExpressCookieSession(req, res, next) {
    // Just next...
    next();
  };
}
