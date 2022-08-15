(function () {

/* Imports */
var Meteor = Package.meteor.Meteor;
var global = Package.meteor.global;
var meteorEnv = Package.meteor.meteorEnv;
var check = Package.check.check;
var Match = Package.check.Match;
var ECMAScript = Package.ecmascript.ECMAScript;
var URL = Package.url.URL;
var URLSearchParams = Package.url.URLSearchParams;
var RoutePolicy = Package.routepolicy.RoutePolicy;
var WebApp = Package.webapp.WebApp;
var WebAppInternals = Package.webapp.WebAppInternals;
var main = Package.webapp.main;
var MongoInternals = Package.mongo.MongoInternals;
var Mongo = Package.mongo.Mongo;
var ServiceConfiguration = Package['service-configuration'].ServiceConfiguration;
var Log = Package.logging.Log;
var meteorInstall = Package.modules.meteorInstall;
var Promise = Package.promise.Promise;

/* Package-scope variables */
var OAuth, OAuthTest;

var require = meteorInstall({"node_modules":{"meteor":{"oauth":{"oauth_server.js":function module(require,exports,module){

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                  //
// packages/oauth/oauth_server.js                                                                                   //
//                                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                    //
let bodyParser;
module.link("body-parser", {
  default(v) {
    bodyParser = v;
  }

}, 0);
OAuth = {};
OAuthTest = {};
RoutePolicy.declare('/_oauth/', 'network');
const registeredServices = {}; // Internal: Maps from service version to handler function. The
// 'oauth1' and 'oauth2' packages manipulate this directly to register
// for callbacks.

OAuth._requestHandlers = {};
/**
/* Register a handler for an OAuth service. The handler will be called
/* when we get an incoming http request on /_oauth/{serviceName}. This
/* handler should use that information to fetch data about the user
/* logging in.
/*
/* @param name {String} e.g. "google", "facebook"
/* @param version {Number} OAuth version (1 or 2)
/* @param urls   For OAuth1 only, specify the service's urls
/* @param handleOauthRequest {Function(oauthBinding|query)}
/*   - (For OAuth1 only) oauthBinding {OAuth1Binding} bound to the appropriate provider
/*   - (For OAuth2 only) query {Object} parameters passed in query string
/*   - return value is:
/*     - {serviceData:, (optional options:)} where serviceData should end
/*       up in the user's services[name] field
/*     - `null` if the user declined to give permissions
*/

OAuth.registerService = (name, version, urls, handleOauthRequest) => {
  if (registeredServices[name]) throw new Error("Already registered the ".concat(name, " OAuth service"));
  registeredServices[name] = {
    serviceName: name,
    version,
    urls,
    handleOauthRequest
  };
}; // For test cleanup.


OAuthTest.unregisterService = name => {
  delete registeredServices[name];
};

OAuth.retrieveCredential = (credentialToken, credentialSecret) => OAuth._retrievePendingCredential(credentialToken, credentialSecret); // The state parameter is normally generated on the client using
// `btoa`, but for tests we need a version that runs on the server.
//


OAuth._generateState = (loginStyle, credentialToken, redirectUrl) => {
  return Buffer.from(JSON.stringify({
    loginStyle: loginStyle,
    credentialToken: credentialToken,
    redirectUrl: redirectUrl
  })).toString('base64');
};

OAuth._stateFromQuery = query => {
  let string;

  try {
    string = Buffer.from(query.state, 'base64').toString('binary');
  } catch (e) {
    Log.warn("Unable to base64 decode state from OAuth query: ".concat(query.state));
    throw e;
  }

  try {
    return JSON.parse(string);
  } catch (e) {
    Log.warn("Unable to parse state from OAuth query: ".concat(string));
    throw e;
  }
};

OAuth._loginStyleFromQuery = query => {
  let style; // For backwards-compatibility for older clients, catch any errors
  // that result from parsing the state parameter. If we can't parse it,
  // set login style to popup by default.

  try {
    style = OAuth._stateFromQuery(query).loginStyle;
  } catch (err) {
    style = "popup";
  }

  if (style !== "popup" && style !== "redirect") {
    throw new Error("Unrecognized login style: ".concat(style));
  }

  return style;
};

OAuth._credentialTokenFromQuery = query => {
  let state; // For backwards-compatibility for older clients, catch any errors
  // that result from parsing the state parameter. If we can't parse it,
  // assume that the state parameter's value is the credential token, as
  // it used to be for older clients.

  try {
    state = OAuth._stateFromQuery(query);
  } catch (err) {
    return query.state;
  }

  return state.credentialToken;
};

OAuth._isCordovaFromQuery = query => {
  try {
    return !!OAuth._stateFromQuery(query).isCordova;
  } catch (err) {
    // For backwards-compatibility for older clients, catch any errors
    // that result from parsing the state parameter. If we can't parse
    // it, assume that we are not on Cordova, since older Meteor didn't
    // do Cordova.
    return false;
  }
}; // Checks if the `redirectUrl` matches the app host.
// We export this function so that developers can override this
// behavior to allow apps from external domains to login using the
// redirect OAuth flow.


OAuth._checkRedirectUrlOrigin = redirectUrl => {
  const appHost = Meteor.absoluteUrl();
  const appHostReplacedLocalhost = Meteor.absoluteUrl(undefined, {
    replaceLocalhost: true
  });
  return redirectUrl.substr(0, appHost.length) !== appHost && redirectUrl.substr(0, appHostReplacedLocalhost.length) !== appHostReplacedLocalhost;
};

const middleware = (req, res, next) => {
  let requestData; // Make sure to catch any exceptions because otherwise we'd crash
  // the runner

  try {
    const serviceName = oauthServiceName(req);

    if (!serviceName) {
      // not an oauth request. pass to next middleware.
      next();
      return;
    }

    const service = registeredServices[serviceName]; // Skip everything if there's no service set by the oauth middleware

    if (!service) throw new Error("Unexpected OAuth service ".concat(serviceName)); // Make sure we're configured

    ensureConfigured(serviceName);
    const handler = OAuth._requestHandlers[service.version];
    if (!handler) throw new Error("Unexpected OAuth version ".concat(service.version));

    if (req.method === 'GET') {
      requestData = req.query;
    } else {
      requestData = req.body;
    }

    handler(service, requestData, res);
  } catch (err) {
    var _requestData;

    // if we got thrown an error, save it off, it will get passed to
    // the appropriate login call (if any) and reported there.
    //
    // The other option would be to display it in the popup tab that
    // is still open at this point, ignoring the 'close' or 'redirect'
    // we were passed. But then the developer wouldn't be able to
    // style the error or react to it in any way.
    if ((_requestData = requestData) !== null && _requestData !== void 0 && _requestData.state && err instanceof Error) {
      try {
        // catch any exceptions to avoid crashing runner
        OAuth._storePendingCredential(OAuth._credentialTokenFromQuery(requestData), err);
      } catch (err) {
        // Ignore the error and just give up. If we failed to store the
        // error, then the login will just fail with a generic error.
        Log.warn("Error in OAuth Server while storing pending login result.\n" + err.stack || err.message);
      }
    } // close the popup. because nobody likes them just hanging
    // there.  when someone sees this multiple times they might
    // think to check server logs (we hope?)
    // Catch errors because any exception here will crash the runner.


    try {
      OAuth._endOfLoginResponse(res, {
        query: requestData,
        loginStyle: OAuth._loginStyleFromQuery(requestData),
        error: err
      });
    } catch (err) {
      Log.warn("Error generating end of login response\n" + (err && (err.stack || err.message)));
    }
  }
}; // Listen to incoming OAuth http requests


WebApp.connectHandlers.use('/_oauth', bodyParser.json());
WebApp.connectHandlers.use('/_oauth', bodyParser.urlencoded({
  extended: false
}));
WebApp.connectHandlers.use(middleware);
OAuthTest.middleware = middleware; // Handle /_oauth/* paths and extract the service name.
//
// @returns {String|null} e.g. "facebook", or null if this isn't an
// oauth request

const oauthServiceName = req => {
  // req.url will be "/_oauth/<service name>" with an optional "?close".
  const i = req.url.indexOf('?');
  let barePath;
  if (i === -1) barePath = req.url;else barePath = req.url.substring(0, i);
  const splitPath = barePath.split('/'); // Any non-oauth request will continue down the default
  // middlewares.

  if (splitPath[1] !== '_oauth') return null; // Find service based on url

  const serviceName = splitPath[2];
  return serviceName;
}; // Make sure we're configured


const ensureConfigured = serviceName => {
  if (!ServiceConfiguration.configurations.findOne({
    service: serviceName
  })) {
    throw new ServiceConfiguration.ConfigError();
  }
};

const isSafe = value => {
  // This matches strings generated by `Random.secret` and
  // `Random.id`.
  return typeof value === "string" && /^[a-zA-Z0-9\-_]+$/.test(value);
}; // Internal: used by the oauth1 and oauth2 packages


OAuth._renderOauthResults = (res, query, credentialSecret) => {
  // For tests, we support the `only_credential_secret_for_test`
  // parameter, which just returns the credential secret without any
  // surrounding HTML. (The test needs to be able to easily grab the
  // secret and use it to log in.)
  //
  // XXX only_credential_secret_for_test could be useful for other
  // things beside tests, like command-line clients. We should give it a
  // real name and serve the credential secret in JSON.
  if (query.only_credential_secret_for_test) {
    res.writeHead(200, {
      'Content-Type': 'text/html'
    });
    res.end(credentialSecret, 'utf-8');
  } else {
    const details = {
      query,
      loginStyle: OAuth._loginStyleFromQuery(query)
    };

    if (query.error) {
      details.error = query.error;
    } else {
      const token = OAuth._credentialTokenFromQuery(query);

      const secret = credentialSecret;

      if (token && secret && isSafe(token) && isSafe(secret)) {
        details.credentials = {
          token: token,
          secret: secret
        };
      } else {
        details.error = "invalid_credential_token_or_secret";
      }
    }

    OAuth._endOfLoginResponse(res, details);
  }
}; // This "template" (not a real Spacebars template, just an HTML file
// with some ##PLACEHOLDER##s) communicates the credential secret back
// to the main window and then closes the popup.


OAuth._endOfPopupResponseTemplate = Assets.getText("end_of_popup_response.html");
OAuth._endOfRedirectResponseTemplate = Assets.getText("end_of_redirect_response.html"); // Renders the end of login response template into some HTML and JavaScript
// that closes the popup or redirects at the end of the OAuth flow.
//
// options are:
//   - loginStyle ("popup" or "redirect")
//   - setCredentialToken (boolean)
//   - credentialToken
//   - credentialSecret
//   - redirectUrl
//   - isCordova (boolean)
//

const renderEndOfLoginResponse = options => {
  // It would be nice to use Blaze here, but it's a little tricky
  // because our mustaches would be inside a <script> tag, and Blaze
  // would treat the <script> tag contents as text (e.g. encode '&' as
  // '&amp;'). So we just do a simple replace.
  const escape = s => {
    if (s) {
      return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\"/g, "&quot;").replace(/\'/g, "&#x27;").replace(/\//g, "&#x2F;");
    } else {
      return s;
    }
  }; // Escape everything just to be safe (we've already checked that some
  // of this data -- the token and secret -- are safe).


  const config = {
    setCredentialToken: !!options.setCredentialToken,
    credentialToken: escape(options.credentialToken),
    credentialSecret: escape(options.credentialSecret),
    storagePrefix: escape(OAuth._storageTokenPrefix),
    redirectUrl: escape(options.redirectUrl),
    isCordova: !!options.isCordova
  };
  let template;

  if (options.loginStyle === 'popup') {
    template = OAuth._endOfPopupResponseTemplate;
  } else if (options.loginStyle === 'redirect') {
    template = OAuth._endOfRedirectResponseTemplate;
  } else {
    throw new Error("invalid loginStyle: ".concat(options.loginStyle));
  }

  const result = template.replace(/##CONFIG##/, JSON.stringify(config)).replace(/##ROOT_URL_PATH_PREFIX##/, __meteor_runtime_config__.ROOT_URL_PATH_PREFIX);
  return "<!DOCTYPE html>\n".concat(result);
}; // Writes an HTTP response to the popup window at the end of an OAuth
// login flow. At this point, if the user has successfully authenticated
// to the OAuth server and authorized this app, we communicate the
// credentialToken and credentialSecret to the main window. The main
// window must provide both these values to the DDP `login` method to
// authenticate its DDP connection. After communicating these vaues to
// the main window, we close the popup.
//
// We export this function so that developers can override this
// behavior, which is particularly useful in, for example, some mobile
// environments where popups and/or `window.opener` don't work. For
// example, an app could override `OAuth._endOfPopupResponse` to put the
// credential token and credential secret in the popup URL for the main
// window to read them there instead of using `window.opener`. If you
// override this function, you take responsibility for writing to the
// request and calling `res.end()` to complete the request.
//
// Arguments:
//   - res: the HTTP response object
//   - details:
//      - query: the query string on the HTTP request
//      - credentials: { token: *, secret: * }. If present, this field
//        indicates that the login was successful. Return these values
//        to the client, who can use them to log in over DDP. If
//        present, the values have been checked against a limited
//        character set and are safe to include in HTML.
//      - error: if present, a string or Error indicating an error that
//        occurred during the login. This can come from the client and
//        so shouldn't be trusted for security decisions or included in
//        the response without sanitizing it first. Only one of `error`
//        or `credentials` should be set.


OAuth._endOfLoginResponse = (res, details) => {
  res.writeHead(200, {
    'Content-Type': 'text/html'
  });
  let redirectUrl;

  if (details.loginStyle === 'redirect') {
    var _Meteor$settings, _Meteor$settings$pack, _Meteor$settings$pack2;

    redirectUrl = OAuth._stateFromQuery(details.query).redirectUrl;
    const appHost = Meteor.absoluteUrl();

    if (!((_Meteor$settings = Meteor.settings) !== null && _Meteor$settings !== void 0 && (_Meteor$settings$pack = _Meteor$settings.packages) !== null && _Meteor$settings$pack !== void 0 && (_Meteor$settings$pack2 = _Meteor$settings$pack.oauth) !== null && _Meteor$settings$pack2 !== void 0 && _Meteor$settings$pack2.disableCheckRedirectUrlOrigin) && OAuth._checkRedirectUrlOrigin(redirectUrl)) {
      details.error = "redirectUrl (".concat(redirectUrl) + ") is not on the same host as the app (".concat(appHost, ")");
      redirectUrl = appHost;
    }
  }

  const isCordova = OAuth._isCordovaFromQuery(details.query);

  if (details.error) {
    Log.warn("Error in OAuth Server: " + (details.error instanceof Error ? details.error.message : details.error));
    res.end(renderEndOfLoginResponse({
      loginStyle: details.loginStyle,
      setCredentialToken: false,
      redirectUrl,
      isCordova
    }), "utf-8");
    return;
  } // If we have a credentialSecret, report it back to the parent
  // window, with the corresponding credentialToken. The parent window
  // uses the credentialToken and credentialSecret to log in over DDP.


  res.end(renderEndOfLoginResponse({
    loginStyle: details.loginStyle,
    setCredentialToken: true,
    credentialToken: details.credentials.token,
    credentialSecret: details.credentials.secret,
    redirectUrl,
    isCordova
  }), "utf-8");
};

const OAuthEncryption = Package["oauth-encryption"] && Package["oauth-encryption"].OAuthEncryption;

const usingOAuthEncryption = () => OAuthEncryption && OAuthEncryption.keyIsLoaded(); // Encrypt sensitive service data such as access tokens if the
// "oauth-encryption" package is loaded and the oauth secret key has
// been specified.  Returns the unencrypted plaintext otherwise.
//
// The user id is not specified because the user isn't known yet at
// this point in the oauth authentication process.  After the oauth
// authentication process completes the encrypted service data fields
// will be re-encrypted with the user id included before inserting the
// service data into the user document.
//


OAuth.sealSecret = plaintext => {
  if (usingOAuthEncryption()) return OAuthEncryption.seal(plaintext);else return plaintext;
}; // Unencrypt a service data field, if the "oauth-encryption"
// package is loaded and the field is encrypted.
//
// Throws an error if the "oauth-encryption" package is loaded and the
// field is encrypted, but the oauth secret key hasn't been specified.
//


OAuth.openSecret = (maybeSecret, userId) => {
  if (!Package["oauth-encryption"] || !OAuthEncryption.isSealed(maybeSecret)) return maybeSecret;
  return OAuthEncryption.open(maybeSecret, userId);
}; // Unencrypt fields in the service data object.
//


OAuth.openSecrets = (serviceData, userId) => {
  const result = {};
  Object.keys(serviceData).forEach(key => result[key] = OAuth.openSecret(serviceData[key], userId));
  return result;
};
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

},"pending_credentials.js":function module(){

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                  //
// packages/oauth/pending_credentials.js                                                                            //
//                                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                    //
//
// When an oauth request is made, Meteor receives oauth credentials
// in one browser tab, and temporarily persists them while that
// tab is closed, then retrieves them in the browser tab that
// initiated the credential request.
//
// _pendingCredentials is the storage mechanism used to share the
// credential between the 2 tabs
//
// Collection containing pending credentials of oauth credential requests
// Has key, credential, and createdAt fields.
OAuth._pendingCredentials = new Mongo.Collection("meteor_oauth_pendingCredentials", {
  _preventAutopublish: true
});

OAuth._pendingCredentials.createIndex('key', {
  unique: true
});

OAuth._pendingCredentials.createIndex('credentialSecret');

OAuth._pendingCredentials.createIndex('createdAt'); // Periodically clear old entries that were never retrieved


const _cleanStaleResults = () => {
  // Remove credentials older than 1 minute
  const timeCutoff = new Date();
  timeCutoff.setMinutes(timeCutoff.getMinutes() - 1);

  OAuth._pendingCredentials.remove({
    createdAt: {
      $lt: timeCutoff
    }
  });
};

const _cleanupHandle = Meteor.setInterval(_cleanStaleResults, 60 * 1000); // Stores the key and credential in the _pendingCredentials collection.
// Will throw an exception if `key` is not a string.
//
// @param key {string}
// @param credential {Object}   The credential to store
// @param credentialSecret {string} A secret that must be presented in
//   addition to the `key` to retrieve the credential
//


OAuth._storePendingCredential = function (key, credential) {
  let credentialSecret = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : null;
  check(key, String);
  check(credentialSecret, Match.Maybe(String));

  if (credential instanceof Error) {
    credential = storableError(credential);
  } else {
    credential = OAuth.sealSecret(credential);
  } // We do an upsert here instead of an insert in case the user happens
  // to somehow send the same `state` parameter twice during an OAuth
  // login; we don't want a duplicate key error.


  OAuth._pendingCredentials.upsert({
    key
  }, {
    key,
    credential,
    credentialSecret,
    createdAt: new Date()
  });
}; // Retrieves and removes a credential from the _pendingCredentials collection
//
// @param key {string}
// @param credentialSecret {string}
//


OAuth._retrievePendingCredential = function (key) {
  let credentialSecret = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : null;
  check(key, String);

  const pendingCredential = OAuth._pendingCredentials.findOne({
    key,
    credentialSecret
  });

  if (pendingCredential) {
    OAuth._pendingCredentials.remove({
      _id: pendingCredential._id
    });

    if (pendingCredential.credential.error) return recreateError(pendingCredential.credential.error);else return OAuth.openSecret(pendingCredential.credential);
  } else {
    return undefined;
  }
}; // Convert an Error into an object that can be stored in mongo
// Note: A Meteor.Error is reconstructed as a Meteor.Error
// All other error classes are reconstructed as a plain Error.
// TODO: Can we do this more simply with EJSON?


const storableError = error => {
  const plainObject = {};
  Object.getOwnPropertyNames(error).forEach(key => plainObject[key] = error[key]); // Keep track of whether it's a Meteor.Error

  if (error instanceof Meteor.Error) {
    plainObject['meteorError'] = true;
  }

  return {
    error: plainObject
  };
}; // Create an error from the error format stored in mongo


const recreateError = errorDoc => {
  let error;

  if (errorDoc.meteorError) {
    error = new Meteor.Error();
    delete errorDoc.meteorError;
  } else {
    error = new Error();
  }

  Object.getOwnPropertyNames(errorDoc).forEach(key => error[key] = errorDoc[key]);
  return error;
};
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

},"oauth_common.js":function module(require,exports,module){

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                  //
// packages/oauth/oauth_common.js                                                                                   //
//                                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                    //
let _objectSpread;

module.link("@babel/runtime/helpers/objectSpread2", {
  default(v) {
    _objectSpread = v;
  }

}, 0);
OAuth._storageTokenPrefix = "Meteor.oauth.credentialSecret-";

OAuth._redirectUri = (serviceName, config, params, absoluteUrlOptions) => {
  // Clone because we're going to mutate 'params'. The 'cordova' and
  // 'android' parameters are only used for picking the host of the
  // redirect URL, and not actually included in the redirect URL itself.
  let isCordova = false;
  let isAndroid = false;

  if (params) {
    params = _objectSpread({}, params);
    isCordova = params.cordova;
    isAndroid = params.android;
    delete params.cordova;
    delete params.android;

    if (Object.keys(params).length === 0) {
      params = undefined;
    }
  }

  if (Meteor.isServer && isCordova) {
    const url = Npm.require('url');

    let rootUrl = process.env.MOBILE_ROOT_URL || __meteor_runtime_config__.ROOT_URL;

    if (isAndroid) {
      // Match the replace that we do in cordova boilerplate
      // (boilerplate-generator package).
      // XXX Maybe we should put this in a separate package or something
      // that is used here and by boilerplate-generator? Or maybe
      // `Meteor.absoluteUrl` should know how to do this?
      const parsedRootUrl = url.parse(rootUrl);

      if (parsedRootUrl.hostname === "localhost") {
        parsedRootUrl.hostname = "10.0.2.2";
        delete parsedRootUrl.host;
      }

      rootUrl = url.format(parsedRootUrl);
    }

    absoluteUrlOptions = _objectSpread(_objectSpread({}, absoluteUrlOptions), {}, {
      // For Cordova clients, redirect to the special Cordova root url
      // (likely a local IP in development mode).
      rootUrl
    });
  }

  return URL._constructUrl(Meteor.absoluteUrl("_oauth/".concat(serviceName), absoluteUrlOptions), null, params);
};
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

},"node_modules":{"body-parser":{"package.json":function module(require,exports,module){

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                  //
// node_modules/meteor/oauth/node_modules/body-parser/package.json                                                  //
//                                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                    //
module.exports = {
  "name": "body-parser",
  "version": "1.19.0"
};

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

},"index.js":function module(require,exports,module){

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                  //
// node_modules/meteor/oauth/node_modules/body-parser/index.js                                                      //
//                                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                    //
module.useNode();
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}}}}}}},{
  "extensions": [
    ".js",
    ".json"
  ]
});

require("/node_modules/meteor/oauth/oauth_server.js");
require("/node_modules/meteor/oauth/pending_credentials.js");
require("/node_modules/meteor/oauth/oauth_common.js");

/* Exports */
Package._define("oauth", {
  OAuth: OAuth,
  OAuthTest: OAuthTest
});

})();

//# sourceURL=meteor://💻app/packages/oauth.js
//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm1ldGVvcjovL/CfkrthcHAvcGFja2FnZXMvb2F1dGgvb2F1dGhfc2VydmVyLmpzIiwibWV0ZW9yOi8v8J+Su2FwcC9wYWNrYWdlcy9vYXV0aC9wZW5kaW5nX2NyZWRlbnRpYWxzLmpzIiwibWV0ZW9yOi8v8J+Su2FwcC9wYWNrYWdlcy9vYXV0aC9vYXV0aF9jb21tb24uanMiXSwibmFtZXMiOlsiYm9keVBhcnNlciIsIm1vZHVsZSIsImxpbmsiLCJkZWZhdWx0IiwidiIsIk9BdXRoIiwiT0F1dGhUZXN0IiwiUm91dGVQb2xpY3kiLCJkZWNsYXJlIiwicmVnaXN0ZXJlZFNlcnZpY2VzIiwiX3JlcXVlc3RIYW5kbGVycyIsInJlZ2lzdGVyU2VydmljZSIsIm5hbWUiLCJ2ZXJzaW9uIiwidXJscyIsImhhbmRsZU9hdXRoUmVxdWVzdCIsIkVycm9yIiwic2VydmljZU5hbWUiLCJ1bnJlZ2lzdGVyU2VydmljZSIsInJldHJpZXZlQ3JlZGVudGlhbCIsImNyZWRlbnRpYWxUb2tlbiIsImNyZWRlbnRpYWxTZWNyZXQiLCJfcmV0cmlldmVQZW5kaW5nQ3JlZGVudGlhbCIsIl9nZW5lcmF0ZVN0YXRlIiwibG9naW5TdHlsZSIsInJlZGlyZWN0VXJsIiwiQnVmZmVyIiwiZnJvbSIsIkpTT04iLCJzdHJpbmdpZnkiLCJ0b1N0cmluZyIsIl9zdGF0ZUZyb21RdWVyeSIsInF1ZXJ5Iiwic3RyaW5nIiwic3RhdGUiLCJlIiwiTG9nIiwid2FybiIsInBhcnNlIiwiX2xvZ2luU3R5bGVGcm9tUXVlcnkiLCJzdHlsZSIsImVyciIsIl9jcmVkZW50aWFsVG9rZW5Gcm9tUXVlcnkiLCJfaXNDb3Jkb3ZhRnJvbVF1ZXJ5IiwiaXNDb3Jkb3ZhIiwiX2NoZWNrUmVkaXJlY3RVcmxPcmlnaW4iLCJhcHBIb3N0IiwiTWV0ZW9yIiwiYWJzb2x1dGVVcmwiLCJhcHBIb3N0UmVwbGFjZWRMb2NhbGhvc3QiLCJ1bmRlZmluZWQiLCJyZXBsYWNlTG9jYWxob3N0Iiwic3Vic3RyIiwibGVuZ3RoIiwibWlkZGxld2FyZSIsInJlcSIsInJlcyIsIm5leHQiLCJyZXF1ZXN0RGF0YSIsIm9hdXRoU2VydmljZU5hbWUiLCJzZXJ2aWNlIiwiZW5zdXJlQ29uZmlndXJlZCIsImhhbmRsZXIiLCJtZXRob2QiLCJib2R5IiwiX3N0b3JlUGVuZGluZ0NyZWRlbnRpYWwiLCJzdGFjayIsIm1lc3NhZ2UiLCJfZW5kT2ZMb2dpblJlc3BvbnNlIiwiZXJyb3IiLCJXZWJBcHAiLCJjb25uZWN0SGFuZGxlcnMiLCJ1c2UiLCJqc29uIiwidXJsZW5jb2RlZCIsImV4dGVuZGVkIiwiaSIsInVybCIsImluZGV4T2YiLCJiYXJlUGF0aCIsInN1YnN0cmluZyIsInNwbGl0UGF0aCIsInNwbGl0IiwiU2VydmljZUNvbmZpZ3VyYXRpb24iLCJjb25maWd1cmF0aW9ucyIsImZpbmRPbmUiLCJDb25maWdFcnJvciIsImlzU2FmZSIsInZhbHVlIiwidGVzdCIsIl9yZW5kZXJPYXV0aFJlc3VsdHMiLCJvbmx5X2NyZWRlbnRpYWxfc2VjcmV0X2Zvcl90ZXN0Iiwid3JpdGVIZWFkIiwiZW5kIiwiZGV0YWlscyIsInRva2VuIiwic2VjcmV0IiwiY3JlZGVudGlhbHMiLCJfZW5kT2ZQb3B1cFJlc3BvbnNlVGVtcGxhdGUiLCJBc3NldHMiLCJnZXRUZXh0IiwiX2VuZE9mUmVkaXJlY3RSZXNwb25zZVRlbXBsYXRlIiwicmVuZGVyRW5kT2ZMb2dpblJlc3BvbnNlIiwib3B0aW9ucyIsImVzY2FwZSIsInMiLCJyZXBsYWNlIiwiY29uZmlnIiwic2V0Q3JlZGVudGlhbFRva2VuIiwic3RvcmFnZVByZWZpeCIsIl9zdG9yYWdlVG9rZW5QcmVmaXgiLCJ0ZW1wbGF0ZSIsInJlc3VsdCIsIl9fbWV0ZW9yX3J1bnRpbWVfY29uZmlnX18iLCJST09UX1VSTF9QQVRIX1BSRUZJWCIsInNldHRpbmdzIiwicGFja2FnZXMiLCJvYXV0aCIsImRpc2FibGVDaGVja1JlZGlyZWN0VXJsT3JpZ2luIiwiT0F1dGhFbmNyeXB0aW9uIiwiUGFja2FnZSIsInVzaW5nT0F1dGhFbmNyeXB0aW9uIiwia2V5SXNMb2FkZWQiLCJzZWFsU2VjcmV0IiwicGxhaW50ZXh0Iiwic2VhbCIsIm9wZW5TZWNyZXQiLCJtYXliZVNlY3JldCIsInVzZXJJZCIsImlzU2VhbGVkIiwib3BlbiIsIm9wZW5TZWNyZXRzIiwic2VydmljZURhdGEiLCJPYmplY3QiLCJrZXlzIiwiZm9yRWFjaCIsImtleSIsIl9wZW5kaW5nQ3JlZGVudGlhbHMiLCJNb25nbyIsIkNvbGxlY3Rpb24iLCJfcHJldmVudEF1dG9wdWJsaXNoIiwiY3JlYXRlSW5kZXgiLCJ1bmlxdWUiLCJfY2xlYW5TdGFsZVJlc3VsdHMiLCJ0aW1lQ3V0b2ZmIiwiRGF0ZSIsInNldE1pbnV0ZXMiLCJnZXRNaW51dGVzIiwicmVtb3ZlIiwiY3JlYXRlZEF0IiwiJGx0IiwiX2NsZWFudXBIYW5kbGUiLCJzZXRJbnRlcnZhbCIsImNyZWRlbnRpYWwiLCJjaGVjayIsIlN0cmluZyIsIk1hdGNoIiwiTWF5YmUiLCJzdG9yYWJsZUVycm9yIiwidXBzZXJ0IiwicGVuZGluZ0NyZWRlbnRpYWwiLCJfaWQiLCJyZWNyZWF0ZUVycm9yIiwicGxhaW5PYmplY3QiLCJnZXRPd25Qcm9wZXJ0eU5hbWVzIiwiZXJyb3JEb2MiLCJtZXRlb3JFcnJvciIsIl9vYmplY3RTcHJlYWQiLCJfcmVkaXJlY3RVcmkiLCJwYXJhbXMiLCJhYnNvbHV0ZVVybE9wdGlvbnMiLCJpc0FuZHJvaWQiLCJjb3Jkb3ZhIiwiYW5kcm9pZCIsImlzU2VydmVyIiwiTnBtIiwicmVxdWlyZSIsInJvb3RVcmwiLCJwcm9jZXNzIiwiZW52IiwiTU9CSUxFX1JPT1RfVVJMIiwiUk9PVF9VUkwiLCJwYXJzZWRSb290VXJsIiwiaG9zdG5hbWUiLCJob3N0IiwiZm9ybWF0IiwiVVJMIiwiX2NvbnN0cnVjdFVybCJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUEsSUFBSUEsVUFBSjtBQUFlQyxNQUFNLENBQUNDLElBQVAsQ0FBWSxhQUFa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RURaLHNCQUFrQixtQ0FDYkEsa0JBRGE7QUFFaEI7QUFDQTtBQUNBTztBQUpnQixNQUFsQjtBQU1EOztBQUVELFNBQU9TLEdBQUcsQ0FBQ0MsYUFBSixDQUNMNUksTUFBTSxDQUFDQyxXQUFQLGtCQUE2Qi9CLFdBQTdCLEdBQTRDeUosa0JBQTVDLENBREssRUFFTCxJQUZLLEVBR0xELE1BSEssQ0FBUDtBQUlELENBaERELEMiLCJmaWxlIjoiL3BhY2thZ2VzL29hdXRoLmpzIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IGJvZHlQYXJzZXIgZnJvbSAnYm9keS1wYXJzZXInO1xuXG5PQXV0aCA9IHt9O1xuT0F1dGhUZXN0ID0ge307XG5cblJvdXRlUG9saWN5LmRlY2xhcmUoJy9fb2F1dGgvJywgJ25ldHdvcmsnKTtcblxuY29uc3QgcmVnaXN0ZXJlZFNlcnZpY2VzID0ge307XG5cbi8vIEludGVybmFsOiBNYXBzIGZyb20gc2VydmljZSB2ZXJzaW9uIHRvIGhhbmRsZXIgZnVuY3Rpb24uIFRoZVxuLy8gJ29hdXRoMScgYW5kICdvYXV0aDInIHBhY2thZ2VzIG1hbmlwdWxhdGUgdGhpcyBkaXJlY3RseSB0byByZWdpc3RlclxuLy8gZm9yIGNhbGxiYWNrcy5cbk9BdXRoLl9yZXF1ZXN0SGFuZGxlcnMgPSB7fTtcblxuXG4vKipcbi8qIFJlZ2lzdGVyIGEgaGFuZGxlciBmb3IgYW4gT0F1dGggc2VydmljZS4gVGhlIGhhbmRsZXIgd2lsbCBiZSBjYWxsZWRcbi8qIHdoZW4gd2UgZ2V0IGFuIGluY29taW5nIGh0dHAgcmVxdWVzdCBvbiAvX29hdXRoL3tzZXJ2aWNlTmFtZX0uIFRoaXNcbi8qIGhhbmRsZXIgc2hvdWxkIHVzZSB0aGF0IGluZm9ybWF0aW9uIHRvIGZldGNoIGRhdGEgYWJvdXQgdGhlIHVzZXJcbi8qIGxvZ2dpbmcgaW4uXG4vKlxuLyogQHBhcmFtIG5hbWUge1N0cmluZ30gZS5nLiBcImdvb2dsZVwiLCBcImZhY2Vib29rXCJcbi8qIEBwYXJhbSB2ZXJzaW9uIHtOdW1iZXJ9IE9BdXRoIHZlcnNpb24gKDEgb3IgMilcbi8qIEBwYXJhbSB1cmxzICAgRm9yIE9BdXRoMSBvbmx5LCBzcGVjaWZ5IHRoZSBzZXJ2aWNlJ3MgdXJsc1xuLyogQHBhcmFtIGhhbmRsZU9hdXRoUmVxdWVzdCB7RnVuY3Rpb24ob2F1dGhCaW5kaW5nfHF1ZXJ5KX1cbi8qICAgLSAoRm9yIE9BdXRoMSBvbmx5KSBvYXV0aEJpbmRpbmcge09BdXRoMUJpbmRpbmd9IGJvdW5kIHRvIHRoZSBhcHByb3ByaWF0ZSBwcm92aWRlclxuLyogICAtIChGb3IgT0F1dGgyIG9ubHkpIHF1ZXJ5IHtPYmplY3R9IHBhcmFtZXRlcnMgcGFzc2VkIGluIHF1ZXJ5IHN0cmluZ1xuLyogICAtIHJldHVybiB2YWx1ZSBpczpcbi8qICAgICAtIHtzZXJ2aWNlRGF0YTosIChvcHRpb25hbCBvcHRpb25zOil9IHdoZXJlIHNlcnZpY2VEYXRhIHNob3VsZCBlbmRcbi8qICAgICAgIHVwIGluIHRoZSB1c2VyJ3Mgc2VydmljZXNbbmFtZV0gZmllbGRcbi8qICAgICAtIGBudWxsYCBpZiB0aGUgdXNlciBkZWNsaW5lZCB0byBnaXZlIHBlcm1pc3Npb25zXG4qL1xuT0F1dGgucmVnaXN0ZXJTZXJ2aWNlID0gKG5hbWUsIHZlcnNpb24sIHVybHMsIGhhbmRsZU9hdXRoUmVxdWVzdCkgPT4ge1xuICBpZiAocmVnaXN0ZXJlZFNlcnZpY2VzW25hbWVdKVxuICAgIHRocm93IG5ldyBFcnJvcihgQWxyZWFkeSByZWdpc3RlcmVkIHRoZSAke25hbWV9IE9BdXRoIHNlcnZpY2VgKTtcblxuICByZWdpc3RlcmVkU2VydmljZXNbbmFtZV0gPSB7XG4gICAgc2VydmljZU5hbWU6IG5hbWUsXG4gICAgdmVyc2lvbixcbiAgICB1cmxzLFxuICAgIGhhbmRsZU9hdXRoUmVxdWVzdCxcbiAgfTtcbn07XG5cbi8vIEZvciB0ZXN0IGNsZWFudXAuXG5PQXV0aFRlc3QudW5yZWdpc3RlclNlcnZpY2UgPSBuYW1lID0+IHtcbiAgZGVsZXRlIHJlZ2lzdGVyZWRTZXJ2aWNlc1tuYW1lXTtcbn07XG5cblxuT0F1dGgucmV0cmlldmVDcmVkZW50aWFsID0gKGNyZWRlbnRpYWxUb2tlbiwgY3JlZGVudGlhbFNlY3JldCkgPT5cbiAgT0F1dGguX3JldHJpZXZlUGVuZGluZ0NyZWRlbnRpYWwoY3JlZGVudGlhbFRva2VuLCBjcmVkZW50aWFsU2VjcmV0KTtcblxuXG4vLyBUaGUgc3RhdGUgcGFyYW1ldGVyIGlzIG5vcm1hbGx5IGdlbmVyYXRlZCBvbiB0aGUgY2xpZW50IHVzaW5nXG4vLyBgYnRvYWAsIGJ1dCBmb3IgdGVzdHMgd2UgbmVlZCBhIHZlcnNpb24gdGhhdCBydW5zIG9uIHRoZSBzZXJ2ZXIuXG4vL1xuT0F1dGguX2dlbmVyYXRlU3RhdGUgPSAobG9naW5TdHlsZSwgY3JlZGVudGlhbFRva2VuLCByZWRpcmVjdFVybCkgPT4ge1xuICByZXR1cm4gQnVmZmVyLmZyb20oSlNPTi5zdHJpbmdpZnkoe1xuICAgIGxvZ2luU3R5bGU6IGxvZ2luU3R5bGUsXG4gICAgY3JlZGVudGlhbFRva2VuOiBjcmVkZW50aWFsVG9rZW4sXG4gICAgcmVkaXJlY3RVcmw6IHJlZGlyZWN0VXJsfSkpLnRvU3RyaW5nKCdiYXNlNjQnKTtcbn07XG5cbk9BdXRoLl9zdGF0ZUZyb21RdWVyeSA9IHF1ZXJ5ID0+IHtcbiAgbGV0IHN0cmluZztcbiAgdHJ5IHtcbiAgICBzdHJpbmcgPSBCdWZmZXIuZnJvbShxdWVyeS5zdGF0ZSwgJ2Jhc2U2NCcpLnRvU3RyaW5nKCdiaW5hcnknKTtcbiAgfSBjYXRjaCAoZSkge1xuICAgIExvZy53YXJuKGBVbmFibGUgdG8gYmFzZTY0IGRlY29kZSBzdGF0ZSBmcm9tIE9BdXRoIHF1ZXJ5OiAke3F1ZXJ5LnN0YXRlfWApO1xuICAgIHRocm93IGU7XG4gIH1cblxuICB0cnkge1xuICAgIHJldHVybiBKU09OLnBhcnNlKHN0cmluZyk7XG4gIH0gY2F0Y2ggKGUpIHtcbiAgICBMb2cud2FybihgVW5hYmxlIHRvIHBhcnNlIHN0YXRlIGZyb20gT0F1dGggcXVlcnk6ICR7c3RyaW5nfWApO1xuICAgIHRocm93IGU7XG4gIH1cbn07XG5cbk9BdXRoLl9sb2dpblN0eWxlRnJvbVF1ZXJ5ID0gcXVlcnkgPT4ge1xuICBsZXQgc3R5bGU7XG4gIC8vIEZvciBiYWNrd2FyZHMtY29tcGF0aWJpbGl0eSBmb3Igb2xkZXIgY2xpZW50cywgY2F0Y2ggYW55IGVycm9yc1xuICAvLyB0aGF0IHJlc3VsdCBmcm9tIHBhcnNpbmcgdGhlIHN0YXRlIHBhcmFtZXRlci4gSWYgd2UgY2FuJ3QgcGFyc2UgaXQsXG4gIC8vIHNldCBsb2dpbiBzdHlsZSB0byBwb3B1cCBieSBkZWZhdWx0LlxuICB0cnkge1xuICAgIHN0eWxlID0gT0F1dGguX3N0YXRlRnJvbVF1ZXJ5KHF1ZXJ5KS5sb2dpblN0eWxlO1xuICB9IGNhdGNoIChlcnIpIHtcbiAgICBzdHlsZSA9IFwicG9wdXBcIjtcbiAgfVxuICBpZiAoc3R5bGUgIT09IFwicG9wdXBcIiAmJiBzdHlsZSAhPT0gXCJyZWRpcmVjdFwiKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBVbnJlY29nbml6ZWQgbG9naW4gc3R5bGU6ICR7c3R5bGV9YCk7XG4gIH1cbiAgcmV0dXJuIHN0eWxlO1xufTtcblxuT0F1dGguX2NyZWRlbnRpYWxUb2tlbkZyb21RdWVyeSA9IHF1ZXJ5ID0+IHtcbiAgbGV0IHN0YXRlO1xuICAvLyBGb3IgYmFja3dhcmRzLWNvbXBhdGliaWxpdHkgZm9yIG9sZGVyIGNsaWVudHMsIGNhdGNoIGFueSBlcnJvcnNcbiAgLy8gdGhhdCByZXN1bHQgZnJvbSBwYXJzaW5nIHRoZSBzdGF0ZSBwYXJhbWV0ZXIuIElmIHdlIGNhbid0IHBhcnNlIGl0LFxuICAvLyBhc3N1bWUgdGhhdCB0aGUgc3RhdGUgcGFyYW1ldGVyJ3MgdmFsdWUgaXMgdGhlIGNyZWRlbnRpYWwgdG9rZW4sIGFzXG4gIC8vIGl0IHVzZWQgdG8gYmUgZm9yIG9sZGVyIGNsaWVudHMuXG4gIHRyeSB7XG4gICAgc3RhdGUgPSBPQXV0aC5fc3RhdGVGcm9tUXVlcnkocXVlcnkpO1xuICB9IGNhdGNoIChlcnIpIHtcbiAgICByZXR1cm4gcXVlcnkuc3RhdGU7XG4gIH1cbiAgcmV0dXJuIHN0YXRlLmNyZWRlbnRpYWxUb2tlbjtcbn07XG5cbk9BdXRoLl9pc0NvcmRvdmFGcm9tUXVlcnkgPSBxdWVyeSA9PiB7XG4gIHRyeSB7XG4gICAgcmV0dXJuICEhIE9BdXRoLl9zdGF0ZUZyb21RdWVyeShxdWVyeSkuaXNDb3Jkb3ZhO1xuICB9IGNhdGNoIChlcnIpIHtcbiAgICAvLyBGb3IgYmFja3dhcmRzLWNvbXBhdGliaWxpdHkgZm9yIG9sZGVyIGNsaWVudHMsIGNhdGNoIGFueSBlcnJvcnNcbiAgICAvLyB0aGF0IHJlc3VsdCBmcm9tIHBhcnNpbmcgdGhlIHN0YXRlIHBhcmFtZXRlci4gSWYgd2UgY2FuJ3QgcGFyc2VcbiAgICAvLyBpdCwgYXNzdW1lIHRoYXQgd2UgYXJlIG5vdCBvbiBDb3Jkb3ZhLCBzaW5jZSBvbGRlciBNZXRlb3IgZGlkbid0XG4gICAgLy8gZG8gQ29yZG92YS5cbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbn07XG5cbi8vIENoZWNrcyBpZiB0aGUgYHJlZGlyZWN0VXJsYCBtYXRjaGVzIHRoZSBhcHAgaG9zdC5cbi8vIFdlIGV4cG9ydCB0aGlzIGZ1bmN0aW9uIHNvIHRoYXQgZGV2ZWxvcGVycyBjYW4gb3ZlcnJpZGUgdGhpc1xuLy8gYmVoYXZpb3IgdG8gYWxsb3cgYXBwcyBmcm9tIGV4dGVybmFsIGRvbWFpbnMgdG8gbG9naW4gdXNpbmcgdGhlXG4vLyByZWRpcmVjdCBPQXV0aCBmbG93LlxuT0F1dGguX2NoZWNrUmVkaXJlY3RVcmxPcmlnaW4gPSByZWRpcmVjdFVybCA9PiB7XG4gIGNvbnN0IGFwcEhvc3QgPSBNZXRlb3IuYWJzb2x1dGVVcmwoKTtcbiAgY29uc3QgYXBwSG9zdFJlcGxhY2VkTG9jYWxob3N0ID0gTWV0ZW9yLmFic29sdXRlVXJsKHVuZGVmaW5lZCwge1xuICAgIHJlcGxhY2VMb2NhbGhvc3Q6IHRydWVcbiAgfSk7XG4gIHJldHVybiAoXG4gICAgcmVkaXJlY3RVcmwuc3Vic3RyKDAsIGFwcEhvc3QubGVuZ3RoKSAhPT0gYXBwSG9zdCAmJlxuICAgIHJlZGlyZWN0VXJsLnN1YnN0cigwLCBhcHBIb3N0UmVwbGFjZWRMb2NhbGhvc3QubGVuZ3RoKSAhPT0gYXBwSG9zdFJlcGxhY2VkTG9jYWxob3N0XG4gICk7XG59O1xuXG5jb25zdCBtaWRkbGV3YXJlID0gKHJlcSwgcmVzLCBuZXh0KSA9PiB7XG4gIGxldCByZXF1ZXN0RGF0YTtcblxuICAvLyBNYWtlIHN1cmUgdG8gY2F0Y2ggYW55IGV4Y2VwdGlvbnMgYmVjYXVzZSBvdGhlcndpc2Ugd2UnZCBjcmFzaFxuICAvLyB0aGUgcnVubmVyXG4gIHRyeSB7XG4gICAgY29uc3Qgc2VydmljZU5hbWUgPSBvYXV0aFNlcnZpY2VOYW1lKHJlcSk7XG4gICAgaWYgKCFzZXJ2aWNlTmFtZSkge1xuICAgICAgLy8gbm90IGFuIG9hdXRoIHJlcXVlc3QuIHBhc3MgdG8gbmV4dCBtaWRkbGV3YXJlLlxuICAgICAgbmV4dCgpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IHNlcnZpY2UgPSByZWdpc3RlcmVkU2VydmljZXNbc2VydmljZU5hbWVdO1xuXG4gICAgLy8gU2tpcCBldmVyeXRoaW5nIGlmIHRoZXJlJ3Mgbm8gc2VydmljZSBzZXQgYnkgdGhlIG9hdXRoIG1pZGRsZXdhcmVcbiAgICBpZiAoIXNlcnZpY2UpXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYFVuZXhwZWN0ZWQgT0F1dGggc2VydmljZSAke3NlcnZpY2VOYW1lfWApO1xuXG4gICAgLy8gTWFrZSBzdXJlIHdlJ3JlIGNvbmZpZ3VyZWRcbiAgICBlbnN1cmVDb25maWd1cmVkKHNlcnZpY2VOYW1lKTtcblxuICAgIGNvbnN0IGhhbmRsZXIgPSBPQXV0aC5fcmVxdWVzdEhhbmRsZXJzW3NlcnZpY2UudmVyc2lvbl07XG4gICAgaWYgKCFoYW5kbGVyKVxuICAgICAgdGhyb3cgbmV3IEVycm9yKGBVbmV4cGVjdGVkIE9BdXRoIHZlcnNpb24gJHtzZXJ2aWNlLnZlcnNpb259YCk7XG5cbiAgICBpZiAocmVxLm1ldGhvZCA9PT0gJ0dFVCcpIHtcbiAgICAgIHJlcXVlc3REYXRhID0gcmVxLnF1ZXJ5O1xuICAgIH0gZWxzZSB7XG4gICAgICByZXF1ZXN0RGF0YSA9IHJlcS5ib2R5O1xuICAgIH1cblxuICAgIGhhbmRsZXIoc2VydmljZSwgcmVxdWVzdERhdGEsIHJlcyk7XG4gIH0gY2F0Y2ggKGVycikge1xuICAgIC8vIGlmIHdlIGdvdCB0aHJvd24gYW4gZXJyb3IsIHNhdmUgaXQgb2ZmLCBpdCB3aWxsIGdldCBwYXNzZWQgdG9cbiAgICAvLyB0aGUgYXBwcm9wcmlhdGUgbG9naW4gY2FsbCAoaWYgYW55KSBhbmQgcmVwb3J0ZWQgdGhlcmUuXG4gICAgLy9cbiAgICAvLyBUaGUgb3RoZXIgb3B0aW9uIHdvdWxkIGJlIHRvIGRpc3BsYXkgaXQgaW4gdGhlIHBvcHVwIHRhYiB0aGF0XG4gICAgLy8gaXMgc3RpbGwgb3BlbiBhdCB0aGlzIHBvaW50LCBpZ25vcmluZyB0aGUgJ2Nsb3NlJyBvciAncmVkaXJlY3QnXG4gICAgLy8gd2Ugd2VyZSBwYXNzZWQuIEJ1dCB0aGVuIHRoZSBkZXZlbG9wZXIgd291bGRuJ3QgYmUgYWJsZSB0b1xuICAgIC8vIHN0eWxlIHRoZSBlcnJvciBvciByZWFjdCB0byBpdCBpbiBhbnkgd2F5LlxuICAgIGlmIChyZXF1ZXN0RGF0YT8uc3RhdGUgJiYgZXJyIGluc3RhbmNlb2YgRXJyb3IpIHtcbiAgICAgIHRyeSB7IC8vIGNhdGNoIGFueSBleGNlcHRpb25zIHRvIGF2b2lkIGNyYXNoaW5nIHJ1bm5lclxuICAgICAgICBPQXV0aC5fc3RvcmVQZW5kaW5nQ3JlZGVudGlhbChPQXV0aC5fY3JlZGVudGlhbFRva2VuRnJvbVF1ZXJ5KHJlcXVlc3REYXRhKSwgZXJyKTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICAvLyBJZ25vcmUgdGhlIGVycm9yIGFuZCBqdXN0IGdpdmUgdXAuIElmIHdlIGZhaWxlZCB0byBzdG9yZSB0aGVcbiAgICAgICAgLy8gZXJyb3IsIHRoZW4gdGhlIGxvZ2luIHdpbGwganVzdCBmYWlsIHdpdGggYSBnZW5lcmljIGVycm9yLlxuICAgICAgICBMb2cud2FybihcIkVycm9yIGluIE9BdXRoIFNlcnZlciB3aGlsZSBzdG9yaW5nIHBlbmRpbmcgbG9naW4gcmVzdWx0LlxcblwiICtcbiAgICAgICAgICAgICAgICAgZXJyLnN0YWNrIHx8IGVyci5tZXNzYWdlKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBjbG9zZSB0aGUgcG9wdXAuIGJlY2F1c2Ugbm9ib2R5IGxpa2VzIHRoZW0ganVzdCBoYW5naW5nXG4gICAgLy8gdGhlcmUuICB3aGVuIHNvbWVvbmUgc2VlcyB0aGlzIG11bHRpcGxlIHRpbWVzIHRoZXkgbWlnaHRcbiAgICAvLyB0aGluayB0byBjaGVjayBzZXJ2ZXIgbG9ncyAod2UgaG9wZT8pXG4gICAgLy8gQ2F0Y2ggZXJyb3JzIGJlY2F1c2UgYW55IGV4Y2VwdGlvbiBoZXJlIHdpbGwgY3Jhc2ggdGhlIHJ1bm5lci5cbiAgICB0cnkge1xuICAgICAgT0F1dGguX2VuZE9mTG9naW5SZXNwb25zZShyZXMsIHtcbiAgICAgICAgcXVlcnk6IHJlcXVlc3REYXRhLFxuICAgICAgICBsb2dpblN0eWxlOiBPQXV0aC5fbG9naW5TdHlsZUZyb21RdWVyeShyZXF1ZXN0RGF0YSksXG4gICAgICAgIGVycm9yOiBlcnJcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgTG9nLndhcm4oXCJFcnJvciBnZW5lcmF0aW5nIGVuZCBvZiBsb2dpbiByZXNwb25zZVxcblwiICtcbiAgICAgICAgICAgICAgIChlcnIgJiYgKGVyci5zdGFjayB8fCBlcnIubWVzc2FnZSkpKTtcbiAgICB9XG4gIH1cbn07XG5cbi8vIExpc3RlbiB0byBpbmNvbWluZyBPQXV0aCBodHRwIHJlcXVlc3RzXG5XZWJBcHAuY29ubmVjdEhhbmRsZXJzLnVzZSgnL19vYXV0aCcsIGJvZHlQYXJzZXIuanNvbigpKTtcbldlYkFwcC5jb25uZWN0SGFuZGxlcnMudXNlKCcvX29hdXRoJywgYm9keVBhcnNlci51cmxlbmNvZGVkKHsgZXh0ZW5kZWQ6IGZhbHNlIH0pKTtcbldlYkFwcC5jb25uZWN0SGFuZGxlcnMudXNlKG1pZGRsZXdhcmUpO1xuXG5PQXV0aFRlc3QubWlkZGxld2FyZSA9IG1pZGRsZXdhcmU7XG5cbi8vIEhhbmRsZSAvX29hdXRoLyogcGF0aHMgYW5kIGV4dHJhY3QgdGhlIHNlcnZpY2UgbmFtZS5cbi8vXG4vLyBAcmV0dXJucyB7U3RyaW5nfG51bGx9IGUuZy4gXCJmYWNlYm9va1wiLCBvciBudWxsIGlmIHRoaXMgaXNuJ3QgYW5cbi8vIG9hdXRoIHJlcXVlc3RcbmNvbnN0IG9hdXRoU2VydmljZU5hbWUgPSByZXEgPT4ge1xuICAvLyByZXEudXJsIHdpbGwgYmUgXCIvX29hdXRoLzxzZXJ2aWNlIG5hbWU+XCIgd2l0aCBhbiBvcHRpb25hbCBcIj9jbG9zZVwiLlxuICBjb25zdCBpID0gcmVxLnVybC5pbmRleE9mKCc/Jyk7XG4gIGxldCBiYXJlUGF0aDtcbiAgaWYgKGkgPT09IC0xKVxuICAgIGJhcmVQYXRoID0gcmVxLnVybDtcbiAgZWxzZVxuICAgIGJhcmVQYXRoID0gcmVxLnVybC5zdWJzdHJpbmcoMCwgaSk7XG4gIGNvbnN0IHNwbGl0UGF0aCA9IGJhcmVQYXRoLnNwbGl0KCcvJyk7XG5cbiAgLy8gQW55IG5vbi1vYXV0aCByZXF1ZXN0IHdpbGwgY29udGludWUgZG93biB0aGUgZGVmYXVsdFxuICAvLyBtaWRkbGV3YXJlcy5cbiAgaWYgKHNwbGl0UGF0aFsxXSAhPT0gJ19vYXV0aCcpXG4gICAgcmV0dXJuIG51bGw7XG5cbiAgLy8gRmluZCBzZXJ2aWNlIGJhc2VkIG9uIHVybFxuICBjb25zdCBzZXJ2aWNlTmFtZSA9IHNwbGl0UGF0aFsyXTtcbiAgcmV0dXJuIHNlcnZpY2VOYW1lO1xufTtcblxuLy8gTWFrZSBzdXJlIHdlJ3JlIGNvbmZpZ3VyZWRcbmNvbnN0IGVuc3VyZUNvbmZpZ3VyZWQgPSBzZXJ2aWNlTmFtZSA9PiB7XG4gIGlmICghU2VydmljZUNvbmZpZ3VyYXRpb24uY29uZmlndXJhdGlvbnMuZmluZE9uZSh7c2VydmljZTogc2VydmljZU5hbWV9KSkge1xuICAgIHRocm93IG5ldyBTZXJ2aWNlQ29uZmlndXJhdGlvbi5Db25maWdFcnJvcigpO1xuICB9XG59O1xuXG5jb25zdCBpc1NhZmUgPSB2YWx1ZSA9PiB7XG4gIC8vIFRoaXMgbWF0Y2hlcyBzdHJpbmdzIGdlbmVyYXRlZCBieSBgUmFuZG9tLnNlY3JldGAgYW5kXG4gIC8vIGBSYW5kb20uaWRgLlxuICByZXR1cm4gdHlwZW9mIHZhbHVlID09PSBcInN0cmluZ1wiICYmXG4gICAgL15bYS16QS1aMC05XFwtX10rJC8udGVzdCh2YWx1ZSk7XG59O1xuXG4vLyBJbnRlcm5hbDogdXNlZCBieSB0aGUgb2F1dGgxIGFuZCBvYXV0aDIgcGFja2FnZXNcbk9BdXRoLl9yZW5kZXJPYXV0aFJlc3VsdHMgPSAocmVzLCBxdWVyeSwgY3JlZGVudGlhbFNlY3JldCkgPT4ge1xuICAvLyBGb3IgdGVzdHMsIHdlIHN1cHBvcnQgdGhlIGBvbmx5X2NyZWRlbnRpYWxfc2VjcmV0X2Zvcl90ZXN0YFxuICAvLyBwYXJhbWV0ZXIsIHdoaWNoIGp1c3QgcmV0dXJucyB0aGUgY3JlZGVudGlhbCBzZWNyZXQgd2l0aG91dCBhbnlcbiAgLy8gc3Vycm91bmRpbmcgSFRNTC4gKFRoZSB0ZXN0IG5lZWRzIHRvIGJlIGFibGUgdG8gZWFzaWx5IGdyYWIgdGhlXG4gIC8vIHNlY3JldCBhbmQgdXNlIGl0IHRvIGxvZyBpbi4pXG4gIC8vXG4gIC8vIFhYWCBvbmx5X2NyZWRlbnRpYWxfc2VjcmV0X2Zvcl90ZXN0IGNvdWxkIGJlIHVzZWZ1bCBmb3Igb3RoZXJcbiAgLy8gdGhpbmdzIGJlc2lkZSB0ZXN0cywgbGlrZSBjb21tYW5kLWxpbmUgY2xpZW50cy4gV2Ugc2hvdWxkIGdpdmUgaXQgYVxuICAvLyByZWFsIG5hbWUgYW5kIHNlcnZlIHRoZSBjcmVkZW50aWFsIHNlY3JldCBpbiBKU09OLlxuXG4gIGlmIChxdWVyeS5vbmx5X2NyZWRlbnRpYWxfc2VjcmV0X2Zvcl90ZXN0KSB7XG4gICAgcmVzLndyaXRlSGVhZCgyMDAsIHsnQ29udGVudC1UeXBlJzogJ3RleHQvaHRtbCd9KTtcbiAgICByZXMuZW5kKGNyZWRlbnRpYWxTZWNyZXQsICd1dGYtOCcpO1xuICB9IGVsc2Uge1xuICAgIGNvbnN0IGRldGFpbHMgPSB7XG4gICAgICBxdWVyeSxcbiAgICAgIGxvZ2luU3R5bGU6IE9BdXRoLl9sb2dpblN0eWxlRnJvbVF1ZXJ5KHF1ZXJ5KVxuICAgIH07XG4gICAgaWYgKHF1ZXJ5LmVycm9yKSB7XG4gICAgICBkZXRhaWxzLmVycm9yID0gcXVlcnkuZXJyb3I7XG4gICAgfSBlbHNlIHtcbiAgICAgIGNvbnN0IHRva2VuID0gT0F1dGguX2NyZWRlbnRpYWxUb2tlbkZyb21RdWVyeShxdWVyeSk7XG4gICAgICBjb25zdCBzZWNyZXQgPSBjcmVkZW50aWFsU2VjcmV0O1xuICAgICAgaWYgKHRva2VuICYmIHNlY3JldCAmJlxuICAgICAgICAgIGlzU2FmZSh0b2tlbikgJiYgaXNTYWZlKHNlY3JldCkpIHtcbiAgICAgICAgZGV0YWlscy5jcmVkZW50aWFscyA9IHsgdG9rZW46IHRva2VuLCBzZWNyZXQ6IHNlY3JldH07XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBkZXRhaWxzLmVycm9yID0gXCJpbnZhbGlkX2NyZWRlbnRpYWxfdG9rZW5fb3Jfc2VjcmV0XCI7XG4gICAgICB9XG4gICAgfVxuXG4gICAgT0F1dGguX2VuZE9mTG9naW5SZXNwb25zZShyZXMsIGRldGFpbHMpO1xuICB9XG59O1xuXG4vLyBUaGlzIFwidGVtcGxhdGVcIiAobm90IGEgcmVhbCBTcGFjZWJhcnMgdGVtcGxhdGUsIGp1c3QgYW4gSFRNTCBmaWxlXG4vLyB3aXRoIHNvbWUgIyNQTEFDRUhPTERFUiMjcykgY29tbXVuaWNhdGVzIHRoZSBjcmVkZW50aWFsIHNlY3JldCBiYWNrXG4vLyB0byB0aGUgbWFpbiB3aW5kb3cgYW5kIHRoZW4gY2xvc2VzIHRoZSBwb3B1cC5cbk9BdXRoLl9lbmRPZlBvcHVwUmVzcG9uc2VUZW1wbGF0ZSA9IEFzc2V0cy5nZXRUZXh0KFxuICBcImVuZF9vZl9wb3B1cF9yZXNwb25zZS5odG1sXCIpO1xuXG5PQXV0aC5fZW5kT2ZSZWRpcmVjdFJlc3BvbnNlVGVtcGxhdGUgPSBBc3NldHMuZ2V0VGV4dChcbiAgXCJlbmRfb2ZfcmVkaXJlY3RfcmVzcG9uc2UuaHRtbFwiKTtcblxuLy8gUmVuZGVycyB0aGUgZW5kIG9mIGxvZ2luIHJlc3BvbnNlIHRlbXBsYXRlIGludG8gc29tZSBIVE1MIGFuZCBKYXZhU2NyaXB0XG4vLyB0aGF0IGNsb3NlcyB0aGUgcG9wdXAgb3IgcmVkaXJlY3RzIGF0IHRoZSBlbmQgb2YgdGhlIE9BdXRoIGZsb3cuXG4vL1xuLy8gb3B0aW9ucyBhcmU6XG4vLyAgIC0gbG9naW5TdHlsZSAoXCJwb3B1cFwiIG9yIFwicmVkaXJlY3RcIilcbi8vICAgLSBzZXRDcmVkZW50aWFsVG9rZW4gKGJvb2xlYW4pXG4vLyAgIC0gY3JlZGVudGlhbFRva2VuXG4vLyAgIC0gY3JlZGVudGlhbFNlY3JldFxuLy8gICAtIHJlZGlyZWN0VXJsXG4vLyAgIC0gaXNDb3Jkb3ZhIChib29sZWFuKVxuLy9cbmNvbnN0IHJlbmRlckVuZE9mTG9naW5SZXNwb25zZSA9IG9wdGlvbnMgPT4ge1xuICAvLyBJdCB3b3VsZCBiZSBuaWNlIHRvIHVzZSBCbGF6ZSBoZXJlLCBidXQgaXQncyBhIGxpdHRsZSB0cmlja3lcbiAgLy8gYmVjYXVzZSBvdXIgbXVzdGFjaGVzIHdvdWxkIGJlIGluc2lkZSBhIDxzY3JpcHQ+IHRhZywgYW5kIEJsYXplXG4gIC8vIHdvdWxkIHRyZWF0IHRoZSA8c2NyaXB0PiB0YWcgY29udGVudHMgYXMgdGV4dCAoZS5nLiBlbmNvZGUgJyYnIGFzXG4gIC8vICcmYW1wOycpLiBTbyB3ZSBqdXN0IGRvIGEgc2ltcGxlIHJlcGxhY2UuXG5cbiAgY29uc3QgZXNjYXBlID0gcyA9PiB7XG4gICAgaWYgKHMpIHtcbiAgICAgIHJldHVybiBzLnJlcGxhY2UoLyYvZywgXCImYW1wO1wiKS5cbiAgICAgICAgcmVwbGFjZSgvPC9nLCBcIiZsdDtcIikuXG4gICAgICAgIHJlcGxhY2UoLz4vZywgXCImZ3Q7XCIpLlxuICAgICAgICByZXBsYWNlKC9cXFwiL2csIFwiJnF1b3Q7XCIpLlxuICAgICAgICByZXBsYWNlKC9cXCcvZywgXCImI3gyNztcIikuXG4gICAgICAgIHJlcGxhY2UoL1xcLy9nLCBcIiYjeDJGO1wiKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuIHM7XG4gICAgfVxuICB9O1xuXG4gIC8vIEVzY2FwZSBldmVyeXRoaW5nIGp1c3QgdG8gYmUgc2FmZSAod2UndmUgYWxyZWFkeSBjaGVja2VkIHRoYXQgc29tZVxuICAvLyBvZiB0aGlzIGRhdGEgLS0gdGhlIHRva2VuIGFuZCBzZWNyZXQgLS0gYXJlIHNhZmUpLlxuICBjb25zdCBjb25maWcgPSB7XG4gICAgc2V0Q3JlZGVudGlhbFRva2VuOiAhISBvcHRpb25zLnNldENyZWRlbnRpYWxUb2tlbixcbiAgICBjcmVkZW50aWFsVG9rZW46IGVzY2FwZShvcHRpb25zLmNyZWRlbnRpYWxUb2tlbiksXG4gICAgY3JlZGVudGlhbFNlY3JldDogZXNjYXBlKG9wdGlvbnMuY3JlZGVudGlhbFNlY3JldCksXG4gICAgc3RvcmFnZVByZWZpeDogZXNjYXBlKE9BdXRoLl9zdG9yYWdlVG9rZW5QcmVmaXgpLFxuICAgIHJlZGlyZWN0VXJsOiBlc2NhcGUob3B0aW9ucy5yZWRpcmVjdFVybCksXG4gICAgaXNDb3Jkb3ZhOiAhISBvcHRpb25zLmlzQ29yZG92YVxuICB9O1xuXG4gIGxldCB0ZW1wbGF0ZTtcbiAgaWYgKG9wdGlvbnMubG9naW5TdHlsZSA9PT0gJ3BvcHVwJykge1xuICAgIHRlbXBsYXRlID0gT0F1dGguX2VuZE9mUG9wdXBSZXNwb25zZVRlbXBsYXRlO1xuICB9IGVsc2UgaWYgKG9wdGlvbnMubG9naW5TdHlsZSA9PT0gJ3JlZGlyZWN0Jykge1xuICAgIHRlbXBsYXRlID0gT0F1dGguX2VuZE9mUmVkaXJlY3RSZXNwb25zZVRlbXBsYXRlO1xuICB9IGVsc2Uge1xuICAgIHRocm93IG5ldyBFcnJvcihgaW52YWxpZCBsb2dpblN0eWxlOiAke29wdGlvbnMubG9naW5TdHlsZX1gKTtcbiAgfVxuXG4gIGNvbnN0IHJlc3VsdCA9IHRlbXBsYXRlLnJlcGxhY2UoLyMjQ09ORklHIyMvLCBKU09OLnN0cmluZ2lmeShjb25maWcpKVxuICAgIC5yZXBsYWNlKFxuICAgICAgLyMjUk9PVF9VUkxfUEFUSF9QUkVGSVgjIy8sIF9fbWV0ZW9yX3J1bnRpbWVfY29uZmlnX18uUk9PVF9VUkxfUEFUSF9QUkVGSVhcbiAgICApO1xuXG4gIHJldHVybiBgPCFET0NUWVBFIGh0bWw+XFxuJHtyZXN1bHR9YDtcbn07XG5cbi8vIFdyaXRlcyBhbiBIVFRQIHJlc3BvbnNlIHRvIHRoZSBwb3B1cCB3aW5kb3cgYXQgdGhlIGVuZCBvZiBhbiBPQXV0aFxuLy8gbG9naW4gZmxvdy4gQXQgdGhpcyBwb2ludCwgaWYgdGhlIHVzZXIgaGFzIHN1Y2Nlc3NmdWxseSBhdXRoZW50aWNhdGVkXG4vLyB0byB0aGUgT0F1dGggc2VydmVyIGFuZCBhdXRob3JpemVkIHRoaXMgYXBwLCB3ZSBjb21tdW5pY2F0ZSB0aGVcbi8vIGNyZWRlbnRpYWxUb2tlbiBhbmQgY3JlZGVudGlhbFNlY3JldCB0byB0aGUgbWFpbiB3aW5kb3cuIFRoZSBtYWluXG4vLyB3aW5kb3cgbXVzdCBwcm92aWRlIGJvdGggdGhlc2UgdmFsdWVzIHRvIHRoZSBERFAgYGxvZ2luYCBtZXRob2QgdG9cbi8vIGF1dGhlbnRpY2F0ZSBpdHMgRERQIGNvbm5lY3Rpb24uIEFmdGVyIGNvbW11bmljYXRpbmcgdGhlc2UgdmF1ZXMgdG9cbi8vIHRoZSBtYWluIHdpbmRvdywgd2UgY2xvc2UgdGhlIHBvcHVwLlxuLy9cbi8vIFdlIGV4cG9ydCB0aGlzIGZ1bmN0aW9uIHNvIHRoYXQgZGV2ZWxvcGVycyBjYW4gb3ZlcnJpZGUgdGhpc1xuLy8gYmVoYXZpb3IsIHdoaWNoIGlzIHBhcnRpY3VsYXJseSB1c2VmdWwgaW4sIGZvciBleGFtcGxlLCBzb21lIG1vYmlsZVxuLy8gZW52aXJvbm1lbnRzIHdoZXJlIHBvcHVwcyBhbmQvb3IgYHdpbmRvdy5vcGVuZXJgIGRvbid0IHdvcmsuIEZvclxuLy8gZXhhbXBsZSwgYW4gYXBwIGNvdWxkIG92ZXJyaWRlIGBPQXV0aC5fZW5kT2ZQb3B1cFJlc3BvbnNlYCB0byBwdXQgdGhlXG4vLyBjcmVkZW50aWFsIHRva2VuIGFuZCBjcmVkZW50aWFsIHNlY3JldCBpbiB0aGUgcG9wdXAgVVJMIGZvciB0aGUgbWFpblxuLy8gd2luZG93IHRvIHJlYWQgdGhlbSB0aGVyZSBpbnN0ZWFkIG9mIHVzaW5nIGB3aW5kb3cub3BlbmVyYC4gSWYgeW91XG4vLyBvdmVycmlkZSB0aGlzIGZ1bmN0aW9uLCB5b3UgdGFrZSByZXNwb25zaWJpbGl0eSBmb3Igd3JpdGluZyB0byB0aGVcbi8vIHJlcXVlc3QgYW5kIGNhbGxpbmcgYHJlcy5lbmQoKWAgdG8gY29tcGxldGUgdGhlIHJlcXVlc3QuXG4vL1xuLy8gQXJndW1lbnRzOlxuLy8gICAtIHJlczogdGhlIEhUVFAgcmVzcG9uc2Ugb2JqZWN0XG4vLyAgIC0gZGV0YWlsczpcbi8vICAgICAgLSBxdWVyeTogdGhlIHF1ZXJ5IHN0cmluZyBvbiB0aGUgSFRUUCByZXF1ZXN0XG4vLyAgICAgIC0gY3JlZGVudGlhbHM6IHsgdG9rZW46ICosIHNlY3JldDogKiB9LiBJZiBwcmVzZW50LCB0aGlzIGZpZWxkXG4vLyAgICAgICAgaW5kaWNhdGVzIHRoYXQgdGhlIGxvZ2luIHdhcyBzdWNjZXNzZnVsLiBSZXR1cm4gdGhlc2UgdmFsdWVzXG4vLyAgICAgICAgdG8gdGhlIGNsaWVudCwgd2hvIGNhbiB1c2UgdGhlbSB0byBsb2cgaW4gb3ZlciBERFAuIElmXG4vLyAgICAgICAgcHJlc2VudCwgdGhlIHZhbHVlcyBoYXZlIGJlZW4gY2hlY2tlZCBhZ2FpbnN0IGEgbGltaXRlZFxuLy8gICAgICAgIGNoYXJhY3RlciBzZXQgYW5kIGFyZSBzYWZlIHRvIGluY2x1ZGUgaW4gSFRNTC5cbi8vICAgICAgLSBlcnJvcjogaWYgcHJlc2VudCwgYSBzdHJpbmcgb3IgRXJyb3IgaW5kaWNhdGluZyBhbiBlcnJvciB0aGF0XG4vLyAgICAgICAgb2NjdXJyZWQgZHVyaW5nIHRoZSBsb2dpbi4gVGhpcyBjYW4gY29tZSBmcm9tIHRoZSBjbGllbnQgYW5kXG4vLyAgICAgICAgc28gc2hvdWxkbid0IGJlIHRydXN0ZWQgZm9yIHNlY3VyaXR5IGRlY2lzaW9ucyBvciBpbmNsdWRlZCBpblxuLy8gICAgICAgIHRoZSByZXNwb25zZSB3aXRob3V0IHNhbml0aXppbmcgaXQgZmlyc3QuIE9ubHkgb25lIG9mIGBlcnJvcmBcbi8vICAgICAgICBvciBgY3JlZGVudGlhbHNgIHNob3VsZCBiZSBzZXQuXG5PQXV0aC5fZW5kT2ZMb2dpblJlc3BvbnNlID0gKHJlcywgZGV0YWlscykgPT4ge1xuICByZXMud3JpdGVIZWFkKDIwMCwgeydDb250ZW50LVR5cGUnOiAndGV4dC9odG1sJ30pO1xuXG4gIGxldCByZWRpcmVjdFVybDtcbiAgaWYgKGRldGFpbHMubG9naW5TdHlsZSA9PT0gJ3JlZGlyZWN0Jykge1xuICAgIHJlZGlyZWN0VXJsID0gT0F1dGguX3N0YXRlRnJvbVF1ZXJ5KGRldGFpbHMucXVlcnkpLnJlZGlyZWN0VXJsO1xuICAgIGNvbnN0IGFwcEhvc3QgPSBNZXRlb3IuYWJzb2x1dGVVcmwoKTtcbiAgICBpZiAoXG4gICAgICAhTWV0ZW9yLnNldHRpbmdzPy5wYWNrYWdlcz8ub2F1dGg/LmRpc2FibGVDaGVja1JlZGlyZWN0VXJsT3JpZ2luICYmXG4gICAgICBPQXV0aC5fY2hlY2tSZWRpcmVjdFVybE9yaWdpbihyZWRpcmVjdFVybCkpIHtcbiAgICAgIGRldGFpbHMuZXJyb3IgPSBgcmVkaXJlY3RVcmwgKCR7cmVkaXJlY3RVcmx9YCArXG4gICAgICAgIGApIGlzIG5vdCBvbiB0aGUgc2FtZSBob3N0IGFzIHRoZSBhcHAgKCR7YXBwSG9zdH0pYDtcbiAgICAgIHJlZGlyZWN0VXJsID0gYXBwSG9zdDtcbiAgICB9XG4gIH1cblxuICBjb25zdCBpc0NvcmRvdmEgPSBPQXV0aC5faXNDb3Jkb3ZhRnJvbVF1ZXJ5KGRldGFpbHMucXVlcnkpO1xuXG4gIGlmIChkZXRhaWxzLmVycm9yKSB7XG4gICAgTG9nLndhcm4oXCJFcnJvciBpbiBPQXV0aCBTZXJ2ZXI6IFwiICtcbiAgICAgICAgICAgICAoZGV0YWlscy5lcnJvciBpbnN0YW5jZW9mIEVycm9yID9cbiAgICAgICAgICAgICAgZGV0YWlscy5lcnJvci5tZXNzYWdlIDogZGV0YWlscy5lcnJvcikpO1xuICAgIHJlcy5lbmQocmVuZGVyRW5kT2ZMb2dpblJlc3BvbnNlKHtcbiAgICAgIGxvZ2luU3R5bGU6IGRldGFpbHMubG9naW5TdHlsZSxcbiAgICAgIHNldENyZWRlbnRpYWxUb2tlbjogZmFsc2UsXG4gICAgICByZWRpcmVjdFVybCxcbiAgICAgIGlzQ29yZG92YSxcbiAgICB9KSwgXCJ1dGYtOFwiKTtcbiAgICByZXR1cm47XG4gIH1cblxuICAvLyBJZiB3ZSBoYXZlIGEgY3JlZGVudGlhbFNlY3JldCwgcmVwb3J0IGl0IGJhY2sgdG8gdGhlIHBhcmVudFxuICAvLyB3aW5kb3csIHdpdGggdGhlIGNvcnJlc3BvbmRpbmcgY3JlZGVudGlhbFRva2VuLiBUaGUgcGFyZW50IHdpbmRvd1xuICAvLyB1c2VzIHRoZSBjcmVkZW50aWFsVG9rZW4gYW5kIGNyZWRlbnRpYWxTZWNyZXQgdG8gbG9nIGluIG92ZXIgRERQLlxuICByZXMuZW5kKHJlbmRlckVuZE9mTG9naW5SZXNwb25zZSh7XG4gICAgbG9naW5TdHlsZTogZGV0YWlscy5sb2dpblN0eWxlLFxuICAgIHNldENyZWRlbnRpYWxUb2tlbjogdHJ1ZSxcbiAgICBjcmVkZW50aWFsVG9rZW46IGRldGFpbHMuY3JlZGVudGlhbHMudG9rZW4sXG4gICAgY3JlZGVudGlhbFNlY3JldDogZGV0YWlscy5jcmVkZW50aWFscy5zZWNyZXQsXG4gICAgcmVkaXJlY3RVcmwsXG4gICAgaXNDb3Jkb3ZhLFxuICB9KSwgXCJ1dGYtOFwiKTtcbn07XG5cblxuY29uc3QgT0F1dGhFbmNyeXB0aW9uID0gUGFja2FnZVtcIm9hdXRoLWVuY3J5cHRpb25cIl0gJiYgUGFja2FnZVtcIm9hdXRoLWVuY3J5cHRpb25cIl0uT0F1dGhFbmNyeXB0aW9uO1xuXG5jb25zdCB1c2luZ09BdXRoRW5jcnlwdGlvbiA9ICgpID0+XG4gIE9BdXRoRW5jcnlwdGlvbiAmJiBPQXV0aEVuY3J5cHRpb24ua2V5SXNMb2FkZWQoKTtcblxuLy8gRW5jcnlwdCBzZW5zaXRpdmUgc2VydmljZSBkYXRhIHN1Y2ggYXMgYWNjZXNzIHRva2VucyBpZiB0aGVcbi8vIFwib2F1dGgtZW5jcnlwdGlvblwiIHBhY2thZ2UgaXMgbG9hZGVkIGFuZCB0aGUgb2F1dGggc2VjcmV0IGtleSBoYXNcbi8vIGJlZW4gc3BlY2lmaWVkLiAgUmV0dXJucyB0aGUgdW5lbmNyeXB0ZWQgcGxhaW50ZXh0IG90aGVyd2lzZS5cbi8vXG4vLyBUaGUgdXNlciBpZCBpcyBub3Qgc3BlY2lmaWVkIGJlY2F1c2UgdGhlIHVzZXIgaXNuJ3Qga25vd24geWV0IGF0XG4vLyB0aGlzIHBvaW50IGluIHRoZSBvYXV0aCBhdXRoZW50aWNhdGlvbiBwcm9jZXNzLiAgQWZ0ZXIgdGhlIG9hdXRoXG4vLyBhdXRoZW50aWNhdGlvbiBwcm9jZXNzIGNvbXBsZXRlcyB0aGUgZW5jcnlwdGVkIHNlcnZpY2UgZGF0YSBmaWVsZHNcbi8vIHdpbGwgYmUgcmUtZW5jcnlwdGVkIHdpdGggdGhlIHVzZXIgaWQgaW5jbHVkZWQgYmVmb3JlIGluc2VydGluZyB0aGVcbi8vIHNlcnZpY2UgZGF0YSBpbnRvIHRoZSB1c2VyIGRvY3VtZW50LlxuLy9cbk9BdXRoLnNlYWxTZWNyZXQgPSBwbGFpbnRleHQgPT4ge1xuICBpZiAodXNpbmdPQXV0aEVuY3J5cHRpb24oKSlcbiAgICByZXR1cm4gT0F1dGhFbmNyeXB0aW9uLnNlYWwocGxhaW50ZXh0KTtcbiAgZWxzZVxuICAgIHJldHVybiBwbGFpbnRleHQ7XG59O1xuXG4vLyBVbmVuY3J5cHQgYSBzZXJ2aWNlIGRhdGEgZmllbGQsIGlmIHRoZSBcIm9hdXRoLWVuY3J5cHRpb25cIlxuLy8gcGFja2FnZSBpcyBsb2FkZWQgYW5kIHRoZSBmaWVsZCBpcyBlbmNyeXB0ZWQuXG4vL1xuLy8gVGhyb3dzIGFuIGVycm9yIGlmIHRoZSBcIm9hdXRoLWVuY3J5cHRpb25cIiBwYWNrYWdlIGlzIGxvYWRlZCBhbmQgdGhlXG4vLyBmaWVsZCBpcyBlbmNyeXB0ZWQsIGJ1dCB0aGUgb2F1dGggc2VjcmV0IGtleSBoYXNuJ3QgYmVlbiBzcGVjaWZpZWQuXG4vL1xuT0F1dGgub3BlblNlY3JldCA9IChtYXliZVNlY3JldCwgdXNlcklkKSA9PiB7XG4gIGlmICghUGFja2FnZVtcIm9hdXRoLWVuY3J5cHRpb25cIl0gfHwgIU9BdXRoRW5jcnlwdGlvbi5pc1NlYWxlZChtYXliZVNlY3JldCkpXG4gICAgcmV0dXJuIG1heWJlU2VjcmV0O1xuXG4gIHJldHVybiBPQXV0aEVuY3J5cHRpb24ub3BlbihtYXliZVNlY3JldCwgdXNlcklkKTtcbn07XG5cbi8vIFVuZW5jcnlwdCBmaWVsZHMgaW4gdGhlIHNlcnZpY2UgZGF0YSBvYmplY3QuXG4vL1xuT0F1dGgub3BlblNlY3JldHMgPSAoc2VydmljZURhdGEsIHVzZXJJZCkgPT4ge1xuICBjb25zdCByZXN1bHQgPSB7fTtcbiAgT2JqZWN0LmtleXMoc2VydmljZURhdGEpLmZvckVhY2goa2V5ID0+XG4gICAgcmVzdWx0W2tleV0gPSBPQXV0aC5vcGVuU2VjcmV0KHNlcnZpY2VEYXRhW2tleV0sIHVzZXJJZClcbiAgKTtcbiAgcmV0dXJuIHJlc3VsdDtcbn07XG4iLCIvL1xuLy8gV2hlbiBhbiBvYXV0aCByZXF1ZXN0IGlzIG1hZGUsIE1ldGVvciByZWNlaXZlcyBvYXV0aCBjcmVkZW50aWFsc1xuLy8gaW4gb25lIGJyb3dzZXIgdGFiLCBhbmQgdGVtcG9yYXJpbHkgcGVyc2lzdHMgdGhlbSB3aGlsZSB0aGF0XG4vLyB0YWIgaXMgY2xvc2VkLCB0aGVuIHJldHJpZXZlcyB0aGVtIGluIHRoZSBicm93c2VyIHRhYiB0aGF0XG4vLyBpbml0aWF0ZWQgdGhlIGNyZWRlbnRpYWwgcmVxdWVzdC5cbi8vXG4vLyBfcGVuZGluZ0NyZWRlbnRpYWxzIGlzIHRoZSBzdG9yYWdlIG1lY2hhbmlzbSB1c2VkIHRvIHNoYXJlIHRoZVxuLy8gY3JlZGVudGlhbCBiZXR3ZWVuIHRoZSAyIHRhYnNcbi8vXG5cblxuLy8gQ29sbGVjdGlvbiBjb250YWluaW5nIHBlbmRpbmcgY3JlZGVudGlhbHMgb2Ygb2F1dGggY3JlZGVudGlhbCByZXF1ZXN0c1xuLy8gSGFzIGtleSwgY3JlZGVudGlhbCwgYW5kIGNyZWF0ZWRBdCBmaWVsZHMuXG5PQXV0aC5fcGVuZGluZ0NyZWRlbnRpYWxzID0gbmV3IE1vbmdvLkNvbGxlY3Rpb24oXG4gIFwibWV0ZW9yX29hdXRoX3BlbmRpbmdDcmVkZW50aWFsc1wiLCB7XG4gICAgX3ByZXZlbnRBdXRvcHVibGlzaDogdHJ1ZVxuICB9KTtcblxuT0F1dGguX3BlbmRpbmdDcmVkZW50aWFscy5jcmVhdGVJbmRleCgna2V5JywgeyB1bmlxdWU6IHRydWUgfSk7XG5PQXV0aC5fcGVuZGluZ0NyZWRlbnRpYWxzLmNyZWF0ZUluZGV4KCdjcmVkZW50aWFsU2VjcmV0Jyk7XG5PQXV0aC5fcGVuZGluZ0NyZWRlbnRpYWxzLmNyZWF0ZUluZGV4KCdjcmVhdGVkQXQnKTtcblxuXG5cbi8vIFBlcmlvZGljYWxseSBjbGVhciBvbGQgZW50cmllcyB0aGF0IHdlcmUgbmV2ZXIgcmV0cmlldmVkXG5jb25zdCBfY2xlYW5TdGFsZVJlc3VsdHMgPSAoKSA9PiB7XG4gIC8vIFJlbW92ZSBjcmVkZW50aWFscyBvbGRlciB0aGFuIDEgbWludXRlXG4gIGNvbnN0IHRpbWVDdXRvZmYgPSBuZXcgRGF0ZSgpO1xuICB0aW1lQ3V0b2ZmLnNldE1pbnV0ZXModGltZUN1dG9mZi5nZXRNaW51dGVzKCkgLSAxKTtcbiAgT0F1dGguX3BlbmRpbmdDcmVkZW50aWFscy5yZW1vdmUoeyBjcmVhdGVkQXQ6IHsgJGx0OiB0aW1lQ3V0b2ZmIH0gfSk7XG59O1xuY29uc3QgX2NsZWFudXBIYW5kbGUgPSBNZXRlb3Iuc2V0SW50ZXJ2YWwoX2NsZWFuU3RhbGVSZXN1bHRzLCA2MCAqIDEwMDApO1xuXG5cbi8vIFN0b3JlcyB0aGUga2V5IGFuZCBjcmVkZW50aWFsIGluIHRoZSBfcGVuZGluZ0NyZWRlbnRpYWxzIGNvbGxlY3Rpb24uXG4vLyBXaWxsIHRocm93IGFuIGV4Y2VwdGlvbiBpZiBga2V5YCBpcyBub3QgYSBzdHJpbmcuXG4vL1xuLy8gQHBhcmFtIGtleSB7c3RyaW5nfVxuLy8gQHBhcmFtIGNyZWRlbnRpYWwge09iamVjdH0gICBUaGUgY3JlZGVudGlhbCB0byBzdG9yZVxuLy8gQHBhcmFtIGNyZWRlbnRpYWxTZWNyZXQge3N0cmluZ30gQSBzZWNyZXQgdGhhdCBtdXN0IGJlIHByZXNlbnRlZCBpblxuLy8gICBhZGRpdGlvbiB0byB0aGUgYGtleWAgdG8gcmV0cmlldmUgdGhlIGNyZWRlbnRpYWxcbi8vXG5PQXV0aC5fc3RvcmVQZW5kaW5nQ3JlZGVudGlhbCA9IChrZXksIGNyZWRlbnRpYWwsIGNyZWRlbnRpYWxTZWNyZXQgPSBudWxsKSA9PiB7XG4gIGNoZWNrKGtleSwgU3RyaW5nKTtcbiAgY2hlY2soY3JlZGVudGlhbFNlY3JldCwgTWF0Y2guTWF5YmUoU3RyaW5nKSk7XG5cbiAgaWYgKGNyZWRlbnRpYWwgaW5zdGFuY2VvZiBFcnJvcikge1xuICAgIGNyZWRlbnRpYWwgPSBzdG9yYWJsZUVycm9yKGNyZWRlbnRpYWwpO1xuICB9IGVsc2Uge1xuICAgIGNyZWRlbnRpYWwgPSBPQXV0aC5zZWFsU2VjcmV0KGNyZWRlbnRpYWwpO1xuICB9XG5cbiAgLy8gV2UgZG8gYW4gdXBzZXJ0IGhlcmUgaW5zdGVhZCBvZiBhbiBpbnNlcnQgaW4gY2FzZSB0aGUgdXNlciBoYXBwZW5zXG4gIC8vIHRvIHNvbWVob3cgc2VuZCB0aGUgc2FtZSBgc3RhdGVgIHBhcmFtZXRlciB0d2ljZSBkdXJpbmcgYW4gT0F1dGhcbiAgLy8gbG9naW47IHdlIGRvbid0IHdhbnQgYSBkdXBsaWNhdGUga2V5IGVycm9yLlxuICBPQXV0aC5fcGVuZGluZ0NyZWRlbnRpYWxzLnVwc2VydCh7XG4gICAga2V5LFxuICB9LCB7XG4gICAga2V5LFxuICAgIGNyZWRlbnRpYWwsXG4gICAgY3JlZGVudGlhbFNlY3JldCxcbiAgICBjcmVhdGVkQXQ6IG5ldyBEYXRlKClcbiAgfSk7XG59O1xuXG5cbi8vIFJldHJpZXZlcyBhbmQgcmVtb3ZlcyBhIGNyZWRlbnRpYWwgZnJvbSB0aGUgX3BlbmRpbmdDcmVkZW50aWFscyBjb2xsZWN0aW9uXG4vL1xuLy8gQHBhcmFtIGtleSB7c3RyaW5nfVxuLy8gQHBhcmFtIGNyZWRlbnRpYWxTZWNyZXQge3N0cmluZ31cbi8vXG5PQXV0aC5fcmV0cmlldmVQZW5kaW5nQ3JlZGVudGlhbCA9IChrZXksIGNyZWRlbnRpYWxTZWNyZXQgPSBudWxsKSA9PiB7XG4gIGNoZWNrKGtleSwgU3RyaW5nKTtcblxuICBjb25zdCBwZW5kaW5nQ3JlZGVudGlhbCA9IE9BdXRoLl9wZW5kaW5nQ3JlZGVudGlhbHMuZmluZE9uZSh7XG4gICAga2V5LFxuICAgIGNyZWRlbnRpYWxTZWNyZXQsXG4gIH0pO1xuXG4gIGlmIChwZW5kaW5nQ3JlZGVudGlhbCkge1xuICAgIE9BdXRoLl9wZW5kaW5nQ3JlZGVudGlhbHMucmVtb3ZlKHsgX2lkOiBwZW5kaW5nQ3JlZGVudGlhbC5faWQgfSk7XG4gICAgaWYgKHBlbmRpbmdDcmVkZW50aWFsLmNyZWRlbnRpYWwuZXJyb3IpXG4gICAgICByZXR1cm4gcmVjcmVhdGVFcnJvcihwZW5kaW5nQ3JlZGVudGlhbC5jcmVkZW50aWFsLmVycm9yKTtcbiAgICBlbHNlXG4gICAgICByZXR1cm4gT0F1dGgub3BlblNlY3JldChwZW5kaW5nQ3JlZGVudGlhbC5jcmVkZW50aWFsKTtcbiAgfSBlbHNlIHtcbiAgICByZXR1cm4gdW5kZWZpbmVkO1xuICB9XG59O1xuXG5cbi8vIENvbnZlcnQgYW4gRXJyb3IgaW50byBhbiBvYmplY3QgdGhhdCBjYW4gYmUgc3RvcmVkIGluIG1vbmdvXG4vLyBOb3RlOiBBIE1ldGVvci5FcnJvciBpcyByZWNvbnN0cnVjdGVkIGFzIGEgTWV0ZW9yLkVycm9yXG4vLyBBbGwgb3RoZXIgZXJyb3IgY2xhc3NlcyBhcmUgcmVjb25zdHJ1Y3RlZCBhcyBhIHBsYWluIEVycm9yLlxuLy8gVE9ETzogQ2FuIHdlIGRvIHRoaXMgbW9yZSBzaW1wbHkgd2l0aCBFSlNPTj9cbmNvbnN0IHN0b3JhYmxlRXJyb3IgPSBlcnJvciA9PiB7XG4gIGNvbnN0IHBsYWluT2JqZWN0ID0ge307XG4gIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKGVycm9yKS5mb3JFYWNoKFxuICAgIGtleSA9PiBwbGFpbk9iamVjdFtrZXldID0gZXJyb3Jba2V5XVxuICApO1xuXG4gIC8vIEtlZXAgdHJhY2sgb2Ygd2hldGhlciBpdCdzIGEgTWV0ZW9yLkVycm9yXG4gIGlmKGVycm9yIGluc3RhbmNlb2YgTWV0ZW9yLkVycm9yKSB7XG4gICAgcGxhaW5PYmplY3RbJ21ldGVvckVycm9yJ10gPSB0cnVlO1xuICB9XG5cbiAgcmV0dXJuIHsgZXJyb3I6IHBsYWluT2JqZWN0IH07XG59O1xuXG4vLyBDcmVhdGUgYW4gZXJyb3IgZnJvbSB0aGUgZXJyb3IgZm9ybWF0IHN0b3JlZCBpbiBtb25nb1xuY29uc3QgcmVjcmVhdGVFcnJvciA9IGVycm9yRG9jID0+IHtcbiAgbGV0IGVycm9yO1xuXG4gIGlmIChlcnJvckRvYy5tZXRlb3JFcnJvcikge1xuICAgIGVycm9yID0gbmV3IE1ldGVvci5FcnJvcigpO1xuICAgIGRlbGV0ZSBlcnJvckRvYy5tZXRlb3JFcnJvcjtcbiAgfSBlbHNlIHtcbiAgICBlcnJvciA9IG5ldyBFcnJvcigpO1xuICB9XG5cbiAgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXMoZXJyb3JEb2MpLmZvckVhY2goa2V5ID0+XG4gICAgZXJyb3Jba2V5XSA9IGVycm9yRG9jW2tleV1cbiAgKTtcblxuICByZXR1cm4gZXJyb3I7XG59O1xuIiwiT0F1dGguX3N0b3JhZ2VUb2tlblByZWZpeCA9IFwiTWV0ZW9yLm9hdXRoLmNyZWRlbnRpYWxTZWNyZXQtXCI7XG5cbk9BdXRoLl9yZWRpcmVjdFVyaSA9IChzZXJ2aWNlTmFtZSwgY29uZmlnLCBwYXJhbXMsIGFic29sdXRlVXJsT3B0aW9ucykgPT4ge1xuICAvLyBDbG9uZSBiZWNhdXNlIHdlJ3JlIGdvaW5nIHRvIG11dGF0ZSAncGFyYW1zJy4gVGhlICdjb3Jkb3ZhJyBhbmRcbiAgLy8gJ2FuZHJvaWQnIHBhcmFtZXRlcnMgYXJlIG9ubHkgdXNlZCBmb3IgcGlja2luZyB0aGUgaG9zdCBvZiB0aGVcbiAgLy8gcmVkaXJlY3QgVVJMLCBhbmQgbm90IGFjdHVhbGx5IGluY2x1ZGVkIGluIHRoZSByZWRpcmVjdCBVUkwgaXRzZWxmLlxuICBsZXQgaXNDb3Jkb3ZhID0gZmFsc2U7XG4gIGxldCBpc0FuZHJvaWQgPSBmYWxzZTtcbiAgaWYgKHBhcmFtcykge1xuICAgIHBhcmFtcyA9IHsgLi4ucGFyYW1zIH07XG4gICAgaXNDb3Jkb3ZhID0gcGFyYW1zLmNvcmRvdmE7XG4gICAgaXNBbmRyb2lkID0gcGFyYW1zLmFuZHJvaWQ7XG4gICAgZGVsZXRlIHBhcmFtcy5jb3Jkb3ZhO1xuICAgIGRlbGV0ZSBwYXJhbXMuYW5kcm9pZDtcbiAgICBpZiAoT2JqZWN0LmtleXMocGFyYW1zKS5sZW5ndGggPT09IDApIHtcbiAgICAgIHBhcmFtcyA9IHVuZGVmaW5lZDtcbiAgICB9XG4gIH1cblxuICBpZiAoTWV0ZW9yLmlzU2VydmVyICYmIGlzQ29yZG92YSkge1xuICAgIGNvbnN0IHVybCA9IE5wbS5yZXF1aXJlKCd1cmwnKTtcbiAgICBsZXQgcm9vdFVybCA9IHByb2Nlc3MuZW52Lk1PQklMRV9ST09UX1VSTCB8fFxuICAgICAgICAgIF9fbWV0ZW9yX3J1bnRpbWVfY29uZmlnX18uUk9PVF9VUkw7XG5cbiAgICBpZiAoaXNBbmRyb2lkKSB7XG4gICAgICAvLyBNYXRjaCB0aGUgcmVwbGFjZSB0aGF0IHdlIGRvIGluIGNvcmRvdmEgYm9pbGVycGxhdGVcbiAgICAgIC8vIChib2lsZXJwbGF0ZS1nZW5lcmF0b3IgcGFja2FnZSkuXG4gICAgICAvLyBYWFggTWF5YmUgd2Ugc2hvdWxkIHB1dCB0aGlzIGluIGEgc2VwYXJhdGUgcGFja2FnZSBvciBzb21ldGhpbmdcbiAgICAgIC8vIHRoYXQgaXMgdXNlZCBoZXJlIGFuZCBieSBib2lsZXJwbGF0ZS1nZW5lcmF0b3I/IE9yIG1heWJlXG4gICAgICAvLyBgTWV0ZW9yLmFic29sdXRlVXJsYCBzaG91bGQga25vdyBob3cgdG8gZG8gdGhpcz9cbiAgICAgIGNvbnN0IHBhcnNlZFJvb3RVcmwgPSB1cmwucGFyc2Uocm9vdFVybCk7XG4gICAgICBpZiAocGFyc2VkUm9vdFVybC5ob3N0bmFtZSA9PT0gXCJsb2NhbGhvc3RcIikge1xuICAgICAgICBwYXJzZWRSb290VXJsLmhvc3RuYW1lID0gXCIxMC4wLjIuMlwiO1xuICAgICAgICBkZWxldGUgcGFyc2VkUm9vdFVybC5ob3N0O1xuICAgICAgfVxuICAgICAgcm9vdFVybCA9IHVybC5mb3JtYXQocGFyc2VkUm9vdFVybCk7XG4gICAgfVxuXG4gICAgYWJzb2x1dGVVcmxPcHRpb25zID0ge1xuICAgICAgLi4uYWJzb2x1dGVVcmxPcHRpb25zLFxuICAgICAgLy8gRm9yIENvcmRvdmEgY2xpZW50cywgcmVkaXJlY3QgdG8gdGhlIHNwZWNpYWwgQ29yZG92YSByb290IHVybFxuICAgICAgLy8gKGxpa2VseSBhIGxvY2FsIElQIGluIGRldmVsb3BtZW50IG1vZGUpLlxuICAgICAgcm9vdFVybCxcbiAgICB9O1xuICB9XG5cbiAgcmV0dXJuIFVSTC5fY29uc3RydWN0VXJsKFxuICAgIE1ldGVvci5hYnNvbHV0ZVVybChgX29hdXRoLyR7c2VydmljZU5hbWV9YCwgYWJzb2x1dGVVcmxPcHRpb25zKSxcbiAgICBudWxsLFxuICAgIHBhcmFtcyk7XG59O1xuIl19
