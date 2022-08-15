(function () {

/* Imports */
var Meteor = Package.meteor.Meteor;
var global = Package.meteor.global;
var meteorEnv = Package.meteor.meteorEnv;
var ECMAScript = Package.ecmascript.ECMAScript;
var DDPRateLimiter = Package['ddp-rate-limiter'].DDPRateLimiter;
var check = Package.check.check;
var Match = Package.check.Match;
var Random = Package.random.Random;
var EJSON = Package.ejson.EJSON;
var Hook = Package['callback-hook'].Hook;
var URL = Package.url.URL;
var URLSearchParams = Package.url.URLSearchParams;
var DDP = Package['ddp-client'].DDP;
var DDPServer = Package['ddp-server'].DDPServer;
var MongoInternals = Package.mongo.MongoInternals;
var Mongo = Package.mongo.Mongo;
var meteorInstall = Package.modules.meteorInstall;
var Promise = Package.promise.Promise;

/* Package-scope variables */
var Accounts, options, stampedLoginToken, handler, name, query, oldestValidDate, user;

var require = meteorInstall({"node_modules":{"meteor":{"accounts-base":{"server_main.js":function module(require,exports,module){

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                   //
// packages/accounts-base/server_main.js                                                                             //
//                                                                                                                   //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                     //
!function (module1) {
  module1.export({
    AccountsServer: () => AccountsServer
  });
  let AccountsServer;
  module1.link("./accounts_server.js", {
    AccountsServer(v) {
      AccountsServer = v;
    }

  }, 0);

  /**
   * @namespace Accounts
   * @summary The namespace for all server-side accounts-related methods.
   */
  Accounts = new AccountsServer(Meteor.server); // Users table. Don't use the normal autopublish, since we want to hide
  // some fields. Code to autopublish this is in accounts_server.js.
  // XXX Allow users to configure this collection name.

  /**
   * @summary A [Mongo.Collection](#collections) containing user documents.
   * @locus Anywhere
   * @type {Mongo.Collection}
   * @importFromPackage meteor
  */

  Meteor.users = Accounts.users;
}.call(this, module);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

},"accounts_common.js":function module(require,exports,module){

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                   //
// packages/accounts-base/accounts_common.js                                                                         //
//                                                                                                                   //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                     //
let _objectSpread;

module.link("@babel/runtime/helpers/objectSpread2", {
  default(v) {
    _objectSpread = v;
  }

}, 0);
module.export({
  AccountsCommon: () => AccountsCommon,
  EXPIRE_TOKENS_INTERVAL_MS: () => EXPIRE_TOKENS_INTERVAL_MS,
  CONNECTION_CLOSE_DELAY_MS: () => CONNECTION_CLOSE_DELAY_MS
});
let Meteor;
module.link("meteor/meteor", {
  Meteor(v) {
    Meteor = v;
  }

}, 0);
// config option keys
const VALID_CONFIG_KEYS = ['sendVerificationEmail', 'forbidClientAccountCreation', 'passwordEnrollTokenExpiration', 'passwordEnrollTokenExpirationInDays', 'restrictCreationByEmailDomain', 'loginExpirationInDays', 'loginExpiration', 'passwordResetTokenExpirationInDays', 'passwordResetTokenExpiration', 'ambiguousErrorMessages', 'bcryptRounds', 'defaultFieldSelector'];
/**
 * @summary Super-constructor for AccountsClient and AccountsServer.
 * @locus Anywhere
 * @class AccountsCommon
 * @instancename accountsClientOrServer
 * @param options {Object} an object with fields:
 * - connection {Object} Optional DDP connection to reuse.
 * - ddpUrl {String} Optional URL for creating a new DDP connection.
 */

class AccountsCommon {
  constructor(options) {
    // Currently this is read directly by packages like accounts-password
    // and accounts-ui-unstyled.
    this._options = {}; // Note that setting this.connection = null causes this.users to be a
    // LocalCollection, which is not what we want.

    this.connection = undefined;

    this._initConnection(options || {}); // There is an allow call in accounts_server.js that restricts writes to
    // this collection.


    this.users = new Mongo.Collection('users', {
      _preventAutopublish: true,
      connection: this.connection
    }); // Callback exceptions are printed with Meteor._debug and ignored.

    this._onLoginHook = new Hook({
      bindEnvironment: false,
      debugPrintExceptions: 'onLogin callback'
    });
    this._onLoginFailureHook = new Hook({
      bindEnvironment: false,
      debugPrintExceptions: 'onLoginFailure callback'
    });
    this._onLogoutHook = new Hook({
      bindEnvironment: false,
      debugPrintExceptions: 'onLogout callback'
    }); // Expose for testing.

    this.DEFAULT_LOGIN_EXPIRATION_DAYS = DEFAULT_LOGIN_EXPIRATION_DAYS;
    this.LOGIN_UNEXPIRING_TOKEN_DAYS = LOGIN_UNEXPIRING_TOKEN_DAYS; // Thrown when the user cancels the login process (eg, closes an oauth
    // popup, declines retina scan, etc)

    const lceName = 'Accounts.LoginCancelledError';
    this.LoginCancelledError = Meteor.makeErrorType(lceName, function (description) {
      this.message = description;
    });
    this.LoginCancelledError.prototype.name = lceName; // This is used to transmit specific subclass errors over the wire. We
    // should come up with a more generic way to do this (eg, with some sort of
    // symbolic error code rather than a number).

    this.LoginCancelledError.numericError = 0x8acdc2f; // loginServiceConfiguration and ConfigError are maintained for backwards compatibility

    Meteor.startup(() => {
      var _Meteor$settings, _Meteor$settings$pack;

      const {
        ServiceConfiguration
      } = Package['service-configuration'];
      this.loginServiceConfiguration = ServiceConfiguration.configurations;
      this.ConfigError = ServiceConfiguration.ConfigError;
      const settings = (_Meteor$settings = Meteor.settings) === null || _Meteor$settings === void 0 ? void 0 : (_Meteor$settings$pack = _Meteor$settings.packages) === null || _Meteor$settings$pack === void 0 ? void 0 : _Meteor$settings$pack['accounts-base'];

      if (settings) {
        if (settings.oauthSecretKey) {
          if (!Package['oauth-encryption']) {
            throw new Error('The oauth-encryption package must be loaded to set oauthSecretKey');
          }

          Package['oauth-encryption'].OAuthEncryption.loadKey(settings.oauthSecretKey);
          delete settings.oauthSecretKey;
        } // Validate config options keys


        Object.keys(settings).forEach(key => {
          if (!VALID_CONFIG_KEYS.includes(key)) {
            // TODO Consider just logging a debug message instead to allow for additional keys in the settings here?
            throw new Meteor.Error("Accounts configuration: Invalid key: ".concat(key));
          } else {
            // set values in Accounts._options
            this._options[key] = settings[key];
          }
        });
      }
    });
  }
  /**
   * @summary Get the current user id, or `null` if no user is logged in. A reactive data source.
   * @locus Anywhere
   */


  userId() {
    throw new Error('userId method not implemented');
  } // merge the defaultFieldSelector with an existing options object


  _addDefaultFieldSelector() {
    let options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
    // this will be the most common case for most people, so make it quick
    if (!this._options.defaultFieldSelector) return options; // if no field selector then just use defaultFieldSelector

    if (!options.fields) return _objectSpread(_objectSpread({}, options), {}, {
      fields: this._options.defaultFieldSelector
    }); // if empty field selector then the full user object is explicitly requested, so obey

    const keys = Object.keys(options.fields);
    if (!keys.length) return options; // if the requested fields are +ve then ignore defaultFieldSelector
    // assume they are all either +ve or -ve because Mongo doesn't like mixed

    if (!!options.fields[keys[0]]) return options; // The requested fields are -ve.
    // If the defaultFieldSelector is +ve then use requested fields, otherwise merge them

    const keys2 = Object.keys(this._options.defaultFieldSelector);
    return this._options.defaultFieldSelector[keys2[0]] ? options : _objectSpread(_objectSpread({}, options), {}, {
      fields: _objectSpread(_objectSpread({}, options.fields), this._options.defaultFieldSelector)
    });
  }
  /**
   * @summary Get the current user record, or `null` if no user is logged in. A reactive data source.
   * @locus Anywhere
   * @param {Object} [options]
   * @param {MongoFieldSpecifier} options.fields Dictionary of fields to return or exclude.
   */


  user(options) {
    const userId = this.userId();
    return userId ? this.users.findOne(userId, this._addDefaultFieldSelector(options)) : null;
  } // Set up config for the accounts system. Call this on both the client
  // and the server.
  //
  // Note that this method gets overridden on AccountsServer.prototype, but
  // the overriding method calls the overridden method.
  //
  // XXX we should add some enforcement that this is called on both the
  // client and the server. Otherwise, a user can
  // 'forbidClientAccountCreation' only on the client and while it looks
  // like their app is secure, the server will still accept createUser
  // calls. https://github.com/meteor/meteor/issues/828
  //
  // @param options {Object} an object with fields:
  // - sendVerificationEmail {Boolean}
  //     Send email address verification emails to new users created from
  //     client signups.
  // - forbidClientAccountCreation {Boolean}
  //     Do not allow clients to create accounts directly.
  // - restrictCreationByEmailDomain {Function or String}
  //     Require created users to have an email matching the function or
  //     having the string as domain.
  // - loginExpirationInDays {Number}
  //     Number of days since login until a user is logged out (login token
  //     expires).
  // - passwordResetTokenExpirationInDays {Number}
  //     Number of days since password reset token creation until the
  //     token cannt be used any longer (password reset token expires).
  // - ambiguousErrorMessages {Boolean}
  //     Return ambiguous error messages from login failures to prevent
  //     user enumeration.
  // - bcryptRounds {Number}
  //     Allows override of number of bcrypt rounds (aka work factor) used
  //     to store passwords.

  /**
   * @summary Set global accounts options. You can also set these in `Meteor.settings.packages.accounts` without the need to call this function.
   * @locus Anywhere
   * @param {Object} options
   * @param {Boolean} options.sendVerificationEmail New users with an email address will receive an address verification email.
   * @param {Boolean} options.forbidClientAccountCreation Calls to [`createUser`](#accounts_createuser) from the client will be rejected. In addition, if you are using [accounts-ui](#accountsui), the "Create account" link will not be available.
   * @param {String | Function} options.restrictCreationByEmailDomain If set to a string, only allows new users if the domain part of their email address matches the string. If set to a function, only allows new users if the function returns true.  The function is passed the full email address of the proposed new user.  Works with password-based sign-in and external services that expose email addresses (Google, Facebook, GitHub). All existing users still can log in after enabling this option. Example: `Accounts.config({ restrictCreationByEmailDomain: 'school.edu' })`.
   * @param {Number} options.loginExpirationInDays The number of days from when a user logs in until their token expires and they are logged out. Defaults to 90. Set to `null` to disable login expiration.
   * @param {Number} options.loginExpiration The number of milliseconds from when a user logs in until their token expires and they are logged out, for a more granular control. If `loginExpirationInDays` is set, it takes precedent.
   * @param {String} options.oauthSecretKey When using the `oauth-encryption` package, the 16 byte key using to encrypt sensitive account credentials in the database, encoded in base64.  This option may only be specified on the server.  See packages/oauth-encryption/README.md for details.
   * @param {Number} options.passwordResetTokenExpirationInDays The number of days from when a link to reset password is sent until token expires and user can't reset password with the link anymore. Defaults to 3.
   * @param {Number} options.passwordResetTokenExpiration The number of milliseconds from when a link to reset password is sent until token expires and user can't reset password with the link anymore. If `passwordResetTokenExpirationInDays` is set, it takes precedent.
   * @param {Number} options.passwordEnrollTokenExpirationInDays The number of days from when a link to set initial password is sent until token expires and user can't set password with the link anymore. Defaults to 30.
   * @param {Number} options.passwordEnrollTokenExpiration The number of milliseconds from when a link to set initial password is sent until token expires and user can't set password with the link anymore. If `passwordEnrollTokenExpirationInDays` is set, it takes precedent.
   * @param {Boolean} options.ambiguousErrorMessages Return ambiguous error messages from login failures to prevent user enumeration. Defaults to false.
   * @param {MongoFieldSpecifier} options.defaultFieldSelector To exclude by default large custom fields from `Meteor.user()` and `Meteor.findUserBy...()` functions when called without a field selector, and all `onLogin`, `onLoginFailure` and `onLogout` callbacks.  Example: `Accounts.config({ defaultFieldSelector: { myBigArray: 0 }})`. Beware when using this. If, for instance, you do not include `email` when excluding the fields, you can have problems with functions like `forgotPassword` that will break because they won't have the required data available. It's recommend that you always keep the fields `_id`, `username`, and `email`.
   */


  config(options) {
    // We don't want users to accidentally only call Accounts.config on the
    // client, where some of the options will have partial effects (eg removing
    // the "create account" button from accounts-ui if forbidClientAccountCreation
    // is set, or redirecting Google login to a specific-domain page) without
    // having their full effects.
    if (Meteor.isServer) {
      __meteor_runtime_config__.accountsConfigCalled = true;
    } else if (!__meteor_runtime_config__.accountsConfigCalled) {
      // XXX would be nice to "crash" the client and replace the UI with an error
      // message, but there's no trivial way to do this.
      Meteor._debug('Accounts.config was called on the client but not on the ' + 'server; some configuration options may not take effect.');
    } // We need to validate the oauthSecretKey option at the time
    // Accounts.config is called. We also deliberately don't store the
    // oauthSecretKey in Accounts._options.


    if (Object.prototype.hasOwnProperty.call(options, 'oauthSecretKey')) {
      if (Meteor.isClient) {
        throw new Error('The oauthSecretKey option may only be specified on the server');
      }

      if (!Package['oauth-encryption']) {
        throw new Error('The oauth-encryption package must be loaded to set oauthSecretKey');
      }

      Package['oauth-encryption'].OAuthEncryption.loadKey(options.oauthSecretKey);
      options = _objectSpread({}, options);
      delete options.oauthSecretKey;
    } // Validate config options keys


    Object.keys(options).forEach(key => {
      if (!VALID_CONFIG_KEYS.includes(key)) {
        throw new Meteor.Error("Accounts.config: Invalid key: ".concat(key));
      }
    }); // set values in Accounts._options

    VALID_CONFIG_KEYS.forEach(key => {
      if (key in options) {
        if (key in this._options) {
          throw new Meteor.Error("Can't set `".concat(key, "` more than once"));
        }

        this._options[key] = options[key];
      }
    });
  }
  /**
   * @summary Register a callback to be called after a login attempt succeeds.
   * @locus Anywhere
   * @param {Function} func The callback to be called when login is successful.
   *                        The callback receives a single object that
   *                        holds login details. This object contains the login
   *                        result type (password, resume, etc.) on both the
   *                        client and server. `onLogin` callbacks registered
   *                        on the server also receive extra data, such
   *                        as user details, connection information, etc.
   */


  onLogin(func) {
    let ret = this._onLoginHook.register(func); // call the just registered callback if already logged in


    this._startupCallback(ret.callback);

    return ret;
  }
  /**
   * @summary Register a callback to be called after a login attempt fails.
   * @locus Anywhere
   * @param {Function} func The callback to be called after the login has failed.
   */


  onLoginFailure(func) {
    return this._onLoginFailureHook.register(func);
  }
  /**
   * @summary Register a callback to be called after a logout attempt succeeds.
   * @locus Anywhere
   * @param {Function} func The callback to be called when logout is successful.
   */


  onLogout(func) {
    return this._onLogoutHook.register(func);
  }

  _initConnection(options) {
    if (!Meteor.isClient) {
      return;
    } // The connection used by the Accounts system. This is the connection
    // that will get logged in by Meteor.login(), and this is the
    // connection whose login state will be reflected by Meteor.userId().
    //
    // It would be much preferable for this to be in accounts_client.js,
    // but it has to be here because it's needed to create the
    // Meteor.users collection.


    if (options.connection) {
      this.connection = options.connection;
    } else if (options.ddpUrl) {
      this.connection = DDP.connect(options.ddpUrl);
    } else if (typeof __meteor_runtime_config__ !== 'undefined' && __meteor_runtime_config__.ACCOUNTS_CONNECTION_URL) {
      // Temporary, internal hook to allow the server to point the client
      // to a different authentication server. This is for a very
      // particular use case that comes up when implementing a oauth
      // server. Unsupported and may go away at any point in time.
      //
      // We will eventually provide a general way to use account-base
      // against any DDP connection, not just one special one.
      this.connection = DDP.connect(__meteor_runtime_config__.ACCOUNTS_CONNECTION_URL);
    } else {
      this.connection = Meteor.connection;
    }
  }

  _getTokenLifetimeMs() {
    // When loginExpirationInDays is set to null, we'll use a really high
    // number of days (LOGIN_UNEXPIRABLE_TOKEN_DAYS) to simulate an
    // unexpiring token.
    const loginExpirationInDays = this._options.loginExpirationInDays === null ? LOGIN_UNEXPIRING_TOKEN_DAYS : this._options.loginExpirationInDays;
    return this._options.loginExpiration || (loginExpirationInDays || DEFAULT_LOGIN_EXPIRATION_DAYS) * 86400000;
  }

  _getPasswordResetTokenLifetimeMs() {
    return this._options.passwordResetTokenExpiration || (this._options.passwordResetTokenExpirationInDays || DEFAULT_PASSWORD_RESET_TOKEN_EXPIRATION_DAYS) * 86400000;
  }

  _getPasswordEnrollTokenLifetimeMs() {
    return this._options.passwordEnrollTokenExpiration || (this._options.passwordEnrollTokenExpirationInDays || DEFAULT_PASSWORD_ENROLL_TOKEN_EXPIRATION_DAYS) * 86400000;
  }

  _tokenExpiration(when) {
    // We pass when through the Date constructor for backwards compatibility;
    // `when` used to be a number.
    return new Date(new Date(when).getTime() + this._getTokenLifetimeMs());
  }

  _tokenExpiresSoon(when) {
    let minLifetimeMs = 0.1 * this._getTokenLifetimeMs();

    const minLifetimeCapMs = MIN_TOKEN_LIFETIME_CAP_SECS * 1000;

    if (minLifetimeMs > minLifetimeCapMs) {
      minLifetimeMs = minLifetimeCapMs;
    }

    return new Date() > new Date(when) - minLifetimeMs;
  } // No-op on the server, overridden on the client.


  _startupCallback(callback) {}

}

// Note that Accounts is defined separately in accounts_client.js and
// accounts_server.js.

/**
 * @summary Get the current user id, or `null` if no user is logged in. A reactive data source.
 * @locus Anywhere but publish functions
 * @importFromPackage meteor
 */
Meteor.userId = () => Accounts.userId();
/**
 * @summary Get the current user record, or `null` if no user is logged in. A reactive data source.
 * @locus Anywhere but publish functions
 * @importFromPackage meteor
 * @param {Object} [options]
 * @param {MongoFieldSpecifier} options.fields Dictionary of fields to return or exclude.
 */


Meteor.user = options => Accounts.user(options); // how long (in days) until a login token expires


const DEFAULT_LOGIN_EXPIRATION_DAYS = 90; // how long (in days) until reset password token expires

const DEFAULT_PASSWORD_RESET_TOKEN_EXPIRATION_DAYS = 3; // how long (in days) until enrol password token expires

const DEFAULT_PASSWORD_ENROLL_TOKEN_EXPIRATION_DAYS = 30; // Clients don't try to auto-login with a token that is going to expire within
// .1 * DEFAULT_LOGIN_EXPIRATION_DAYS, capped at MIN_TOKEN_LIFETIME_CAP_SECS.
// Tries to avoid abrupt disconnects from expiring tokens.

const MIN_TOKEN_LIFETIME_CAP_SECS = 3600; // one hour
// how often (in milliseconds) we check for expired tokens

const EXPIRE_TOKENS_INTERVAL_MS = 600 * 1000;
const CONNECTION_CLOSE_DELAY_MS = 10 * 1000;
// A large number of expiration days (approximately 100 years worth) that is
// used when creating unexpiring tokens.
const LOGIN_UNEXPIRING_TOKEN_DAYS = 365 * 100;
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

},"accounts_server.js":function module(require,exports,module){

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                   //
// packages/accounts-base/accounts_server.js                                                                         //
//                                                                                                                   //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                     //
const _excluded = ["token"];

let _objectWithoutProperties;

module.link("@babel/runtime/helpers/objectWithoutProperties", {
  default(v) {
    _objectWithoutProperties = v;
  }

}, 0);

let _objectSpread;

module.link("@babel/runtime/helpers/objectSpread2", {
  default(v) {
    _objectSpread = v;
  }

}, 1);
module.export({
  AccountsServer: () => AccountsServer
});
let crypto;
module.link("crypto", {
  default(v) {
    crypto = v;
  }

}, 0);
let AccountsCommon, EXPIRE_TOKENS_INTERVAL_MS;
module.link("./accounts_common.js", {
  AccountsCommon(v) {
    AccountsCommon = v;
  },

  EXPIRE_TOKENS_INTERVAL_MS(v) {
    EXPIRE_TOKENS_INTERVAL_MS = v;
  }

}, 1);
let URL;
module.link("meteor/url", {
  URL(v) {
    URL = v;
  }

}, 2);
const hasOwn = Object.prototype.hasOwnProperty; // XXX maybe this belongs in the check package

const NonEmptyString = Match.Where(x => {
  check(x, String);
  return x.length > 0;
});
/**
 * @summary Constructor for the `Accounts` namespace on the server.
 * @locus Server
 * @class AccountsServer
 * @extends AccountsCommon
 * @instancename accountsServer
 * @param {Object} server A server object such as `Meteor.server`.
 */

class AccountsServer extends AccountsCommon {
  // Note that this constructor is less likely to be instantiated multiple
  // times than the `AccountsClient` constructor, because a single server
  // can provide only one set of methods.
  constructor(server) {
    var _this;

    super();
    _this = this;

    this.onCreateLoginToken = function (func) {
      if (this._onCreateLoginTokenHook) {
        throw new Error('Can only call onCreateLoginToken once');
      }

      this._onCreateLoginTokenHook = func;
    };

    this._selectorForFastCaseInsensitiveLookup = (fieldName, string) => {
      // Performance seems to improve up to 4 prefix characters
      const prefix = string.substring(0, Math.min(string.length, 4));
      const orClause = generateCasePermutationsForString(prefix).map(prefixPermutation => {
        const selector = {};
        selector[fieldName] = new RegExp("^".concat(Meteor._escapeRegExp(prefixPermutation)));
        return selector;
      });
      const caseInsensitiveClause = {};
      caseInsensitiveClause[fieldName] = new RegExp("^".concat(Meteor._escapeRegExp(string), "$"), 'i');
      return {
        $and: [{
          $or: orClause
        }, caseInsensitiveClause]
      };
    };

    this._findUserByQuery = (query, options) => {
      let user = null;

      if (query.id) {
        // default field selector is added within getUserById()
        user = Meteor.users.findOne(query.id, this._addDefaultFieldSelector(options));
      } else {
        options = this._addDefaultFieldSelector(options);
        let fieldName;
        let fieldValue;

        if (query.username) {
          fieldName = 'username';
          fieldValue = query.username;
        } else if (query.email) {
          fieldName = 'emails.address';
          fieldValue = query.email;
        } else {
          throw new Error("shouldn't happen (validation missed something)");
        }

        let selector = {};
        selector[fieldName] = fieldValue;
        user = Meteor.users.findOne(selector, options); // If user is not found, try a case insensitive lookup

        if (!user) {
          selector = this._selectorForFastCaseInsensitiveLookup(fieldName, fieldValue);
          const candidateUsers = Meteor.users.find(selector, options).fetch(); // No match if multiple candidates are found

          if (candidateUsers.length === 1) {
            user = candidateUsers[0];
          }
        }
      }

      return user;
    };

    this._handleError = function (msg) {
      let throwError = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
      const error = new Meteor.Error(403, _this._options.ambiguousErrorMessages ? "Something went wrong. Please check your credentials." : msg);

      if (throwError) {
        throw error;
      }

      return error;
    };

    this._userQueryValidator = Match.Where(user => {
      check(user, {
        id: Match.Optional(NonEmptyString),
        username: Match.Optional(NonEmptyString),
        email: Match.Optional(NonEmptyString)
      });
      if (Object.keys(user).length !== 1) throw new Match.Error("User property must have exactly one field");
      return true;
    });
    this._server = server || Meteor.server; // Set up the server's methods, as if by calling Meteor.methods.

    this._initServerMethods();

    this._initAccountDataHooks(); // If autopublish is on, publish these user fields. Login service
    // packages (eg accounts-google) add to these by calling
    // addAutopublishFields.  Notably, this isn't implemented with multiple
    // publishes since DDP only merges only across top-level fields, not
    // subfields (such as 'services.facebook.accessToken')


    this._autopublishFields = {
      loggedInUser: ['profile', 'username', 'emails'],
      otherUsers: ['profile', 'username']
    }; // use object to keep the reference when used in functions
    // where _defaultPublishFields is destructured into lexical scope
    // for publish callbacks that need `this`

    this._defaultPublishFields = {
      projection: {
        profile: 1,
        username: 1,
        emails: 1
      }
    };

    this._initServerPublications(); // connectionId -> {connection, loginToken}


    this._accountData = {}; // connection id -> observe handle for the login token that this connection is
    // currently associated with, or a number. The number indicates that we are in
    // the process of setting up the observe (using a number instead of a single
    // sentinel allows multiple attempts to set up the observe to identify which
    // one was theirs).

    this._userObservesForConnections = {};
    this._nextUserObserveNumber = 1; // for the number described above.
    // list of all registered handlers.

    this._loginHandlers = [];
    setupUsersCollection(this.users);
    setupDefaultLoginHandlers(this);
    setExpireTokensInterval(this);
    this._validateLoginHook = new Hook({
      bindEnvironment: false
    });
    this._validateNewUserHooks = [defaultValidateNewUserHook.bind(this)];

    this._deleteSavedTokensForAllUsersOnStartup();

    this._skipCaseInsensitiveChecksForTest = {};
    this.urls = {
      resetPassword: (token, extraParams) => this.buildEmailUrl("#/reset-password/".concat(token), extraParams),
      verifyEmail: (token, extraParams) => this.buildEmailUrl("#/verify-email/".concat(token), extraParams),
      loginToken: (selector, token, extraParams) => this.buildEmailUrl("/?loginToken=".concat(token, "&selector=").concat(selector), extraParams),
      enrollAccount: (token, extraParams) => this.buildEmailUrl("#/enroll-account/".concat(token), extraParams)
    };
    this.addDefaultRateLimit();

    this.buildEmailUrl = function (path) {
      let extraParams = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
      const url = new URL(Meteor.absoluteUrl(path));
      const params = Object.entries(extraParams);

      if (params.length > 0) {
        // Add additional parameters to the url
        for (const [key, value] of params) {
          url.searchParams.append(key, value);
        }
      }

      return url.toString();
    };
  } ///
  /// CURRENT USER
  ///
  // @override of "abstract" non-implementation in accounts_common.js


  userId() {
    // This function only works if called inside a method or a pubication.
    // Using any of the information from Meteor.user() in a method or
    // publish function will always use the value from when the function first
    // runs. This is likely not what the user expects. The way to make this work
    // in a method or publish function is to do Meteor.find(this.userId).observe
    // and recompute when the user record changes.
    const currentInvocation = DDP._CurrentMethodInvocation.get() || DDP._CurrentPublicationInvocation.get();

    if (!currentInvocation) throw new Error("Meteor.userId can only be invoked in method calls or publications.");
    return currentInvocation.userId;
  } ///
  /// LOGIN HOOKS
  ///

  /**
   * @summary Validate login attempts.
   * @locus Server
   * @param {Function} func Called whenever a login is attempted (either successful or unsuccessful).  A login can be aborted by returning a falsy value or throwing an exception.
   */


  validateLoginAttempt(func) {
    // Exceptions inside the hook callback are passed up to us.
    return this._validateLoginHook.register(func);
  }
  /**
   * @summary Set restrictions on new user creation.
   * @locus Server
   * @param {Function} func Called whenever a new user is created. Takes the new user object, and returns true to allow the creation or false to abort.
   */


  validateNewUser(func) {
    this._validateNewUserHooks.push(func);
  }
  /**
   * @summary Validate login from external service
   * @locus Server
   * @param {Function} func Called whenever login/user creation from external service is attempted. Login or user creation based on this login can be aborted by passing a falsy value or throwing an exception.
   */


  beforeExternalLogin(func) {
    if (this._beforeExternalLoginHook) {
      throw new Error("Can only call beforeExternalLogin once");
    }

    this._beforeExternalLoginHook = func;
  } ///
  /// CREATE USER HOOKS
  ///

  /**
   * @summary Customize login token creation.
   * @locus Server
   * @param {Function} func Called whenever a new token is created.
   * Return the sequence and the user object. Return true to keep sending the default email, or false to override the behavior.
   */


  /**
   * @summary Customize new user creation.
   * @locus Server
   * @param {Function} func Called whenever a new user is created. Return the new user object, or throw an `Error` to abort the creation.
   */
  onCreateUser(func) {
    if (this._onCreateUserHook) {
      throw new Error("Can only call onCreateUser once");
    }

    this._onCreateUserHook = func;
  }
  /**
   * @summary Customize oauth user profile updates
   * @locus Server
   * @param {Function} func Called whenever a user is logged in via oauth. Return the profile object to be merged, or throw an `Error` to abort the creation.
   */


  onExternalLogin(func) {
    if (this._onExternalLoginHook) {
      throw new Error("Can only call onExternalLogin once");
    }

    this._onExternalLoginHook = func;
  }
  /**
   * @summary Customize user selection on external logins
   * @locus Server
   * @param {Function} func Called whenever a user is logged in via oauth and a
   * user is not found with the service id. Return the user or undefined.
   */


  setAdditionalFindUserOnExternalLogin(func) {
    if (this._additionalFindUserOnExternalLogin) {
      throw new Error("Can only call setAdditionalFindUserOnExternalLogin once");
    }

    this._additionalFindUserOnExternalLogin = func;
  }

  _validateLogin(connection, attempt) {
    this._validateLoginHook.each(callback => {
      let ret;

      try {
        ret = callback(cloneAttemptWithConnection(connection, attempt));
      } catch (e) {
        attempt.allowed = false; // XXX this means the last thrown error overrides previous error
        // messages. Maybe this is surprising to users and we should make
        // overriding errors more explicit. (see
        // https://github.com/meteor/meteor/issues/1960)

        attempt.error = e;
        return true;
      }

      if (!ret) {
        attempt.allowed = false; // don't override a specific error provided by a previous
        // validator or the initial attempt (eg "incorrect password").

        if (!attempt.error) attempt.error = new Meteor.Error(403, "Login forbidden");
      }

      return true;
    });
  }

  _successfulLogin(connection, attempt) {
    this._onLoginHook.each(callback => {
      callback(cloneAttemptWithConnection(connection, attempt));
      return true;
    });
  }

  _failedLogin(connection, attempt) {
    this._onLoginFailureHook.each(callback => {
      callback(cloneAttemptWithConnection(connection, attempt));
      return true;
    });
  }

  _successfulLogout(connection, userId) {
    // don't fetch the user object unless there are some callbacks registered
    let user;

    this._onLogoutHook.each(callback => {
      if (!user && userId) user = this.users.findOne(userId, {
        fields: this._options.defaultFieldSelector
      });
      callback({
        user,
        connection
      });
      return true;
    });
  }

  ///
  /// LOGIN METHODS
  ///
  // Login methods return to the client an object containing these
  // fields when the user was logged in successfully:
  //
  //   id: userId
  //   token: *
  //   tokenExpires: *
  //
  // tokenExpires is optional and intends to provide a hint to the
  // client as to when the token will expire. If not provided, the
  // client will call Accounts._tokenExpiration, passing it the date
  // that it received the token.
  //
  // The login method will throw an error back to the client if the user
  // failed to log in.
  //
  //
  // Login handlers and service specific login methods such as
  // `createUser` internally return a `result` object containing these
  // fields:
  //
  //   type:
  //     optional string; the service name, overrides the handler
  //     default if present.
  //
  //   error:
  //     exception; if the user is not allowed to login, the reason why.
  //
  //   userId:
  //     string; the user id of the user attempting to login (if
  //     known), required for an allowed login.
  //
  //   options:
  //     optional object merged into the result returned by the login
  //     method; used by HAMK from SRP.
  //
  //   stampedLoginToken:
  //     optional object with `token` and `when` indicating the login
  //     token is already present in the database, returned by the
  //     "resume" login handler.
  //
  // For convenience, login methods can also throw an exception, which
  // is converted into an {error} result.  However, if the id of the
  // user attempting the login is known, a {userId, error} result should
  // be returned instead since the user id is not captured when an
  // exception is thrown.
  //
  // This internal `result` object is automatically converted into the
  // public {id, token, tokenExpires} object returned to the client.
  // Try a login method, converting thrown exceptions into an {error}
  // result.  The `type` argument is a default, inserted into the result
  // object if not explicitly returned.
  //
  // Log in a user on a connection.
  //
  // We use the method invocation to set the user id on the connection,
  // not the connection object directly. setUserId is tied to methods to
  // enforce clear ordering of method application (using wait methods on
  // the client, and a no setUserId after unblock restriction on the
  // server)
  //
  // The `stampedLoginToken` parameter is optional.  When present, it
  // indicates that the login token has already been inserted into the
  // database and doesn't need to be inserted again.  (It's used by the
  // "resume" login handler).
  _loginUser(methodInvocation, userId, stampedLoginToken) {
    if (!stampedLoginToken) {
      stampedLoginToken = this._generateStampedLoginToken();

      this._insertLoginToken(userId, stampedLoginToken);
    } // This order (and the avoidance of yields) is important to make
    // sure that when publish functions are rerun, they see a
    // consistent view of the world: the userId is set and matches
    // the login token on the connection (not that there is
    // currently a public API for reading the login token on a
    // connection).


    Meteor._noYieldsAllowed(() => this._setLoginToken(userId, methodInvocation.connection, this._hashLoginToken(stampedLoginToken.token)));

    methodInvocation.setUserId(userId);
    return {
      id: userId,
      token: stampedLoginToken.token,
      tokenExpires: this._tokenExpiration(stampedLoginToken.when)
    };
  }

  // After a login method has completed, call the login hooks.  Note
  // that `attemptLogin` is called for *all* login attempts, even ones
  // which aren't successful (such as an invalid password, etc).
  //
  // If the login is allowed and isn't aborted by a validate login hook
  // callback, log in the user.
  //
  _attemptLogin(methodInvocation, methodName, methodArgs, result) {
    if (!result) throw new Error("result is required"); // XXX A programming error in a login handler can lead to this occurring, and
    // then we don't call onLogin or onLoginFailure callbacks. Should
    // tryLoginMethod catch this case and turn it into an error?

    if (!result.userId && !result.error) throw new Error("A login method must specify a userId or an error");
    let user;
    if (result.userId) user = this.users.findOne(result.userId, {
      fields: this._options.defaultFieldSelector
    });
    const attempt = {
      type: result.type || "unknown",
      allowed: !!(result.userId && !result.error),
      methodName: methodName,
      methodArguments: Array.from(methodArgs)
    };

    if (result.error) {
      attempt.error = result.error;
    }

    if (user) {
      attempt.user = user;
    } // _validateLogin may mutate `attempt` by adding an error and changing allowed
    // to false, but that's the only change it can make (and the user's callbacks
    // only get a clone of `attempt`).


    this._validateLogin(methodInvocation.connection, attempt);

    if (attempt.allowed) {
      const ret = _objectSpread(_objectSpread({}, this._loginUser(methodInvocation, result.userId, result.stampedLoginToken)), result.options);

      ret.type = attempt.type;

      this._successfulLogin(methodInvocation.connection, attempt);

      return ret;
    } else {
      this._failedLogin(methodInvocation.connection, attempt);

      throw attempt.error;
    }
  }

  // All service specific login methods should go through this function.
  // Ensure that thrown exceptions are caught and that login hook
  // callbacks are still called.
  //
  _loginMethod(methodInvocation, methodName, methodArgs, type, fn) {
    return this._attemptLogin(methodInvocation, methodName, methodArgs, tryLoginMethod(type, fn));
  }

  // Report a login attempt failed outside the context of a normal login
  // method. This is for use in the case where there is a multi-step login
  // procedure (eg SRP based password login). If a method early in the
  // chain fails, it should call this function to report a failure. There
  // is no corresponding method for a successful login; methods that can
  // succeed at logging a user in should always be actual login methods
  // (using either Accounts._loginMethod or Accounts.registerLoginHandler).
  _reportLoginFailure(methodInvocation, methodName, methodArgs, result) {
    const attempt = {
      type: result.type || "unknown",
      allowed: false,
      error: result.error,
      methodName: methodName,
      methodArguments: Array.from(methodArgs)
    };

    if (result.userId) {
      attempt.user = this.users.findOne(result.userId, {
        fields: this._options.defaultFieldSelector
      });
    }

    this._validateLogin(methodInvocation.connection, attempt);

    this._failedLogin(methodInvocation.connection, attempt); // _validateLogin may mutate attempt to set a new error message. Return
    // the modified version.


    return attempt;
  }

  ///
  /// LOGIN HANDLERS
  ///
  // The main entry point for auth packages to hook in to login.
  //
  // A login handler is a login method which can return `undefined` to
  // indicate that the login request is not handled by this handler.
  //
  // @param name {String} Optional.  The service name, used by default
  // if a specific service name isn't returned in the result.
  //
  // @param handler {Function} A function that receives an options object
  // (as passed as an argument to the `login` method) and returns one of:
  // - `undefined`, meaning don't handle;
  // - a login method result object
  registerLoginHandler(name, handler) {
    if (!handler) {
      handler = name;
      name = null;
    }

    this._loginHandlers.push({
      name: name,
      handler: handler
    });
  }

  // Checks a user's credentials against all the registered login
  // handlers, and returns a login token if the credentials are valid. It
  // is like the login method, except that it doesn't set the logged-in
  // user on the connection. Throws a Meteor.Error if logging in fails,
  // including the case where none of the login handlers handled the login
  // request. Otherwise, returns {id: userId, token: *, tokenExpires: *}.
  //
  // For example, if you want to login with a plaintext password, `options` could be
  //   { user: { username: <username> }, password: <password> }, or
  //   { user: { email: <email> }, password: <password> }.
  // Try all of the registered login handlers until one of them doesn't
  // return `undefined`, meaning it handled this call to `login`. Return
  // that return value.
  _runLoginHandlers(methodInvocation, options) {
    for (let handler of this._loginHandlers) {
      const result = tryLoginMethod(handler.name, () => handler.handler.call(methodInvocation, options));

      if (result) {
        return result;
      }

      if (result !== undefined) {
        throw new Meteor.Error(400, "A login handler should return a result or undefined");
      }
    }

    return {
      type: null,
      error: new Meteor.Error(400, "Unrecognized options for login request")
    };
  }

  // Deletes the given loginToken from the database.
  //
  // For new-style hashed token, this will cause all connections
  // associated with the token to be closed.
  //
  // Any connections associated with old-style unhashed tokens will be
  // in the process of becoming associated with hashed tokens and then
  // they'll get closed.
  destroyToken(userId, loginToken) {
    this.users.update(userId, {
      $pull: {
        "services.resume.loginTokens": {
          $or: [{
            hashedToken: loginToken
          }, {
            token: loginToken
          }]
        }
      }
    });
  }

  _initServerMethods() {
    // The methods created in this function need to be created here so that
    // this variable is available in their scope.
    const accounts = this; // This object will be populated with methods and then passed to
    // accounts._server.methods further below.

    const methods = {}; // @returns {Object|null}
    //   If successful, returns {token: reconnectToken, id: userId}
    //   If unsuccessful (for example, if the user closed the oauth login popup),
    //     throws an error describing the reason

    methods.login = function (options) {
      // Login handlers should really also check whatever field they look at in
      // options, but we don't enforce it.
      check(options, Object);

      const result = accounts._runLoginHandlers(this, options);

      return accounts._attemptLogin(this, "login", arguments, result);
    };

    methods.logout = function () {
      const token = accounts._getLoginToken(this.connection.id);

      accounts._setLoginToken(this.userId, this.connection, null);

      if (token && this.userId) {
        accounts.destroyToken(this.userId, token);
      }

      accounts._successfulLogout(this.connection, this.userId);

      this.setUserId(null);
    }; // Generates a new login token with the same expiration as the
    // connection's current token and saves it to the database. Associates
    // the connection with this new token and returns it. Throws an error
    // if called on a connection that isn't logged in.
    //
    // @returns Object
    //   If successful, returns { token: <new token>, id: <user id>,
    //   tokenExpires: <expiration date> }.


    methods.getNewToken = function () {
      const user = accounts.users.findOne(this.userId, {
        fields: {
          "services.resume.loginTokens": 1
        }
      });

      if (!this.userId || !user) {
        throw new Meteor.Error("You are not logged in.");
      } // Be careful not to generate a new token that has a later
      // expiration than the curren token. Otherwise, a bad guy with a
      // stolen token could use this method to stop his stolen token from
      // ever expiring.


      const currentHashedToken = accounts._getLoginToken(this.connection.id);

      const currentStampedToken = user.services.resume.loginTokens.find(stampedToken => stampedToken.hashedToken === currentHashedToken);

      if (!currentStampedToken) {
        // safety belt: this should never happen
        throw new Meteor.Error("Invalid login token");
      }

      const newStampedToken = accounts._generateStampedLoginToken();

      newStampedToken.when = currentStampedToken.when;

      accounts._insertLoginToken(this.userId, newStampedToken);

      return accounts._loginUser(this, this.userId, newStampedToken);
    }; // Removes all tokens except the token associated with the current
    // connection. Throws an error if the connection is not logged
    // in. Returns nothing on success.


    methods.removeOtherTokens = function () {
      if (!this.userId) {
        throw new Meteor.Error("You are not logged in.");
      }

      const currentToken = accounts._getLoginToken(this.connection.id);

      accounts.users.update(this.userId, {
        $pull: {
          "services.resume.loginTokens": {
            hashedToken: {
              $ne: currentToken
            }
          }
        }
      });
    }; // Allow a one-time configuration for a login service. Modifications
    // to this collection are also allowed in insecure mode.


    methods.configureLoginService = options => {
      check(options, Match.ObjectIncluding({
        service: String
      })); // Don't let random users configure a service we haven't added yet (so
      // that when we do later add it, it's set up with their configuration
      // instead of ours).
      // XXX if service configuration is oauth-specific then this code should
      //     be in accounts-oauth; if it's not then the registry should be
      //     in this package

      if (!(accounts.oauth && accounts.oauth.serviceNames().includes(options.service))) {
        throw new Meteor.Error(403, "Service unknown");
      }

      const {
        ServiceConfiguration
      } = Package['service-configuration'];
      if (ServiceConfiguration.configurations.findOne({
        service: options.service
      })) throw new Meteor.Error(403, "Service ".concat(options.service, " already configured"));
      if (hasOwn.call(options, 'secret') && usingOAuthEncryption()) options.secret = OAuthEncryption.seal(options.secret);
      ServiceConfiguration.configurations.insert(options);
    };

    accounts._server.methods(methods);
  }

  _initAccountDataHooks() {
    this._server.onConnection(connection => {
      this._accountData[connection.id] = {
        connection: connection
      };
      connection.onClose(() => {
        this._removeTokenFromConnection(connection.id);

        delete this._accountData[connection.id];
      });
    });
  }

  _initServerPublications() {
    // Bring into lexical scope for publish callbacks that need `this`
    const {
      users,
      _autopublishFields,
      _defaultPublishFields
    } = this; // Publish all login service configuration fields other than secret.

    this._server.publish("meteor.loginServiceConfiguration", () => {
      const {
        ServiceConfiguration
      } = Package['service-configuration'];
      return ServiceConfiguration.configurations.find({}, {
        fields: {
          secret: 0
        }
      });
    }, {
      is_auto: true
    }); // not technically autopublish, but stops the warning.
    // Use Meteor.startup to give other packages a chance to call
    // setDefaultPublishFields.


    Meteor.startup(() => {
      // Publish the current user's record to the client.
      this._server.publish(null, function () {
        if (this.userId) {
          return users.find({
            _id: this.userId
          }, {
            fields: _defaultPublishFields.projection
          });
        } else {
          return null;
        }
      },
      /*suppress autopublish warning*/
      {
        is_auto: true
      });
    }); // Use Meteor.startup to give other packages a chance to call
    // addAutopublishFields.

    Package.autopublish && Meteor.startup(() => {
      // ['profile', 'username'] -> {profile: 1, username: 1}
      const toFieldSelector = fields => fields.reduce((prev, field) => _objectSpread(_objectSpread({}, prev), {}, {
        [field]: 1
      }), {});

      this._server.publish(null, function () {
        if (this.userId) {
          return users.find({
            _id: this.userId
          }, {
            fields: toFieldSelector(_autopublishFields.loggedInUser)
          });
        } else {
          return null;
        }
      },
      /*suppress autopublish warning*/
      {
        is_auto: true
      }); // XXX this publish is neither dedup-able nor is it optimized by our special
      // treatment of queries on a specific _id. Therefore this will have O(n^2)
      // run-time performance every time a user document is changed (eg someone
      // logging in). If this is a problem, we can instead write a manual publish
      // function which filters out fields based on 'this.userId'.


      this._server.publish(null, function () {
        const selector = this.userId ? {
          _id: {
            $ne: this.userId
          }
        } : {};
        return users.find(selector, {
          fields: toFieldSelector(_autopublishFields.otherUsers)
        });
      },
      /*suppress autopublish warning*/
      {
        is_auto: true
      });
    });
  }

  // Add to the list of fields or subfields to be automatically
  // published if autopublish is on. Must be called from top-level
  // code (ie, before Meteor.startup hooks run).
  //
  // @param opts {Object} with:
  //   - forLoggedInUser {Array} Array of fields published to the logged-in user
  //   - forOtherUsers {Array} Array of fields published to users that aren't logged in
  addAutopublishFields(opts) {
    this._autopublishFields.loggedInUser.push.apply(this._autopublishFields.loggedInUser, opts.forLoggedInUser);

    this._autopublishFields.otherUsers.push.apply(this._autopublishFields.otherUsers, opts.forOtherUsers);
  }

  // Replaces the fields to be automatically
  // published when the user logs in
  //
  // @param {MongoFieldSpecifier} fields Dictionary of fields to return or exclude.
  setDefaultPublishFields(fields) {
    this._defaultPublishFields.projection = fields;
  }

  ///
  /// ACCOUNT DATA
  ///
  // HACK: This is used by 'meteor-accounts' to get the loginToken for a
  // connection. Maybe there should be a public way to do that.
  _getAccountData(connectionId, field) {
    const data = this._accountData[connectionId];
    return data && data[field];
  }

  _setAccountData(connectionId, field, value) {
    const data = this._accountData[connectionId]; // safety belt. shouldn't happen. accountData is set in onConnection,
    // we don't have a connectionId until it is set.

    if (!data) return;
    if (value === undefined) delete data[field];else data[field] = value;
  }

  ///
  /// RECONNECT TOKENS
  ///
  /// support reconnecting using a meteor login token
  _hashLoginToken(loginToken) {
    const hash = crypto.createHash('sha256');
    hash.update(loginToken);
    return hash.digest('base64');
  }

  // {token, when} => {hashedToken, when}
  _hashStampedToken(stampedToken) {
    const {
      token
    } = stampedToken,
          hashedStampedToken = _objectWithoutProperties(stampedToken, _excluded);

    return _objectSpread(_objectSpread({}, hashedStampedToken), {}, {
      hashedToken: this._hashLoginToken(token)
    });
  }

  // Using $addToSet avoids getting an index error if another client
  // logging in simultaneously has already inserted the new hashed
  // token.
  _insertHashedLoginToken(userId, hashedToken, query) {
    query = query ? _objectSpread({}, query) : {};
    query._id = userId;
    this.users.update(query, {
      $addToSet: {
        "services.resume.loginTokens": hashedToken
      }
    });
  }

  // Exported for tests.
  _insertLoginToken(userId, stampedToken, query) {
    this._insertHashedLoginToken(userId, this._hashStampedToken(stampedToken), query);
  }

  _clearAllLoginTokens(userId) {
    this.users.update(userId, {
      $set: {
        'services.resume.loginTokens': []
      }
    });
  }

  // test hook
  _getUserObserve(connectionId) {
    return this._userObservesForConnections[connectionId];
  }

  // Clean up this connection's association with the token: that is, stop
  // the observe that we started when we associated the connection with
  // this token.
  _removeTokenFromConnection(connectionId) {
    if (hasOwn.call(this._userObservesForConnections, connectionId)) {
      const observe = this._userObservesForConnections[connectionId];

      if (typeof observe === 'number') {
        // We're in the process of setting up an observe for this connection. We
        // can't clean up that observe yet, but if we delete the placeholder for
        // this connection, then the observe will get cleaned up as soon as it has
        // been set up.
        delete this._userObservesForConnections[connectionId];
      } else {
        delete this._userObservesForConnections[connectionId];
        observe.stop();
      }
    }
  }

  _getLoginToken(connectionId) {
    return this._getAccountData(connectionId, 'loginToken');
  }

  // newToken is a hashed token.
  _setLoginToken(userId, connection, newToken) {
    this._removeTokenFromConnection(connection.id);

    this._setAccountData(connection.id, 'loginToken', newToken);

    if (newToken) {
      // Set up an observe for this token. If the token goes away, we need
      // to close the connection.  We defer the observe because there's
      // no need for it to be on the critical path for login; we just need
      // to ensure that the connection will get closed at some point if
      // the token gets deleted.
      //
      // Initially, we set the observe for this connection to a number; this
      // signifies to other code (which might run while we yield) that we are in
      // the process of setting up an observe for this connection. Once the
      // observe is ready to go, we replace the number with the real observe
      // handle (unless the placeholder has been deleted or replaced by a
      // different placehold number, signifying that the connection was closed
      // already -- in this case we just clean up the observe that we started).
      const myObserveNumber = ++this._nextUserObserveNumber;
      this._userObservesForConnections[connection.id] = myObserveNumber;
      Meteor.defer(() => {
        // If something else happened on this connection in the meantime (it got
        // closed, or another call to _setLoginToken happened), just do
        // nothing. We don't need to start an observe for an old connection or old
        // token.
        if (this._userObservesForConnections[connection.id] !== myObserveNumber) {
          return;
        }

        let foundMatchingUser; // Because we upgrade unhashed login tokens to hashed tokens at
        // login time, sessions will only be logged in with a hashed
        // token. Thus we only need to observe hashed tokens here.

        const observe = this.users.find({
          _id: userId,
          'services.resume.loginTokens.hashedToken': newToken
        }, {
          fields: {
            _id: 1
          }
        }).observeChanges({
          added: () => {
            foundMatchingUser = true;
          },
          removed: connection.close // The onClose callback for the connection takes care of
          // cleaning up the observe handle and any other state we have
          // lying around.

        }, {
          nonMutatingCallbacks: true
        }); // If the user ran another login or logout command we were waiting for the
        // defer or added to fire (ie, another call to _setLoginToken occurred),
        // then we let the later one win (start an observe, etc) and just stop our
        // observe now.
        //
        // Similarly, if the connection was already closed, then the onClose
        // callback would have called _removeTokenFromConnection and there won't
        // be an entry in _userObservesForConnections. We can stop the observe.

        if (this._userObservesForConnections[connection.id] !== myObserveNumber) {
          observe.stop();
          return;
        }

        this._userObservesForConnections[connection.id] = observe;

        if (!foundMatchingUser) {
          // We've set up an observe on the user associated with `newToken`,
          // so if the new token is removed from the database, we'll close
          // the connection. But the token might have already been deleted
          // before we set up the observe, which wouldn't have closed the
          // connection because the observe wasn't running yet.
          connection.close();
        }
      });
    }
  }

  // (Also used by Meteor Accounts server and tests).
  //
  _generateStampedLoginToken() {
    return {
      token: Random.secret(),
      when: new Date()
    };
  }

  ///
  /// TOKEN EXPIRATION
  ///
  // Deletes expired password reset tokens from the database.
  //
  // Exported for tests. Also, the arguments are only used by
  // tests. oldestValidDate is simulate expiring tokens without waiting
  // for them to actually expire. userId is used by tests to only expire
  // tokens for the test user.
  _expirePasswordResetTokens(oldestValidDate, userId) {
    const tokenLifetimeMs = this._getPasswordResetTokenLifetimeMs(); // when calling from a test with extra arguments, you must specify both!


    if (oldestValidDate && !userId || !oldestValidDate && userId) {
      throw new Error("Bad test. Must specify both oldestValidDate and userId.");
    }

    oldestValidDate = oldestValidDate || new Date(new Date() - tokenLifetimeMs);
    const tokenFilter = {
      $or: [{
        "services.password.reset.reason": "reset"
      }, {
        "services.password.reset.reason": {
          $exists: false
        }
      }]
    };
    expirePasswordToken(this, oldestValidDate, tokenFilter, userId);
  } // Deletes expired password enroll tokens from the database.
  //
  // Exported for tests. Also, the arguments are only used by
  // tests. oldestValidDate is simulate expiring tokens without waiting
  // for them to actually expire. userId is used by tests to only expire
  // tokens for the test user.


  _expirePasswordEnrollTokens(oldestValidDate, userId) {
    const tokenLifetimeMs = this._getPasswordEnrollTokenLifetimeMs(); // when calling from a test with extra arguments, you must specify both!


    if (oldestValidDate && !userId || !oldestValidDate && userId) {
      throw new Error("Bad test. Must specify both oldestValidDate and userId.");
    }

    oldestValidDate = oldestValidDate || new Date(new Date() - tokenLifetimeMs);
    const tokenFilter = {
      "services.password.enroll.reason": "enroll"
    };
    expirePasswordToken(this, oldestValidDate, tokenFilter, userId);
  } // Deletes expired tokens from the database and closes all open connections
  // associated with these tokens.
  //
  // Exported for tests. Also, the arguments are only used by
  // tests. oldestValidDate is simulate expiring tokens without waiting
  // for them to actually expire. userId is used by tests to only expire
  // tokens for the test user.


  _expireTokens(oldestValidDate, userId) {
    const tokenLifetimeMs = this._getTokenLifetimeMs(); // when calling from a test with extra arguments, you must specify both!


    if (oldestValidDate && !userId || !oldestValidDate && userId) {
      throw new Error("Bad test. Must specify both oldestValidDate and userId.");
    }

    oldestValidDate = oldestValidDate || new Date(new Date() - tokenLifetimeMs);
    const userFilter = userId ? {
      _id: userId
    } : {}; // Backwards compatible with older versions of meteor that stored login token
    // timestamps as numbers.

    this.users.update(_objectSpread(_objectSpread({}, userFilter), {}, {
      $or: [{
        "services.resume.loginTokens.when": {
          $lt: oldestValidDate
        }
      }, {
        "services.resume.loginTokens.when": {
          $lt: +oldestValidDate
        }
      }]
    }), {
      $pull: {
        "services.resume.loginTokens": {
          $or: [{
            when: {
              $lt: oldestValidDate
            }
          }, {
            when: {
              $lt: +oldestValidDate
            }
          }]
        }
      }
    }, {
      multi: true
    }); // The observe on Meteor.users will take care of closing connections for
    // expired tokens.
  }

  // @override from accounts_common.js
  config(options) {
    // Call the overridden implementation of the method.
    const superResult = AccountsCommon.prototype.config.apply(this, arguments); // If the user set loginExpirationInDays to null, then we need to clear the
    // timer that periodically expires tokens.

    if (hasOwn.call(this._options, 'loginExpirationInDays') && this._options.loginExpirationInDays === null && this.expireTokenInterval) {
      Meteor.clearInterval(this.expireTokenInterval);
      this.expireTokenInterval = null;
    }

    return superResult;
  }

  // Called by accounts-password
  insertUserDoc(options, user) {
    // - clone user document, to protect from modification
    // - add createdAt timestamp
    // - prepare an _id, so that you can modify other collections (eg
    // create a first task for every new user)
    //
    // XXX If the onCreateUser or validateNewUser hooks fail, we might
    // end up having modified some other collection
    // inappropriately. The solution is probably to have onCreateUser
    // accept two callbacks - one that gets called before inserting
    // the user document (in which you can modify its contents), and
    // one that gets called after (in which you should change other
    // collections)
    user = _objectSpread({
      createdAt: new Date(),
      _id: Random.id()
    }, user);

    if (user.services) {
      Object.keys(user.services).forEach(service => pinEncryptedFieldsToUser(user.services[service], user._id));
    }

    let fullUser;

    if (this._onCreateUserHook) {
      fullUser = this._onCreateUserHook(options, user); // This is *not* part of the API. We need this because we can't isolate
      // the global server environment between tests, meaning we can't test
      // both having a create user hook set and not having one set.

      if (fullUser === 'TEST DEFAULT HOOK') fullUser = defaultCreateUserHook(options, user);
    } else {
      fullUser = defaultCreateUserHook(options, user);
    }

    this._validateNewUserHooks.forEach(hook => {
      if (!hook(fullUser)) throw new Meteor.Error(403, "User validation failed");
    });

    let userId;

    try {
      userId = this.users.insert(fullUser);
    } catch (e) {
      // XXX string parsing sucks, maybe
      // https://jira.mongodb.org/browse/SERVER-3069 will get fixed one day
      // https://jira.mongodb.org/browse/SERVER-4637
      if (!e.errmsg) throw e;
      if (e.errmsg.includes('emails.address')) throw new Meteor.Error(403, "Email already exists.");
      if (e.errmsg.includes('username')) throw new Meteor.Error(403, "Username already exists.");
      throw e;
    }

    return userId;
  }

  // Helper function: returns false if email does not match company domain from
  // the configuration.
  _testEmailDomain(email) {
    const domain = this._options.restrictCreationByEmailDomain;
    return !domain || typeof domain === 'function' && domain(email) || typeof domain === 'string' && new RegExp("@".concat(Meteor._escapeRegExp(domain), "$"), 'i').test(email);
  }

  ///
  /// CLEAN UP FOR `logoutOtherClients`
  ///
  _deleteSavedTokensForUser(userId, tokensToDelete) {
    if (tokensToDelete) {
      this.users.update(userId, {
        $unset: {
          "services.resume.haveLoginTokensToDelete": 1,
          "services.resume.loginTokensToDelete": 1
        },
        $pullAll: {
          "services.resume.loginTokens": tokensToDelete
        }
      });
    }
  }

  _deleteSavedTokensForAllUsersOnStartup() {
    // If we find users who have saved tokens to delete on startup, delete
    // them now. It's possible that the server could have crashed and come
    // back up before new tokens are found in localStorage, but this
    // shouldn't happen very often. We shouldn't put a delay here because
    // that would give a lot of power to an attacker with a stolen login
    // token and the ability to crash the server.
    Meteor.startup(() => {
      this.users.find({
        "services.resume.haveLoginTokensToDelete": true
      }, {
        fields: {
          "services.resume.loginTokensToDelete": 1
        }
      }).forEach(user => {
        this._deleteSavedTokensForUser(user._id, user.services.resume.loginTokensToDelete);
      });
    });
  }

  ///
  /// MANAGING USER OBJECTS
  ///
  // Updates or creates a user after we authenticate with a 3rd party.
  //
  // @param serviceName {String} Service name (eg, twitter).
  // @param serviceData {Object} Data to store in the user's record
  //        under services[serviceName]. Must include an "id" field
  //        which is a unique identifier for the user in the service.
  // @param options {Object, optional} Other options to pass to insertUserDoc
  //        (eg, profile)
  // @returns {Object} Object with token and id keys, like the result
  //        of the "login" method.
  //
  updateOrCreateUserFromExternalService(serviceName, serviceData, options) {
    options = _objectSpread({}, options);

    if (serviceName === "password" || serviceName === "resume") {
      throw new Error("Can't use updateOrCreateUserFromExternalService with internal service " + serviceName);
    }

    if (!hasOwn.call(serviceData, 'id')) {
      throw new Error("Service data for service ".concat(serviceName, " must include id"));
    } // Look for a user with the appropriate service user id.


    const selector = {};
    const serviceIdKey = "services.".concat(serviceName, ".id"); // XXX Temporary special case for Twitter. (Issue #629)
    //   The serviceData.id will be a string representation of an integer.
    //   We want it to match either a stored string or int representation.
    //   This is to cater to earlier versions of Meteor storing twitter
    //   user IDs in number form, and recent versions storing them as strings.
    //   This can be removed once migration technology is in place, and twitter
    //   users stored with integer IDs have been migrated to string IDs.

    if (serviceName === "twitter" && !isNaN(serviceData.id)) {
      selector["$or"] = [{}, {}];
      selector["$or"][0][serviceIdKey] = serviceData.id;
      selector["$or"][1][serviceIdKey] = parseInt(serviceData.id, 10);
    } else {
      selector[serviceIdKey] = serviceData.id;
    }

    let user = this.users.findOne(selector, {
      fields: this._options.defaultFieldSelector
    }); // Check to see if the developer has a custom way to find the user outside
    // of the general selectors above.

    if (!user && this._additionalFindUserOnExternalLogin) {
      user = this._additionalFindUserOnExternalLogin({
        serviceName,
        serviceData,
        options
      });
    } // Before continuing, run user hook to see if we should continue


    if (this._beforeExternalLoginHook && !this._beforeExternalLoginHook(serviceName, serviceData, user)) {
      throw new Meteor.Error(403, "Login forbidden");
    } // When creating a new user we pass through all options. When updating an
    // existing user, by default we only process/pass through the serviceData
    // (eg, so that we keep an unexpired access token and don't cache old email
    // addresses in serviceData.email). The onExternalLogin hook can be used when
    // creating or updating a user, to modify or pass through more options as
    // needed.


    let opts = user ? {} : options;

    if (this._onExternalLoginHook) {
      opts = this._onExternalLoginHook(options, user);
    }

    if (user) {
      pinEncryptedFieldsToUser(serviceData, user._id);
      let setAttrs = {};
      Object.keys(serviceData).forEach(key => setAttrs["services.".concat(serviceName, ".").concat(key)] = serviceData[key]); // XXX Maybe we should re-use the selector above and notice if the update
      //     touches nothing?

      setAttrs = _objectSpread(_objectSpread({}, setAttrs), opts);
      this.users.update(user._id, {
        $set: setAttrs
      });
      return {
        type: serviceName,
        userId: user._id
      };
    } else {
      // Create a new user with the service data.
      user = {
        services: {}
      };
      user.services[serviceName] = serviceData;
      return {
        type: serviceName,
        userId: this.insertUserDoc(opts, user)
      };
    }
  }

  // Removes default rate limiting rule
  removeDefaultRateLimit() {
    const resp = DDPRateLimiter.removeRule(this.defaultRateLimiterRuleId);
    this.defaultRateLimiterRuleId = null;
    return resp;
  }

  // Add a default rule of limiting logins, creating new users and password reset
  // to 5 times every 10 seconds per connection.
  addDefaultRateLimit() {
    if (!this.defaultRateLimiterRuleId) {
      this.defaultRateLimiterRuleId = DDPRateLimiter.addRule({
        userId: null,
        clientAddress: null,
        type: 'method',
        name: name => ['login', 'createUser', 'resetPassword', 'forgotPassword'].includes(name),
        connectionId: connectionId => true
      }, 5, 10000);
    }
  }

  /**
   * @summary Creates options for email sending for reset password and enroll account emails.
   * You can use this function when customizing a reset password or enroll account email sending.
   * @locus Server
   * @param {Object} email Which address of the user's to send the email to.
   * @param {Object} user The user object to generate options for.
   * @param {String} url URL to which user is directed to confirm the email.
   * @param {String} reason `resetPassword` or `enrollAccount`.
   * @returns {Object} Options which can be passed to `Email.send`.
   * @importFromPackage accounts-base
   */
  generateOptionsForEmail(email, user, url, reason) {
    let extra = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : {};
    const options = {
      to: email,
      from: this.emailTemplates[reason].from ? this.emailTemplates[reason].from(user) : this.emailTemplates.from,
      subject: this.emailTemplates[reason].subject(user, url, extra)
    };

    if (typeof this.emailTemplates[reason].text === 'function') {
      options.text = this.emailTemplates[reason].text(user, url, extra);
    }

    if (typeof this.emailTemplates[reason].html === 'function') {
      options.html = this.emailTemplates[reason].html(user, url, extra);
    }

    if (typeof this.emailTemplates.headers === 'object') {
      options.headers = this.emailTemplates.headers;
    }

    return options;
  }

  _checkForCaseInsensitiveDuplicates(fieldName, displayName, fieldValue, ownUserId) {
    // Some tests need the ability to add users with the same case insensitive
    // value, hence the _skipCaseInsensitiveChecksForTest check
    const skipCheck = Object.prototype.hasOwnProperty.call(this._skipCaseInsensitiveChecksForTest, fieldValue);

    if (fieldValue && !skipCheck) {
      const matchedUsers = Meteor.users.find(this._selectorForFastCaseInsensitiveLookup(fieldName, fieldValue), {
        fields: {
          _id: 1
        },
        // we only need a maximum of 2 users for the logic below to work
        limit: 2
      }).fetch();

      if (matchedUsers.length > 0 && ( // If we don't have a userId yet, any match we find is a duplicate
      !ownUserId || // Otherwise, check to see if there are multiple matches or a match
      // that is not us
      matchedUsers.length > 1 || matchedUsers[0]._id !== ownUserId)) {
        this._handleError("".concat(displayName, " already exists."));
      }
    }
  }

  _createUserCheckingDuplicates(_ref) {
    let {
      user,
      email,
      username,
      options
    } = _ref;

    const newUser = _objectSpread(_objectSpread(_objectSpread({}, user), username ? {
      username
    } : {}), email ? {
      emails: [{
        address: email,
        verified: false
      }]
    } : {}); // Perform a case insensitive check before insert


    this._checkForCaseInsensitiveDuplicates('username', 'Username', username);

    this._checkForCaseInsensitiveDuplicates('emails.address', 'Email', email);

    const userId = this.insertUserDoc(options, newUser); // Perform another check after insert, in case a matching user has been
    // inserted in the meantime

    try {
      this._checkForCaseInsensitiveDuplicates('username', 'Username', username, userId);

      this._checkForCaseInsensitiveDuplicates('emails.address', 'Email', email, userId);
    } catch (ex) {
      // Remove inserted user if the check fails
      Meteor.users.remove(userId);
      throw ex;
    }

    return userId;
  }

}

// Give each login hook callback a fresh cloned copy of the attempt
// object, but don't clone the connection.
//
const cloneAttemptWithConnection = (connection, attempt) => {
  const clonedAttempt = EJSON.clone(attempt);
  clonedAttempt.connection = connection;
  return clonedAttempt;
};

const tryLoginMethod = (type, fn) => {
  let result;

  try {
    result = fn();
  } catch (e) {
    result = {
      error: e
    };
  }

  if (result && !result.type && type) result.type = type;
  return result;
};

const setupDefaultLoginHandlers = accounts => {
  accounts.registerLoginHandler("resume", function (options) {
    return defaultResumeLoginHandler.call(this, accounts, options);
  });
}; // Login handler for resume tokens.


const defaultResumeLoginHandler = (accounts, options) => {
  if (!options.resume) return undefined;
  check(options.resume, String);

  const hashedToken = accounts._hashLoginToken(options.resume); // First look for just the new-style hashed login token, to avoid
  // sending the unhashed token to the database in a query if we don't
  // need to.


  let user = accounts.users.findOne({
    "services.resume.loginTokens.hashedToken": hashedToken
  }, {
    fields: {
      "services.resume.loginTokens.$": 1
    }
  });

  if (!user) {
    // If we didn't find the hashed login token, try also looking for
    // the old-style unhashed token.  But we need to look for either
    // the old-style token OR the new-style token, because another
    // client connection logging in simultaneously might have already
    // converted the token.
    user = accounts.users.findOne({
      $or: [{
        "services.resume.loginTokens.hashedToken": hashedToken
      }, {
        "services.resume.loginTokens.token": options.resume
      }]
    }, // Note: Cannot use ...loginTokens.$ positional operator with $or query.
    {
      fields: {
        "services.resume.loginTokens": 1
      }
    });
  }

  if (!user) return {
    error: new Meteor.Error(403, "You've been logged out by the server. Please log in again.")
  }; // Find the token, which will either be an object with fields
  // {hashedToken, when} for a hashed token or {token, when} for an
  // unhashed token.

  let oldUnhashedStyleToken;
  let token = user.services.resume.loginTokens.find(token => token.hashedToken === hashedToken);

  if (token) {
    oldUnhashedStyleToken = false;
  } else {
    token = user.services.resume.loginTokens.find(token => token.token === options.resume);
    oldUnhashedStyleToken = true;
  }

  const tokenExpires = accounts._tokenExpiration(token.when);

  if (new Date() >= tokenExpires) return {
    userId: user._id,
    error: new Meteor.Error(403, "Your session has expired. Please log in again.")
  }; // Update to a hashed token when an unhashed token is encountered.

  if (oldUnhashedStyleToken) {
    // Only add the new hashed token if the old unhashed token still
    // exists (this avoids resurrecting the token if it was deleted
    // after we read it).  Using $addToSet avoids getting an index
    // error if another client logging in simultaneously has already
    // inserted the new hashed token.
    accounts.users.update({
      _id: user._id,
      "services.resume.loginTokens.token": options.resume
    }, {
      $addToSet: {
        "services.resume.loginTokens": {
          "hashedToken": hashedToken,
          "when": token.when
        }
      }
    }); // Remove the old token *after* adding the new, since otherwise
    // another client trying to login between our removing the old and
    // adding the new wouldn't find a token to login with.

    accounts.users.update(user._id, {
      $pull: {
        "services.resume.loginTokens": {
          "token": options.resume
        }
      }
    });
  }

  return {
    userId: user._id,
    stampedLoginToken: {
      token: options.resume,
      when: token.when
    }
  };
};

const expirePasswordToken = (accounts, oldestValidDate, tokenFilter, userId) => {
  // boolean value used to determine if this method was called from enroll account workflow
  let isEnroll = false;
  const userFilter = userId ? {
    _id: userId
  } : {}; // check if this method was called from enroll account workflow

  if (tokenFilter['services.password.enroll.reason']) {
    isEnroll = true;
  }

  let resetRangeOr = {
    $or: [{
      "services.password.reset.when": {
        $lt: oldestValidDate
      }
    }, {
      "services.password.reset.when": {
        $lt: +oldestValidDate
      }
    }]
  };

  if (isEnroll) {
    resetRangeOr = {
      $or: [{
        "services.password.enroll.when": {
          $lt: oldestValidDate
        }
      }, {
        "services.password.enroll.when": {
          $lt: +oldestValidDate
        }
      }]
    };
  }

  const expireFilter = {
    $and: [tokenFilter, resetRangeOr]
  };

  if (isEnroll) {
    accounts.users.update(_objectSpread(_objectSpread({}, userFilter), expireFilter), {
      $unset: {
        "services.password.enroll": ""
      }
    }, {
      multi: true
    });
  } else {
    accounts.users.update(_objectSpread(_objectSpread({}, userFilter), expireFilter), {
      $unset: {
        "services.password.reset": ""
      }
    }, {
      multi: true
    });
  }
};

const setExpireTokensInterval = accounts => {
  accounts.expireTokenInterval = Meteor.setInterval(() => {
    accounts._expireTokens();

    accounts._expirePasswordResetTokens();

    accounts._expirePasswordEnrollTokens();
  }, EXPIRE_TOKENS_INTERVAL_MS);
}; ///
/// OAuth Encryption Support
///


const OAuthEncryption = Package["oauth-encryption"] && Package["oauth-encryption"].OAuthEncryption;

const usingOAuthEncryption = () => {
  return OAuthEncryption && OAuthEncryption.keyIsLoaded();
}; // OAuth service data is temporarily stored in the pending credentials
// collection during the oauth authentication process.  Sensitive data
// such as access tokens are encrypted without the user id because
// we don't know the user id yet.  We re-encrypt these fields with the
// user id included when storing the service data permanently in
// the users collection.
//


const pinEncryptedFieldsToUser = (serviceData, userId) => {
  Object.keys(serviceData).forEach(key => {
    let value = serviceData[key];
    if (OAuthEncryption && OAuthEncryption.isSealed(value)) value = OAuthEncryption.seal(OAuthEncryption.open(value), userId);
    serviceData[key] = value;
  });
}; // Encrypt unencrypted login service secrets when oauth-encryption is
// added.
//
// XXX For the oauthSecretKey to be available here at startup, the
// developer must call Accounts.config({oauthSecretKey: ...}) at load
// time, instead of in a Meteor.startup block, because the startup
// block in the app code will run after this accounts-base startup
// block.  Perhaps we need a post-startup callback?


Meteor.startup(() => {
  if (!usingOAuthEncryption()) {
    return;
  }

  const {
    ServiceConfiguration
  } = Package['service-configuration'];
  ServiceConfiguration.configurations.find({
    $and: [{
      secret: {
        $exists: true
      }
    }, {
      "secret.algorithm": {
        $exists: false
      }
    }]
  }).forEach(config => {
    ServiceConfiguration.configurations.update(config._id, {
      $set: {
        secret: OAuthEncryption.seal(config.secret)
      }
    });
  });
}); // XXX see comment on Accounts.createUser in passwords_server about adding a
// second "server options" argument.

const defaultCreateUserHook = (options, user) => {
  if (options.profile) user.profile = options.profile;
  return user;
}; // Validate new user's email or Google/Facebook/GitHub account's email


function defaultValidateNewUserHook(user) {
  const domain = this._options.restrictCreationByEmailDomain;

  if (!domain) {
    return true;
  }

  let emailIsGood = false;

  if (user.emails && user.emails.length > 0) {
    emailIsGood = user.emails.reduce((prev, email) => prev || this._testEmailDomain(email.address), false);
  } else if (user.services && Object.values(user.services).length > 0) {
    // Find any email of any service and check it
    emailIsGood = Object.values(user.services).reduce((prev, service) => service.email && this._testEmailDomain(service.email), false);
  }

  if (emailIsGood) {
    return true;
  }

  if (typeof domain === 'string') {
    throw new Meteor.Error(403, "@".concat(domain, " email required"));
  } else {
    throw new Meteor.Error(403, "Email doesn't match the criteria.");
  }
}

const setupUsersCollection = users => {
  ///
  /// RESTRICTING WRITES TO USER OBJECTS
  ///
  users.allow({
    // clients can modify the profile field of their own document, and
    // nothing else.
    update: (userId, user, fields, modifier) => {
      // make sure it is our record
      if (user._id !== userId) {
        return false;
      } // user can only modify the 'profile' field. sets to multiple
      // sub-keys (eg profile.foo and profile.bar) are merged into entry
      // in the fields list.


      if (fields.length !== 1 || fields[0] !== 'profile') {
        return false;
      }

      return true;
    },
    fetch: ['_id'] // we only look at _id.

  }); /// DEFAULT INDEXES ON USERS

  users.createIndex('username', {
    unique: true,
    sparse: true
  });
  users.createIndex('emails.address', {
    unique: true,
    sparse: true
  });
  users.createIndex('services.resume.loginTokens.hashedToken', {
    unique: true,
    sparse: true
  });
  users.createIndex('services.resume.loginTokens.token', {
    unique: true,
    sparse: true
  }); // For taking care of logoutOtherClients calls that crashed before the
  // tokens were deleted.

  users.createIndex('services.resume.haveLoginTokensToDelete', {
    sparse: true
  }); // For expiring login tokens

  users.createIndex("services.resume.loginTokens.when", {
    sparse: true
  }); // For expiring password tokens

  users.createIndex('services.password.reset.when', {
    sparse: true
  });
  users.createIndex('services.password.enroll.when', {
    sparse: true
  });
}; // Generates permutations of all case variations of a given string.


const generateCasePermutationsForString = string => {
  let permutations = [''];

  for (let i = 0; i < string.length; i++) {
    const ch = string.charAt(i);
    permutations = [].concat(...permutations.map(prefix => {
      const lowerCaseChar = ch.toLowerCase();
      const upperCaseChar = ch.toUpperCase(); // Don't add unnecessary permutations when ch is not a letter

      if (lowerCaseChar === upperCaseChar) {
        return [prefix + ch];
      } else {
        return [prefix + lowerCaseChar, prefix + upperCaseChar];
      }
    }));
  }

  return permutations;
};
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}}}}},{
  "extensions": [
    ".js",
    ".json"
  ]
});

var exports = require("/node_modules/meteor/accounts-base/server_main.js");

/* Exports */
Package._define("accounts-base", exports, {
  Accounts: Accounts
});

})();

//# sourceURL=meteor://💻app/packages/accounts-base.js
//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm1ldGVvcjovL/CfkrthcHAvcGFja2FnZXMvYWNjb3VudHMtYmFzZS9zZXJ2ZXJfbWFpbi5qcyIsIm1ldGVvcjovL/CfkrthcHAvcGFja2FnZXMvYWNjb3VudHMtYmFzZS9hY2NvdW50c19jb21tb24uanMiLCJtZXRlb3I6Ly/wn5K7YXBwL3BhY2thZ2VzL2FjY291bnRzLWJhc2UvYWNjb3VudHNfc2VydmVyLmpzIl0sIm5hbWVzIjpbIm1vZHVsZTEiLCJleHBvcnQiLCJBY2NvdW50c1NlcnZlciIsImxpbmsiLCJ2IiwiQWNjb3VudHMiLCJNZXRlb3IiLCJzZXJ2ZXIiLCJ1c2VycyIsIl9vYmplY3RTcHJlYWQiLCJtb2R1bGUiLCJkZWZhdWx0IiwiQWNjb3VudHNDb21tb24iLCJFWFBJUkVfVE9LRU5TX0lOVEVSVkFMX01TIiwiQ09OTkVDVElPTl9DTE9TRV9ERUxBWV9NUyIsIlZBTElEX0NPTkZJR19LRVlTIiwiY29uc3RydWN0b3IiLCJvcHRpb25zIiwiX29wdGlvbnMiLCJjb25uZWN0aW9uIiwidW5kZWZpbmVkIiwiX2luaXRDb25uZWN0aW9uIiwiTW9uZ28iLCJDb2xsZWN0aW9uIiwiX3ByZXZlbnRBdXRvcHVibGlzaCIsIl9vbkxvZ2luSG9vayIsIkhvb2siLCJiaW5kRW52aXJvbm1lbnQiLCJkZWJ1Z1ByaW50RXhjZXB0aW9ucyIsIl9vbkxvZ2luRmFpbHVyZUhvb2siLCJfb25Mb2dvdXRIb29rIiwiREVGQVVMVF9MT0dJTl9FWFBJUkFUSU9OX0RBWVMiLCJMT0dJTl9VTkVYUElSSU5HX1RPS0VOX0RBWVMiLCJsY2VOYW1lIiwiTG9naW5DYW5jZWxsZWRFcnJvciIsIm1ha2VFcnJvclR5cGUiLCJkZXNjcmlwdGlvbiIsIm1lc3NhZ2UiLCJwcm90b3R5cGUiLCJuYW1lIiwibnVtZXJpY0Vycm9yIiwic3RhcnR1cCIsIlNlcnZpY2VDb25maWd1cmF0aW9uIiwiUGFja2FnZSIsImxvZ2luU2VydmljZUNvbmZpZ3VyYXRpb24iLCJjb25maWd1cmF0aW9ucyIsIkNvbmZpZ0Vycm9yIiwic2V0dGluZ3MiLCJwYWNrYWdlcyIsIm9hdXRoU2VjcmV0S2V5IiwiRXJyb3IiLCJPQXV0aEVuY3J5cHRpb24iLCJsb2FkS2V5IiwiT2JqZWN0Iiwia2V5cyIsImZvckVhY2giLCJrZXkiLCJpbmNsdWRlcyIsInVzZXJJZCIsIl9hZGREZWZhdWx0RmllbGRTZWxlY3RvciIsImRlZmF1bHRGaWVsZFNlbGVjdG9yIiwiZmllbGRzIiwibGVuZ3RoIiwia2V5czIiLCJ1c2VyIiwiZmluZE9uZSIsImNvbmZpZyIsImlzU2VydmVyIiwiX19tZXRlb3JfcnVudGltZV9jb25maWdfXyIsImFjY291bnRzQ29uZmlnQ2FsbGVkIiwiX2RlYnVnIiwiaGFzT3duUHJvcGVydHkiLCJjYWxsIiwiaXNDbGllbnQiLCJvbkxvZ2luIiwiZnVuYyIsInJldCIsInJlZ2lzdGVyIiwiX3N0YXJ0dXBDYWxsYmFjayIsImNhbGxiYWNrIiwib25Mb2dpbkZhaWx1cmUiLCJvbkxvZ291dCIsImRkcFVybCIsIkREUCIsImNvbm5lY3QiLCJBQ0NPVU5UU19DT05ORUNUSU9OX1VSTCIsIl9nZXRUb2tlbkxpZmV0aW1lTXMiLCJsb2dpbkV4cGlyYXRpb25JbkRheXMiLCJsb2dpbkV4cGlyYXRpb24iLCJfZ2V0UGFzc3dvcmRSZXNldFRva2VuTGlmZXRpbWVNcyIsInBhc3N3b3JkUmVzZXRUb2tlbkV4cGlyYXRpb24iLCJwYXNzd29yZFJlc2V0VG9rZW5FeHBpcmF0aW9uSW5EYXlzIiwiREVGQVVMVF9QQVNTV09SRF9SRVNFVF9UT0tFTl9FWFBJUkFUSU9OX0RBWVMiLCJfZ2V0UGFzc3dvcmRFbnJvbGxUb2tlbkxpZmV0aW1lTXMiLCJwYXNzd29yZEVucm9sbFRva2VuRXhwaXJhdGlvbiIsInBhc3N3b3JkRW5yb2xsVG9rZW5FeHBpcmF0aW9uSW5EYXlzIiwiREVGQVVMVF9QQVNTV09SRF9FTlJPTExfVE9LRU5fRVhQSVJBVElPTl9EQVlTIiwiX3Rva2VuRXhwaXJhdGlvbiIsIndoZW4iLCJEYXRlIiwiZ2V0VGltZSIsIl90b2tlbkV4cGlyZXNTb29uIiwibWluTGlmZXRpbWVNcyIsIm1pbkxpZmV0aW1lQ2FwTXMiLCJNSU5fVE9LRU5fTElGRVRJTUVfQ0FQX1NFQ1MiLCJfb2JqZWN0V2l0aG91dFByb3BlcnRpZXMiLCJjcnlwdG8iLCJVUkwiLCJoYXNPd24iLCJOb25FbXB0eVN0cmluZyIsIk1hdGNoIiwiV2hlcmUiLCJ4IiwiY2hlY2siLCJTdHJpbmciLCJvbkNyZWF0ZUxvZ2luVG9rZW4iLCJfb25DcmVhdGVMb2dpblRva2VuSG9vayIsIl9zZWxlY3RvckZvckZhc3RDYXNlSW5zZW5zaXRpdmVMb29rdXAiLCJmaWVsZE5hbWUiLCJzdHJpbmciLCJwcmVmaXgiLCJzdWJzdHJpbmciLCJNYXRoIiwibWluIiwib3JDbGF1c2UiLCJnZW5lcmF0ZUNhc2VQZXJtdXRhdGlvbnNGb3JTdHJpbmciLCJtYXAiLCJwcmVmaXhQZXJtdXRhdGlvbiIsInNlbGVjdG9yIiwiUmVnRXhwIiwiX2VzY2FwZVJlZ0V4cCIsImNhc2VJbnNlbnNpdGl2ZUNsYXVzZSIsIiRhbmQiLCIkb3IiLCJfZmluZFVzZXJCeVF1ZXJ5IiwicXVlcnkiLCJpZCIsImZpZWxkVmFsdWUiLCJ1c2VybmFtZSIsImVtYWlsIiwiY2FuZGlkYXRlVXNlcnMiLCJmaW5kIiwiZmV0Y2giLCJfaGFuZGxlRXJyb3IiLCJtc2ciLCJ0aHJvd0Vycm9yIiwiZXJyb3IiLCJhbWJpZ3VvdXNFcnJvck1lc3NhZ2VzIiwiX3VzZXJRdWVyeVZhbGlkYXRvciIsIk9wdGlvbmFsIiwiX3NlcnZlciIsIl9pbml0U2VydmVyTWV0aG9kcyIsIl9pbml0QWNjb3VudERhdGFIb29rcyIsIl9hdXRvcHVibGlzaEZpZWxkcyIsImxvZ2dlZEluVXNlciIsIm90aGVyVXNlcnMiLCJfZGVmYXVsdFB1Ymxpc2hGaWVsZHMiLCJwcm9qZWN0aW9uIiwicHJvZmlsZSIsImVtYWlscyIsIl9pbml0U2VydmVyUHVibGljYXRpb25zIiwiX2FjY291bnREYXRhIiwiX3VzZXJPYnNlcnZlc0ZvckNvbm5lY3Rpb25zIiwiX25leHRVc2VyT2JzZXJ2ZU51bWJlciIsIl9sb2dpbkhhbmRsZXJzIiwic2V0dXBVc2Vyc0NvbGxlY3Rpb24iLCJzZXR1cERlZmF1bHRMb2dpbkhhbmRsZXJzIiwic2V0RXhwaXJlVG9rZW5zSW50ZXJ2YWwiLCJfdmFsaWRhdGVMb2dpbkhvb2siLCJfdmFsaWRhdGVOZXdVc2VySG9va3MiLCJkZWZhdWx0VmFsaWRhdGVOZXdVc2VySG9vayIsImJpbmQiLCJfZGVsZXRlU2F2ZWRUb2tlbnNGb3JBbGxVc2Vyc09uU3RhcnR1cCIsIl9za2lwQ2FzZUluc2Vuc2l0aXZlQ2hlY2tzRm9yVGVzdCIsInVybHMiLCJyZXNldFBhc3N3b3JkIiwidG9rZW4iLCJleHRyYVBhcmFtcyIsImJ1aWxkRW1haWxVcmwiLCJ2ZXJpZnlFbWFpbCIsImxvZ2luVG9rZW4iLCJlbnJvbGxBY2NvdW50IiwiYWRkRGVmYXVsdFJhdGVMaW1pdCIsInBhdGgiLCJ1cmwiLCJhYnNvbHV0ZVVybCIsInBhcmFtcyIsImVudHJpZXMiLCJ2YWx1ZSIsInNlYXJjaFBhcmFtcyIsImFwcGVuZCIsInRvU3RyaW5nIiwiY3VycmVudEludm9jYXRpb24iLCJfQ3VycmVudE1ldGhvZEludm9jYXRpb24iLCJnZXQiLCJfQ3VycmVudFB1YmxpY2F0aW9uSW52b2NhdGlvbiIsInZhbGlkYXRlTG9naW5BdHRlbXB0IiwidmFsaWRhdGVOZXdVc2VyIiwicHVzaCIsImJlZm9yZUV4dGVybmFsTG9naW4iLCJfYmVmb3JlRXh0ZXJuYWxMb2dpbkhvb2siLCJvbkNyZWF0ZVVzZXIiLCJfb25DcmVhdGVVc2VySG9vayIsIm9uRXh0ZXJuYWxMb2dpbiIsIl9vbkV4dGVybmFsTG9naW5Ib29rIiwic2V0QWRkaXRpb25hbEZpbmRVc2VyT25FeHRlcm5hbExvZ2luIiwiX2FkZGl0aW9uYWxGaW5kVXNlck9uRXh0ZXJuYWxMb2dpbiIsIl92YWxpZGF0ZUxvZ2luIiwiYXR0ZW1wdCIsImVhY2giLCJjbG9uZUF0dGVtcHRXaXRoQ29ubmVjdGlvbiIsImUiLCJhbGxvd2VkIiwiX3N1Y2Nlc3NmdWxMb2dpbiIsIl9mYWlsZWRMb2dpbiIsIl9zdWNjZXNzZnVsTG9nb3V0IiwiX2xvZ2luVXNlciIsIm1ldGhvZEludm9jYXRpb24iLCJzdGFtcGVkTG9naW5Ub2tlbiIsIl9nZW5lcmF0ZVN0YW1wZWRMb2dpblRva2VuIiwiX2luc2VydExvZ2luVG9rZW4iLCJfbm9ZaWVsZHNBbGxvd2VkIiwiX3NldExvZ2luVG9rZW4iLCJfaGFzaExvZ2luVG9rZW4iLCJzZXRVc2VySWQiLCJ0b2tlbkV4cGlyZXMiLCJfYXR0ZW1wdExvZ2luIiwibWV0aG9kTmFtZSIsIm1ldGhvZEFyZ3MiLCJyZXN1bHQiLCJ0eXBlIiwibWV0aG9kQXJndW1lbnRzIiwiQXJyYXkiLCJmcm9tIiwiX2xvZ2luTWV0aG9kIiwiZm4iLCJ0cnlMb2dpbk1ldGhvZCIsIl9yZXBvcnRMb2dpbkZhaWx1cmUiLCJyZWdpc3RlckxvZ2luSGFuZGxlciIsImhhbmRsZXIiLCJfcnVuTG9naW5IYW5kbGVycyIsImRlc3Ryb3lUb2tlbiIsInVwZGF0ZSIsIiRwdWxsIiwiaGFzaGVkVG9rZW4iLCJhY2NvdW50cyIsIm1ldGhvZHMiLCJsb2dpbiIsImFyZ3VtZW50cyIsImxvZ291dCIsIl9nZXRMb2dpblRva2VuIiwiZ2V0TmV3VG9rZW4iLCJjdXJyZW50SGFzaGVkVG9rZW4iLCJjdXJyZW50U3RhbXBlZFRva2VuIiwic2VydmljZXMiLCJyZXN1bWUiLCJsb2dpblRva2VucyIsInN0YW1wZWRUb2tlbiIsIm5ld1N0YW1wZWRUb2tlbiIsInJlbW92ZU90aGVyVG9rZW5zIiwiY3VycmVudFRva2VuIiwiJG5lIiwiY29uZmlndXJlTG9naW5TZXJ2aWNlIiwiT2JqZWN0SW5jbHVkaW5nIiwic2VydmljZSIsIm9hdXRoIiwic2VydmljZU5hbWVzIiwidXNpbmdPQXV0aEVuY3J5cHRpb24iLCJzZWNyZXQiLCJzZWFsIiwiaW5zZXJ0Iiwib25Db25uZWN0aW9uIiwib25DbG9zZSIsIl9yZW1vdmVUb2tlbkZyb21Db25uZWN0aW9uIiwicHVibGlzaCIsImlzX2F1dG8iLCJfaWQiLCJhdXRvcHVibGlzaCIsInRvRmllbGRTZWxlY3RvciIsInJlZHVjZSIsInByZXYiLCJmaWVsZCIsImFkZEF1dG9wdWJsaXNoRmllbGRzIiwib3B0cyIsImFwcGx5IiwiZm9yTG9nZ2VkSW5Vc2VyIiwiZm9yT3RoZXJVc2VycyIsInNldERlZmF1bHRQdWJsaXNoRmllbGRzIiwiX2dldEFjY291bnREYXRhIiwiY29ubmVjdGlvbklkIiwiZGF0YSIsIl9zZXRBY2NvdW50RGF0YSIsImhhc2giLCJjcmVhdGVIYXNoIiwiZGlnZXN0IiwiX2hhc2hTdGFtcGVkVG9rZW4iLCJoYXNoZWRTdGFtcGVkVG9rZW4iLCJfaW5zZXJ0SGFzaGVkTG9naW5Ub2tlbiIsIiRhZGRUb1NldCIsIl9jbGVhckFsbExvZ2luVG9rZW5zIiwiJHNldCIsIl9nZXRVc2VyT2JzZXJ2ZSIsIm9ic2VydmUiLCJzdG9wIiwibmV3VG9rZW4iLCJteU9ic2VydmVOdW1iZXIiLCJkZWZlciIsImZvdW5kTWF0Y2hpbmdVc2VyIiwib2JzZXJ2ZUNoYW5nZXMiLCJhZGRlZCIsInJlbW92ZWQiLCJjbG9zZSIsIm5vbk11dGF0aW5nQ2FsbGJhY2tzIiwiUmFuZG9tIiwiX2V4cGlyZVBhc3N3b3JkUmVzZXRUb2tlbnMiLCJvbGRlc3RWYWxpZERhdGUiLCJ0b2tlbkxpZmV0aW1lTXMiLCJ0b2tlbkZpbHRlciIsIiRleGlzdHMiLCJleHBpcmVQYXNzd29yZFRva2VuIiwiX2V4cGlyZVBhc3N3b3JkRW5yb2xsVG9rZW5zIiwiX2V4cGlyZVRva2VucyIsInVzZXJGaWx0ZXIiLCIkbHQiLCJtdWx0aSIsInN1cGVyUmVzdWx0IiwiZXhwaXJlVG9rZW5JbnRlcnZhbCIsImNsZWFySW50ZXJ2YWwiLCJpbnNlcnRVc2VyRG9jIiwiY3JlYXRlZEF0IiwicGluRW5jcnlwdGVkRmllbGRzVG9Vc2VyIiwiZnVsbFVzZXIiLCJkZWZhdWx0Q3JlYXRlVXNlckhvb2siLCJob29rIiwiZXJybXNnIiwiX3Rlc3RFbWFpbERvbWFpbiIsImRvbWFpbiIsInJlc3RyaWN0Q3JlYXRpb25CeUVtYWlsRG9tYWluIiwidGVzdCIsIl9kZWxldGVTYXZlZFRva2Vuc0ZvclVzZXIiLCJ0b2tlbnNUb0RlbGV0ZSIsIiR1bnNldCIsIiRwdWxsQWxsIiwibG9naW5Ub2tlbnNUb0RlbGV0ZSIsInVwZGF0ZU9yQ3JlYXRlVXNlckZyb21FeHRlcm5hbFNlcnZpY2UiLCJzZXJ2aWNlTmFtZSIsInNlcnZpY2VEYXRhIiwic2VydmljZUlkS2V5IiwiaXNOYU4iLCJwYXJzZUludCIsInNldEF0dHJzIiwicmVtb3ZlRGVmYXVsdFJhdGVMaW1pdCIsInJlc3AiLCJERFBSYXRlTGltaXRlciIsInJlbW92ZVJ1bGUiLCJkZWZhdWx0UmF0ZUxpbWl0ZXJSdWxlSWQiLCJhZGRSdWxlIiwiY2xpZW50QWRkcmVzcyIsImdlbmVyYXRlT3B0aW9uc0ZvckVtYWlsIiwicmVhc29uIiwiZXh0cmEiLCJ0byIsImVtYWlsVGVtcGxhdGVzIiwic3ViamVjdCIsInRleHQiLCJodG1sIiwiaGVhZGVycyIsIl9jaGVja0ZvckNhc2VJbnNlbnNpdGl2ZUR1cGxpY2F0ZXMiLCJkaXNwbGF5TmFtZSIsIm93blVzZXJJZCIsInNraXBDaGVjayIsIm1hdGNoZWRVc2VycyIsImxpbWl0IiwiX2NyZWF0ZVVzZXJDaGVja2luZ0R1cGxpY2F0ZXMiLCJuZXdVc2VyIiwiYWRkcmVzcyIsInZlcmlmaWVkIiwiZXgiLCJyZW1vdmUiLCJjbG9uZWRBdHRlbXB0IiwiRUpTT04iLCJjbG9uZSIsImRlZmF1bHRSZXN1bWVMb2dpbkhhbmRsZXIiLCJvbGRVbmhhc2hlZFN0eWxlVG9rZW4iLCJpc0Vucm9sbCIsInJlc2V0UmFuZ2VPciIsImV4cGlyZUZpbHRlciIsInNldEludGVydmFsIiwia2V5SXNMb2FkZWQiLCJpc1NlYWxlZCIsIm9wZW4iLCJlbWFpbElzR29vZCIsInZhbHVlcyIsImFsbG93IiwibW9kaWZpZXIiLCJjcmVhdGVJbmRleCIsInVuaXF1ZSIsInNwYXJzZSIsInBlcm11dGF0aW9ucyIsImkiLCJjaCIsImNoYXJBdCIsImNvbmNhdCIsImxvd2VyQ2FzZUNoYXIiLCJ0b0xvd2VyQ2FzZSIsInVwcGVyQ2FzZUNoYXIiLCJ0b1VwcGVyQ2FzZSJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBQSxTQUFPLENBQUNDLE1BQVIsQ0FBZTtBQUFDQyxrQkFBYyxFQUFDLE1BQUlBO0FBQXBCLEdBQWY7QUFBb0QsTUFBSUEsY0FBSjtBQUFtQkYsU0FBTyxDQUFDRyxJQUFSLENBQWEsc0JBQWIsRUFBb0M7QUFBQ0Qsa0JBQWMsQ0FBQ0UsQ0FBRCxFQUFHO0FBQUNGLG9CQUFjLEdBQUNFLENBQWY7QUFBaUI7O0FBQXBDLEdBQXBDLEVBQTBFLENBQTFFOztBQUV2RTtBQUNBO0FBQ0E7QUFDQTtBQUNBQyxVQUFRLEdBQUcsSUFBSUgsY0FBSixDQUFtQkksTUFBTSxDQUFDQyxNQUExQixDQUFYLEMsQ0FFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUNBRCxRQUFNLENBQUNFLEtBQVAsR0FBZUgsUUFBUSxDQUFDRyxLQUF4Qjs7Ozs7Ozs7Ozs7O0FDbEJBLElBQUlDLGFBQUo7O0FBQWtCQyxNQUFNLENBQUNQLElBQVAsQ0FBWSxzQ0FBWixFQUFtRDtBQUFDUSxTQUFPLENBQUNQLENBQUQsRUFBRztBQUFDSyxpQkFBYSxHQUFDTCxDQUFkO0FBQWdCOztBQUE1QixDQUFuRCxFQUFpRixDQUFqRjtBQUFsQk0sTUFBTSxDQUFDVCxNQUFQLENBQWM7QUFBQ1csZ0JBQWMsRUFBQyxNQUFJQSxjQUFwQjtBQUFtQ0MsMkJBQXlCLEVBQUMsTUFBSUEseUJBQWpFO0FBQTJGQywyQkFBeUIsRUFBQyxNQUFJQTtBQUF6SCxDQUFkO0FBQW1LLElBQUlSLE1BQUo7QUFBV0ksTUFBTSxDQUFDUCxJQUFQLENBQVksZUFBWixFQUE0QjtBQUFDRyxRQUFNLENBQUNGLENBQUQsRUFBRztBQUFDRSxVQUFNLEdBQUNGLENBQVA7QUFBUzs7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LENBNENBOzs7QUFDQSxNQUFNaFIsaUNBQWlDLEdBQUdOLE1BQU0sSUFBSTtBQUNsRCxNQUFJdVIsWUFBWSxHQUFHLENBQUMsRUFBRCxDQUFuQjs7QUFDQSxPQUFLLElBQUlDLENBQUMsR0FBRyxDQUFiLEVBQWdCQSxDQUFDLEdBQUd4UixNQUFNLENBQUN6RCxNQUEzQixFQUFtQ2lWLENBQUMsRUFBcEMsRUFBd0M7QUFDdEMsVUFBTUMsRUFBRSxHQUFHelIsTUFBTSxDQUFDMFIsTUFBUCxDQUFjRixDQUFkLENBQVg7QUFDQUQsZ0JBQVksR0FBRyxHQUFHSSxNQUFILENBQVUsR0FBSUosWUFBWSxDQUFDaFIsR0FBYixDQUFpQk4sTUFBTSxJQUFJO0FBQ3RELFlBQU0yUixhQUFhLEdBQUdILEVBQUUsQ0FBQ0ksV0FBSCxFQUF0QjtBQUNBLFlBQU1DLGFBQWEsR0FBR0wsRUFBRSxDQUFDTSxXQUFILEVBQXRCLENBRnNELENBR3REOztBQUNBLFVBQUlILGFBQWEsS0FBS0UsYUFBdEIsRUFBcUM7QUFDbkMsZUFBTyxDQUFDN1IsTUFBTSxHQUFHd1IsRUFBVixDQUFQO0FBQ0QsT0FGRCxNQUVPO0FBQ0wsZUFBTyxDQUFDeFIsTUFBTSxHQUFHMlIsYUFBVixFQUF5QjNSLE1BQU0sR0FBRzZSLGFBQWxDLENBQVA7QUFDRDtBQUNGLEtBVDRCLENBQWQsQ0FBZjtBQVVEOztBQUNELFNBQU9QLFlBQVA7QUFDRCxDQWhCRCxDIiwiZmlsZSI6Ii9wYWNrYWdlcy9hY2NvdW50cy1iYXNlLmpzIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgQWNjb3VudHNTZXJ2ZXIgfSBmcm9tIFwiLi9hY2NvdW50c19zZXJ2ZXIuanNcIjtcblxuLyoqXG4gKiBAbmFtZXNwYWNlIEFjY291bnRzXG4gKiBAc3VtbWFyeSBUaGUgbmFtZXNwYWNlIGZvciBhbGwgc2VydmVyLXNpZGUgYWNjb3VudHMtcmVsYXRlZCBtZXRob2RzLlxuICovXG5BY2NvdW50cyA9IG5ldyBBY2NvdW50c1NlcnZlcihNZXRlb3Iuc2VydmVyKTtcblxuLy8gVXNlcnMgdGFibGUuIERvbid0IHVzZSB0aGUgbm9ybWFsIGF1dG9wdWJsaXNoLCBzaW5jZSB3ZSB3YW50IHRvIGhpZGVcbi8vIHNvbWUgZmllbGRzLiBDb2RlIHRvIGF1dG9wdWJsaXNoIHRoaXMgaXMgaW4gYWNjb3VudHNfc2VydmVyLmpzLlxuLy8gWFhYIEFsbG93IHVzZXJzIHRvIGNvbmZpZ3VyZSB0aGlzIGNvbGxlY3Rpb24gbmFtZS5cblxuLyoqXG4gKiBAc3VtbWFyeSBBIFtNb25nby5Db2xsZWN0aW9uXSgjY29sbGVjdGlvbnMpIGNvbnRhaW5pbmcgdXNlciBkb2N1bWVudHMuXG4gKiBAbG9jdXMgQW55d2hlcmVcbiAqIEB0eXBlIHtNb25nby5Db2xsZWN0aW9ufVxuICogQGltcG9ydEZyb21QYWNrYWdlIG1ldGVvclxuKi9cbk1ldGVvci51c2VycyA9IEFjY291bnRzLnVzZXJzO1xuXG5leHBvcnQge1xuICAvLyBTaW5jZSB0aGlzIGZpbGUgaXMgdGhlIG1haW4gbW9kdWxlIGZvciB0aGUgc2VydmVyIHZlcnNpb24gb2YgdGhlXG4gIC8vIGFjY291bnRzLWJhc2UgcGFja2FnZSwgcHJvcGVydGllcyBvZiBub24tZW50cnktcG9pbnQgbW9kdWxlcyBuZWVkIHRvXG4gIC8vIGJlIHJlLWV4cG9ydGVkIGluIG9yZGVyIHRvIGJlIGFjY2Vzc2libGUgdG8gbW9kdWxlcyB0aGF0IGltcG9ydCB0aGVcbiAgLy8gYWNjb3VudHMtYmFzZSBwYWNrYWdlLlxuICBBY2NvdW50c1NlcnZlclxufTtcbiIsImltcG9ydCB7IE1ldGVvciB9IGZyb20gJ21ldGVvci9tZXRlb3InO1xuXG4vLyBjb25maWcgb3B0aW9uIGtleXNcbmNvbnN0IFZBTElEX0NPTkZJR19LRVlTID0gW1xuICAnc2VuZFZlcmlmaWNhdGlvbkVtYWlsJyxcbiAgJ2ZvcmJpZENsaWVudEFjY291bnRDcmVhdGlvbicsXG4gICdwYXNzd29yZEVucm9sbFRva2VuRXhwaXJhdGlvbicsXG4gICdwYXNzd29yZEVucm9sbFRva2VuRXhwaXJhdGlvbkluRGF5cycsXG4gICdyZXN0cmljdENyZWF0aW9uQnlFbWFpbERvbWFpbicsXG4gICdsb2dpbkV4cGlyYXRpb25JbkRheXMnLFxuICAnbG9naW5FeHBpcmF0aW9uJyxcbiAgJ3Bhc3N3b3JkUmVzZXRUb2tlbkV4cGlyYXRpb25JbkRheXMnLFxuICAncGFzc3dvcmRSZXNldFRva2VuRXhwaXJhdGlvbicsXG4gICdhbWJpZ3VvdXNFcnJvck1lc3NhZ2VzJyxcbiAgJ2JjcnlwdFJvdW5kcycsXG4gICdkZWZhdWx0RmllbGRTZWxlY3RvcicsXG5dO1xuXG4vKipcbiAqIEBzdW1tYXJ5IFN1cGVyLWNvbnN0cnVjdG9yIGZvciBBY2NvdW50c0NsaWVudCBhbmQgQWNjb3VudHNTZXJ2ZXIuXG4gKiBAbG9jdXMgQW55d2hlcmVcbiAqIEBjbGFzcyBBY2NvdW50c0NvbW1vblxuICogQGluc3RhbmNlbmFtZSBhY2NvdW50c0NsaWVudE9yU2VydmVyXG4gKiBAcGFyYW0gb3B0aW9ucyB7T2JqZWN0fSBhbiBvYmplY3Qgd2l0aCBmaWVsZHM6XG4gKiAtIGNvbm5lY3Rpb24ge09iamVjdH0gT3B0aW9uYWwgRERQIGNvbm5lY3Rpb24gdG8gcmV1c2UuXG4gKiAtIGRkcFVybCB7U3RyaW5nfSBPcHRpb25hbCBVUkwgZm9yIGNyZWF0aW5nIGEgbmV3IEREUCBjb25uZWN0aW9uLlxuICovXG5leHBvcnQgY2xhc3MgQWNjb3VudHNDb21tb24ge1xuICBjb25zdHJ1Y3RvcihvcHRpb25zKSB7XG4gICAgLy8gQ3VycmVudGx5IHRoaXMgaXMgcmVhZCBkaXJlY3RseSBieSBwYWNrYWdlcyBsaWtlIGFjY291bnRzLXBhc3N3b3JkXG4gICAgLy8gYW5kIGFjY291bnRzLXVpLXVuc3R5bGVkLlxuICAgIHRoaXMuX29wdGlvbnMgPSB7fTtcblxuICAgIC8vIE5vdGUgdGhhdCBzZXR0aW5nIHRoaXMuY29ubmVjdGlvbiA9IG51bGwgY2F1c2VzIHRoaXMudXNlcnMgdG8gYmUgYVxuICAgIC8vIExvY2FsQ29sbGVjdGlvbiwgd2hpY2ggaXMgbm90IHdoYXQgd2Ugd2FudC5cbiAgICB0aGlzLmNvbm5lY3Rpb24gPSB1bmRlZmluZWQ7XG4gICAgdGhpcy5faW5pdENvbm5lY3Rpb24ob3B0aW9ucyB8fCB7fSk7XG5cbiAgICAvLyBUaGVyZSBpcyBhbiBhbGxvdyBjYWxsIGluIGFjY291bnRzX3NlcnZlci5qcyB0aGF0IHJlc3RyaWN0cyB3cml0ZXMgdG9cbiAgICAvLyB0aGlzIGNvbGxlY3Rpb24uXG4gICAgdGhpcy51c2VycyA9IG5ldyBNb25nby5Db2xsZWN0aW9uKCd1c2VycycsIHtcbiAgICAgIF9wcmV2ZW50QXV0b3B1Ymxpc2g6IHRydWUsXG4gICAgICBjb25uZWN0aW9uOiB0aGlzLmNvbm5lY3Rpb24sXG4gICAgfSk7XG5cbiAgICAvLyBDYWxsYmFjayBleGNlcHRpb25zIGFyZSBwcmludGVkIHdpdGggTWV0ZW9yLl9kZWJ1ZyBhbmQgaWdub3JlZC5cbiAgICB0aGlzLl9vbkxvZ2luSG9vayA9IG5ldyBIb29rKHtcbiAgICAgIGJpbmRFbnZpcm9ubWVudDogZmFsc2UsXG4gICAgICBkZWJ1Z1ByaW50RXhjZXB0aW9uczogJ29uTG9naW4gY2FsbGJhY2snLFxuICAgIH0pO1xuXG4gICAgdGhpcy5fb25Mb2dpbkZhaWx1cmVIb29rID0gbmV3IEhvb2soe1xuICAgICAgYmluZEVudmlyb25tZW50OiBmYWxzZSxcbiAgICAgIGRlYnVnUHJpbnRFeGNlcHRpb25zOiAnb25Mb2dpbkZhaWx1cmUgY2FsbGJhY2snLFxuICAgIH0pO1xuXG4gICAgdGhpcy5fb25Mb2dvdXRIb29rID0gbmV3IEhvb2soe1xuICAgICAgYmluZEVudmlyb25tZW50OiBmYWxzZSxcbiAgICAgIGRlYnVnUHJpbnRFeGNlcHRpb25zOiAnb25Mb2dvdXQgY2FsbGJhY2snLFxuICAgIH0pO1xuXG4gICAgLy8gRXhwb3NlIGZvciB0ZXN0aW5nLlxuICAgIHRoaXMuREVGQVVMVF9MT0dJTl9FWFBJUkFUSU9OX0RBWVMgPSBERUZBVUxUX0xPR0lOX0VYUElSQVRJT05fREFZUztcbiAgICB0aGlzLkxPR0lOX1VORVhQSVJJTkdfVE9LRU5fREFZUyA9IExPR0lOX1VORVhQSVJJTkdfVE9LRU5fREFZUztcblxuICAgIC8vIFRocm93biB3aGVuIHRoZSB1c2VyIGNhbmNlbHMgdGhlIGxvZ2luIHByb2Nlc3MgKGVnLCBjbG9zZXMgYW4gb2F1dGhcbiAgICAvLyBwb3B1cCwgZGVjbGluZXMgcmV0aW5hIHNjYW4sIGV0YylcbiAgICBjb25zdCBsY2VOYW1lID0gJ0FjY291bnRzLkxvZ2luQ2FuY2VsbGVkRXJyb3InO1xuICAgIHRoaXMuTG9naW5DYW5jZWxsZWRFcnJvciA9IE1ldGVvci5tYWtlRXJyb3JUeXBlKGxjZU5hbWUsIGZ1bmN0aW9uKFxuICAgICAgZGVzY3JpcHRpb25cbiAgICApIHtcbiAgICAgIHRoaXMubWVzc2FnZSA9IGRlc2NyaXB0aW9uO1xuICAgIH0pO1xuICAgIHRoaXMuTG9naW5DYW5jZWxsZWRFcnJvci5wcm90b3R5cGUubmFtZSA9IGxjZU5hbWU7XG5cbiAgICAvLyBUaGlzIGlzIHVzZWQgdG8gdHJhbnNtaXQgc3BlY2lmaWMgc3ViY2xhc3MgZXJyb3JzIG92ZXIgdGhlIHdpcmUuIFdlXG4gICAgLy8gc2hvdWxkIGNvbWUgdXAgd2l0aCBhIG1vcmUgZ2VuZXJpYyB3YXkgdG8gZG8gdGhpcyAoZWcsIHdpdGggc29tZSBzb3J0IG9mXG4gICAgLy8gc3ltYm9saWMgZXJyb3IgY29kZSByYXRoZXIgdGhhbiBhIG51bWJlcikuXG4gICAgdGhpcy5Mb2dpbkNhbmNlbGxlZEVycm9yLm51bWVyaWNFcnJvciA9IDB4OGFjZGMyZjtcblxuICAgIC8vIGxvZ2luU2VydmljZUNvbmZpZ3VyYXRpb24gYW5kIENvbmZpZ0Vycm9yIGFyZSBtYWludGFpbmVkIGZvciBiYWNrd2FyZHMgY29tcGF0aWJpbGl0eVxuICAgIE1ldGVvci5zdGFydHVwKCgpID0+IHtcbiAgICAgIGNvbnN0IHsgU2VydmljZUNvbmZpZ3VyYXRpb24gfSA9IFBhY2thZ2VbJ3NlcnZpY2UtY29uZmlndXJhdGlvbiddO1xuICAgICAgdGhpcy5sb2dpblNlcnZpY2VDb25maWd1cmF0aW9uID0gU2VydmljZUNvbmZpZ3VyYXRpb24uY29uZmlndXJhdGlvbnM7XG4gICAgICB0aGlzLkNvbmZpZ0Vycm9yID0gU2VydmljZUNvbmZpZ3VyYXRpb24uQ29uZmlnRXJyb3I7XG5cbiAgICAgIGNvbnN0IHNldHRpbmdzID0gTWV0ZW9yLnNldHRpbmdzPy5wYWNrYWdlcz8uWydhY2NvdW50cy1iYXNlJ107XG4gICAgICBpZiAoc2V0dGluZ3MpIHtcbiAgICAgICAgaWYgKHNldHRpbmdzLm9hdXRoU2VjcmV0S2V5KSB7XG4gICAgICAgICAgaWYgKCFQYWNrYWdlWydvYXV0aC1lbmNyeXB0aW9uJ10pIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAgICAgJ1RoZSBvYXV0aC1lbmNyeXB0aW9uIHBhY2thZ2UgbXVzdCBiZSBsb2FkZWQgdG8gc2V0IG9hdXRoU2VjcmV0S2V5J1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgUGFja2FnZVsnb2F1dGgtZW5jcnlwdGlvbiddLk9BdXRoRW5jcnlwdGlvbi5sb2FkS2V5KFxuICAgICAgICAgICAgc2V0dGluZ3Mub2F1dGhTZWNyZXRLZXlcbiAgICAgICAgICApO1xuICAgICAgICAgIGRlbGV0ZSBzZXR0aW5ncy5vYXV0aFNlY3JldEtleTtcbiAgICAgICAgfVxuICAgICAgICAvLyBWYWxpZGF0ZSBjb25maWcgb3B0aW9ucyBrZXlzXG4gICAgICAgIE9iamVjdC5rZXlzKHNldHRpbmdzKS5mb3JFYWNoKGtleSA9PiB7XG4gICAgICAgICAgaWYgKCFWQUxJRF9DT05GSUdfS0VZUy5pbmNsdWRlcyhrZXkpKSB7XG4gICAgICAgICAgICAvLyBUT0RPIENvbnNpZGVyIGp1c3QgbG9nZ2luZyBhIGRlYnVnIG1lc3NhZ2UgaW5zdGVhZCB0byBhbGxvdyBmb3IgYWRkaXRpb25hbCBrZXlzIGluIHRoZSBzZXR0aW5ncyBoZXJlP1xuICAgICAgICAgICAgdGhyb3cgbmV3IE1ldGVvci5FcnJvcihcbiAgICAgICAgICAgICAgYEFjY291bnRzIGNvbmZpZ3VyYXRpb246IEludmFsaWQga2V5OiAke2tleX1gXG4gICAgICAgICAgICApO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAvLyBzZXQgdmFsdWVzIGluIEFjY291bnRzLl9vcHRpb25zXG4gICAgICAgICAgICB0aGlzLl9vcHRpb25zW2tleV0gPSBzZXR0aW5nc1trZXldO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogQHN1bW1hcnkgR2V0IHRoZSBjdXJyZW50IHVzZXIgaWQsIG9yIGBudWxsYCBpZiBubyB1c2VyIGlzIGxvZ2dlZCBpbi4gQSByZWFjdGl2ZSBkYXRhIHNvdXJjZS5cbiAgICogQGxvY3VzIEFueXdoZXJlXG4gICAqL1xuICB1c2VySWQoKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCd1c2VySWQgbWV0aG9kIG5vdCBpbXBsZW1lbnRlZCcpO1xuICB9XG5cbiAgLy8gbWVyZ2UgdGhlIGRlZmF1bHRGaWVsZFNlbGVjdG9yIHdpdGggYW4gZXhpc3Rpbmcgb3B0aW9ucyBvYmplY3RcbiAgX2FkZERlZmF1bHRGaWVsZFNlbGVjdG9yKG9wdGlvbnMgPSB7fSkge1xuICAgIC8vIHRoaXMgd2lsbCBiZSB0aGUgbW9zdCBjb21tb24gY2FzZSBmb3IgbW9zdCBwZW9wbGUsIHNvIG1ha2UgaXQgcXVpY2tcbiAgICBpZiAoIXRoaXMuX29wdGlvbnMuZGVmYXVsdEZpZWxkU2VsZWN0b3IpIHJldHVybiBvcHRpb25zO1xuXG4gICAgLy8gaWYgbm8gZmllbGQgc2VsZWN0b3IgdGhlbiBqdXN0IHVzZSBkZWZhdWx0RmllbGRTZWxlY3RvclxuICAgIGlmICghb3B0aW9ucy5maWVsZHMpXG4gICAgICByZXR1cm4ge1xuICAgICAgICAuLi5vcHRpb25zLFxuICAgICAgICBmaWVsZHM6IHRoaXMuX29wdGlvbnMuZGVmYXVsdEZpZWxkU2VsZWN0b3IsXG4gICAgICB9O1xuXG4gICAgLy8gaWYgZW1wdHkgZmllbGQgc2VsZWN0b3IgdGhlbiB0aGUgZnVsbCB1c2VyIG9iamVjdCBpcyBleHBsaWNpdGx5IHJlcXVlc3RlZCwgc28gb2JleVxuICAgIGNvbnN0IGtleXMgPSBPYmplY3Qua2V5cyhvcHRpb25zLmZpZWxkcyk7XG4gICAgaWYgKCFrZXlzLmxlbmd0aCkgcmV0dXJuIG9wdGlvbnM7XG5cbiAgICAvLyBpZiB0aGUgcmVxdWVzdGVkIGZpZWxkcyBhcmUgK3ZlIHRoZW4gaWdub3JlIGRlZmF1bHRGaWVsZFNlbGVjdG9yXG4gICAgLy8gYXNzdW1lIHRoZXkgYXJlIGFsbCBlaXRoZXIgK3ZlIG9yIC12ZSBiZWNhdXNlIE1vbmdvIGRvZXNuJ3QgbGlrZSBtaXhlZFxuICAgIGlmICghIW9wdGlvbnMuZmllbGRzW2tleXNbMF1dKSByZXR1cm4gb3B0aW9ucztcblxuICAgIC8vIFRoZSByZXF1ZXN0ZWQgZmllbGRzIGFyZSAtdmUuXG4gICAgLy8gSWYgdGhlIGRlZmF1bHRGaWVsZFNlbGVjdG9yIGlzICt2ZSB0aGVuIHVzZSByZXF1ZXN0ZWQgZmllbGRzLCBvdGhlcndpc2UgbWVyZ2UgdGhlbVxuICAgIGNvbnN0IGtleXMyID0gT2JqZWN0LmtleXModGhpcy5fb3B0aW9ucy5kZWZhdWx0RmllbGRTZWxlY3Rvcik7XG4gICAgcmV0dXJuIHRoaXMuX29wdGlvbnMuZGVmYXVsdEZpZWxkU2VsZWN0b3Jba2V5czJbMF1dXG4gICAgICA/IG9wdGlvbnNcbiAgICAgIDoge1xuICAgICAgICAgIC4uLm9wdGlvbnMsXG4gICAgICAgICAgZmllbGRzOiB7XG4gICAgICAgICAgICAuLi5vcHRpb25zLmZpZWxkcyxcbiAgICAgICAgICAgIC4uLnRoaXMuX29wdGlvbnMuZGVmYXVsdEZpZWxkU2VsZWN0b3IsXG4gICAgICAgICAgfSxcbiAgICAgICAgfTtcbiAgfVxuXG4gIC8qKlxuICAgKiBAc3VtbWFyeSBHZXQgdGhlIGN1cnJlbnQgdXNlciByZWNvcmQsIG9yIGBudWxsYCBpZiBubyB1c2VyIGlzIGxvZ2dlZCBpbi4gQSByZWFjdGl2ZSBkYXRhIHNvdXJjZS5cbiAgICogQGxvY3VzIEFueXdoZXJlXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBbb3B0aW9uc11cbiAgICogQHBhcmFtIHtNb25nb0ZpZWxkU3BlY2lmaWVyfSBvcHRpb25zLmZpZWxkcyBEaWN0aW9uYXJ5IG9mIGZpZWxkcyB0byByZXR1cm4gb3IgZXhjbHVkZS5cbiAgICovXG4gIHVzZXIob3B0aW9ucykge1xuICAgIGNvbnN0IHVzZXJJZCA9IHRoaXMudXNlcklkKCk7XG4gICAgcmV0dXJuIHVzZXJJZFxuICAgICAgPyB0aGlzLnVzZXJzLmZpbmRPbmUodXNlcklkLCB0aGlzLl9hZGREZWZhdWx0RmllbGRTZWxlY3RvcihvcHRpb25zKSlcbiAgICAgIDogbnVsbDtcbiAgfVxuXG4gIC8vIFNldCB1cCBjb25maWcgZm9yIHRoZSBhY2NvdW50cyBzeXN0ZW0uIENhbGwgdGhpcyBvbiBib3RoIHRoZSBjbGllbnRcbiAgLy8gYW5kIHRoZSBzZXJ2ZXIuXG4gIC8vXG4gIC8vIE5vdGUgdGhhdCB0aGlzIG1ldGhvZCBnZXRzIG92ZXJyaWRkZW4gb24gQWNjb3VudHNTZXJ2ZXIucHJvdG90eXBlLCBidXRcbiAgLy8gdGhlIG92ZXJyaWRpbmcgbWV0aG9kIGNhbGxzIHRoZSBvdmVycmlkZGVuIG1ldGhvZC5cbiAgLy9cbiAgLy8gWFhYIHdlIHNob3VsZCBhZGQgc29tZSBlbmZvcmNlbWVudCB0aGF0IHRoaXMgaXMgY2FsbGVkIG9uIGJvdGggdGhlXG4gIC8vIGNsaWVudCBhbmQgdGhlIHNlcnZlci4gT3RoZXJ3aXNlLCBhIHVzZXIgY2FuXG4gIC8vICdmb3JiaWRDbGllbnRBY2NvdW50Q3JlYXRpb24nIG9ubHkgb24gdGhlIGNsaWVudCBhbmQgd2hpbGUgaXQgbG9va3NcbiAgLy8gbGlrZSB0aGVpciBhcHAgaXMgc2VjdXJlLCB0aGUgc2VydmVyIHdpbGwgc3RpbGwgYWNjZXB0IGNyZWF0ZVVzZXJcbiAgLy8gY2FsbHMuIGh0dHBzOi8vZ2l0aHViLmNvbS9tZXRlb3IvbWV0ZW9yL2lzc3Vlcy84MjhcbiAgLy9cbiAgLy8gQHBhcmFtIG9wdGlvbnMge09iamVjdH0gYW4gb2JqZWN0IHdpdGggZmllbGRzOlxuICAvLyAtIHNlbmRWZXJpZmljYXRpb25FbWFpbCB7Qm9vbGVhbn1cbiAgLy8gICAgIFNlbmQgZW1haWwgYWRkcmVzcyB2ZXJpZmljYXRpb24gZW1haWxzIHRvIG5ldyB1c2VycyBjcmVhdGVkIGZyb21cbiAgLy8gICAgIGNsaWVudCBzaWdudXBzLlxuICAvLyAtIGZvcmJpZENsaWVudEFjY291bnRDcmVhdGlvbiB7Qm9vbGVhbn1cbiAgLy8gICAgIERvIG5vdCBhbGxvdyBjbGllbnRzIHRvIGNyZWF0ZSBhY2NvdW50cyBkaXJlY3RseS5cbiAgLy8gLSByZXN0cmljdENyZWF0aW9uQnlFbWFpbERvbWFpbiB7RnVuY3Rpb24gb3IgU3RyaW5nfVxuICAvLyAgICAgUmVxdWlyZSBjcmVhdGVkIHVzZXJzIHRvIGhhdmUgYW4gZW1haWwgbWF0Y2hpbmcgdGhlIGZ1bmN0aW9uIG9yXG4gIC8vICAgICBoYXZpbmcgdGhlIHN0cmluZyBhcyBkb21haW4uXG4gIC8vIC0gbG9naW5FeHBpcmF0aW9uSW5EYXlzIHtOdW1iZXJ9XG4gIC8vICAgICBOdW1iZXIgb2YgZGF5cyBzaW5jZSBsb2dpbiB1bnRpbCBhIHVzZXIgaXMgbG9nZ2VkIG91dCAobG9naW4gdG9rZW5cbiAgLy8gICAgIGV4cGlyZXMpLlxuICAvLyAtIHBhc3N3b3JkUmVzZXRUb2tlbkV4cGlyYXRpb25JbkRheXMge051bWJlcn1cbiAgLy8gICAgIE51bWJlciBvZiBkYXlzIHNpbmNlIHBhc3N3b3JkIHJlc2V0IHRva2VuIGNyZWF0aW9uIHVudGlsIHRoZVxuICAvLyAgICAgdG9rZW4gY2FubnQgYmUgdXNlZCBhbnkgbG9uZ2VyIChwYXNzd29yZCByZXNldCB0b2tlbiBleHBpcmVzKS5cbiAgLy8gLSBhbWJpZ3VvdXNFcnJvck1lc3NhZ2VzIHtCb29sZWFufVxuICAvLyAgICAgUmV0dXJuIGFtYmlndW91cyBlcnJvciBtZXNzYWdlcyBmcm9tIGxvZ2luIGZhaWx1cmVzIHRvIHByZXZlbnRcbiAgLy8gICAgIHVzZXIgZW51bWVyYXRpb24uXG4gIC8vIC0gYmNyeXB0Um91bmRzIHtOdW1iZXJ9XG4gIC8vICAgICBBbGxvd3Mgb3ZlcnJpZGUgb2YgbnVtYmVyIG9mIGJjcnlwdCByb3VuZHMgKGFrYSB3b3JrIGZhY3RvcikgdXNlZFxuICAvLyAgICAgdG8gc3RvcmUgcGFzc3dvcmRzLlxuXG4gIC8qKlxuICAgKiBAc3VtbWFyeSBTZXQgZ2xvYmFsIGFjY291bnRzIG9wdGlvbnMuIFlvdSBjYW4gYWxzbyBzZXQgdGhlc2UgaW4gYE1ldGVvci5zZXR0aW5ncy5wYWNrYWdlcy5hY2NvdW50c2Agd2l0aG91dCB0aGUgbmVlZCB0byBjYWxsIHRoaXMgZnVuY3Rpb24uXG4gICAqIEBsb2N1cyBBbnl3aGVyZVxuICAgKiBAcGFyYW0ge09iamVjdH0gb3B0aW9uc1xuICAgKiBAcGFyYW0ge0Jvb2xlYW59IG9wdGlvbnMuc2VuZFZlcmlmaWNhdGlvbkVtYWlsIE5ldyB1c2VycyB3aXRoIGFuIGVtYWlsIGFkZHJlc3Mgd2lsbCByZWNlaXZlIGFuIGFkZHJlc3MgdmVyaWZpY2F0aW9uIGVtYWlsLlxuICAgKiBAcGFyYW0ge0Jvb2xlYW59IG9wdGlvbnMuZm9yYmlkQ2xpZW50QWNjb3VudENyZWF0aW9uIENhbGxzIHRvIFtgY3JlYXRlVXNlcmBdKCNhY2NvdW50c19jcmVhdGV1c2VyKSBmcm9tIHRoZSBjbGllbnQgd2lsbCBiZSByZWplY3RlZC4gSW4gYWRkaXRpb24sIGlmIHlvdSBhcmUgdXNpbmcgW2FjY291bnRzLXVpXSgjYWNjb3VudHN1aSksIHRoZSBcIkNyZWF0ZSBhY2NvdW50XCIgbGluayB3aWxsIG5vdCBiZSBhdmFpbGFibGUuXG4gICAqIEBwYXJhbSB7U3RyaW5nIHwgRnVuY3Rpb259IG9wdGlvbnMucmVzdHJpY3RDcmVhdGlvbkJ5RW1haWxEb21haW4gSWYgc2V0IHRvIGEgc3RyaW5nLCBvbmx5IGFsbG93cyBuZXcgdXNlcnMgaWYgdGhlIGRvbWFpbiBwYXJ0IG9mIHRoZWlyIGVtYWlsIGFkZHJlc3MgbWF0Y2hlcyB0aGUgc3RyaW5nLiBJZiBzZXQgdG8gYSBmdW5jdGlvbiwgb25seSBhbGxvd3MgbmV3IHVzZXJzIGlmIHRoZSBmdW5jdGlvbiByZXR1cm5zIHRydWUuICBUaGUgZnVuY3Rpb24gaXMgcGFzc2VkIHRoZSBmdWxsIGVtYWlsIGFkZHJlc3Mgb2YgdGhlIHByb3Bvc2VkIG5ldyB1c2VyLiAgV29ya3Mgd2l0aCBwYXNzd29yZC1iYXNlZCBzaWduLWluIGFuZCBleHRlcm5hbCBzZXJ2aWNlcyB0aGF0IGV4cG9zZSBlbWFpbCBhZGRyZXNzZXMgKEdvb2dsZSwgRmFjZWJvb2ssIEdpdEh1YikuIEFsbCBleGlzdGluZyB1c2VycyBzdGlsbCBjYW4gbG9nIGluIGFmdGVyIGVuYWJsaW5nIHRoaXMgb3B0aW9uLiBFeGFtcGxlOiBgQWNjb3VudHMuY29uZmlnKHsgcmVzdHJpY3RDcmVhdGlvbkJ5RW1haWxEb21haW46ICdzY2hvb2wuZWR1JyB9KWAuXG4gICAqIEBwYXJhbSB7TnVtYmVyfSBvcHRpb25zLmxvZ2luRXhwaXJhdGlvbkluRGF5cyBUaGUgbnVtYmVyIG9mIGRheXMgZnJvbSB3aGVuIGEgdXNlciBsb2dzIGluIHVudGlsIHRoZWlyIHRva2VuIGV4cGlyZXMgYW5kIHRoZXkgYXJlIGxvZ2dlZCBvdXQuIERlZmF1bHRzIHRvIDkwLiBTZXQgdG8gYG51bGxgIHRvIGRpc2FibGUgbG9naW4gZXhwaXJhdGlvbi5cbiAgICogQHBhcmFtIHtOdW1iZXJ9IG9wdGlvbnMubG9naW5FeHBpcmF0aW9uIFRoZSBudW1iZXIgb2YgbWlsbGlzZWNvbmRzIGZyb20gd2hlbiBhIHVzZXIgbG9ncyBpbiB1bnRpbCB0aGVpciB0b2tlbiBleHBpcmVzIGFuZCB0aGV5IGFyZSBsb2dnZWQgb3V0LCBmb3IgYSBtb3JlIGdyYW51bGFyIGNvbnRyb2wuIElmIGBsb2dpbkV4cGlyYXRpb25JbkRheXNgIGlzIHNldCwgaXQgdGFrZXMgcHJlY2VkZW50LlxuICAgKiBAcGFyYW0ge1N0cmluZ30gb3B0aW9ucy5vYXV0aFNlY3JldEtleSBXaGVuIHVzaW5nIHRoZSBgb2F1dGgtZW5jcnlwdGlvbmAgcGFja2FnZSwgdGhlIDE2IGJ5dGUga2V5IHVzaW5nIHRvIGVuY3J5cHQgc2Vuc2l0aXZlIGFjY291bnQgY3JlZGVudGlhbHMgaW4gdGhlIGRhdGFiYXNlLCBlbmNvZGVkIGluIGJhc2U2NC4gIFRoaXMgb3B0aW9uIG1heSBvbmx5IGJlIHNwZWNpZmllZCBvbiB0aGUgc2VydmVyLiAgU2VlIHBhY2thZ2VzL29hdXRoLWVuY3J5cHRpb24vUkVBRE1FLm1kIGZvciBkZXRhaWxzLlxuICAgKiBAcGFyYW0ge051bWJlcn0gb3B0aW9ucy5wYXNzd29yZFJlc2V0VG9rZW5FeHBpcmF0aW9uSW5EYXlzIFRoZSBudW1iZXIgb2YgZGF5cyBmcm9tIHdoZW4gYSBsaW5rIHRvIHJlc2V0IHBhc3N3b3JkIGlzIHNlbnQgdW50aWwgdG9rZW4gZXhwaXJlcyBhbmQgdXNlciBjYW4ndCByZXNldCBwYXNzd29yZCB3aXRoIHRoZSBsaW5rIGFueW1vcmUuIERlZmF1bHRzIHRvIDMuXG4gICAqIEBwYXJhbSB7TnVtYmVyfSBvcHRpb25zLnBhc3N3b3JkUmVzZXRUb2tlbkV4cGlyYXRpb24gVGhlIG51bWJlciBvZiBtaWxsaXNlY29uZHMgZnJvbSB3aGVuIGEgbGluayB0byByZXNldCBwYXNzd29yZCBpcyBzZW50IHVudGlsIHRva2VuIGV4cGlyZXMgYW5kIHVzZXIgY2FuJ3QgcmVzZXQgcGFzc3dvcmQgd2l0aCB0aGUgbGluayBhbnltb3JlLiBJZiBgcGFzc3dvcmRSZXNldFRva2VuRXhwaXJhdGlvbkluRGF5c2AgaXMgc2V0LCBpdCB0YWtlcyBwcmVjZWRlbnQuXG4gICAqIEBwYXJhbSB7TnVtYmVyfSBvcHRpb25zLnBhc3N3b3JkRW5yb2xsVG9rZW5FeHBpcmF0aW9uSW5EYXlzIFRoZSBudW1iZXIgb2YgZGF5cyBmcm9tIHdoZW4gYSBsaW5rIHRvIHNldCBpbml0aWFsIHBhc3N3b3JkIGlzIHNlbnQgdW50aWwgdG9rZW4gZXhwaXJlcyBhbmQgdXNlciBjYW4ndCBzZXQgcGFzc3dvcmQgd2l0aCB0aGUgbGluayBhbnltb3JlLiBEZWZhdWx0cyB0byAzMC5cbiAgICogQHBhcmFtIHtOdW1iZXJ9IG9wdGlvbnMucGFzc3dvcmRFbnJvbGxUb2tlbkV4cGlyYXRpb24gVGhlIG51bWJlciBvZiBtaWxsaXNlY29uZHMgZnJvbSB3aGVuIGEgbGluayB0byBzZXQgaW5pdGlhbCBwYXNzd29yZCBpcyBzZW50IHVudGlsIHRva2VuIGV4cGlyZXMgYW5kIHVzZXIgY2FuJ3Qgc2V0IHBhc3N3b3JkIHdpdGggdGhlIGxpbmsgYW55bW9yZS4gSWYgYHBhc3N3b3JkRW5yb2xsVG9rZW5FeHBpcmF0aW9uSW5EYXlzYCBpcyBzZXQsIGl0IHRha2VzIHByZWNlZGVudC5cbiAgICogQHBhcmFtIHtCb29sZWFufSBvcHRpb25zLmFtYmlndW91c0Vycm9yTWVzc2FnZXMgUmV0dXJuIGFtYmlndW91cyBlcnJvciBtZXNzYWdlcyBmcm9tIGxvZ2luIGZhaWx1cmVzIHRvIHByZXZlbnQgdXNlciBlbnVtZXJhdGlvbi4gRGVmYXVsdHMgdG8gZmFsc2UuXG4gICAqIEBwYXJhbSB7TW9uZ29GaWVsZFNwZWNpZmllcn0gb3B0aW9ucy5kZWZhdWx0RmllbGRTZWxlY3RvciBUbyBleGNsdWRlIGJ5IGRlZmF1bHQgbGFyZ2UgY3VzdG9tIGZpZWxkcyBmcm9tIGBNZXRlb3IudXNlcigpYCBhbmQgYE1ldGVvci5maW5kVXNlckJ5Li4uKClgIGZ1bmN0aW9ucyB3aGVuIGNhbGxlZCB3aXRob3V0IGEgZmllbGQgc2VsZWN0b3IsIGFuZCBhbGwgYG9uTG9naW5gLCBgb25Mb2dpbkZhaWx1cmVgIGFuZCBgb25Mb2dvdXRgIGNhbGxiYWNrcy4gIEV4YW1wbGU6IGBBY2NvdW50cy5jb25maWcoeyBkZWZhdWx0RmllbGRTZWxlY3RvcjogeyBteUJpZ0FycmF5OiAwIH19KWAuIEJld2FyZSB3aGVuIHVzaW5nIHRoaXMuIElmLCBmb3IgaW5zdGFuY2UsIHlvdSBkbyBub3QgaW5jbHVkZSBgZW1haWxgIHdoZW4gZXhjbHVkaW5nIHRoZSBmaWVsZHMsIHlvdSBjYW4gaGF2ZSBwcm9ibGVtcyB3aXRoIGZ1bmN0aW9ucyBsaWtlIGBmb3Jnb3RQYXNzd29yZGAgdGhhdCB3aWxsIGJyZWFrIGJlY2F1c2UgdGhleSB3b24ndCBoYXZlIHRoZSByZXF1aXJlZCBkYXRhIGF2YWlsYWJsZS4gSXQncyByZWNvbW1lbmQgdGhhdCB5b3UgYWx3YXlzIGtlZXAgdGhlIGZpZWxkcyBgX2lkYCwgYHVzZXJuYW1lYCwgYW5kIGBlbWFpbGAuXG4gICAqL1xuICBjb25maWcob3B0aW9ucykge1xuICAgIC8vIFdlIGRvbid0IHdhbnQgdXNlcnMgdG8gYWNjaWRlbnRhbGx5IG9ubHkgY2FsbCBBY2NvdW50cy5jb25maWcgb24gdGhlXG4gICAgLy8gY2xpZW50LCB3aGVyZSBzb21lIG9mIHRoZSBvcHRpb25zIHdpbGwgaGF2ZSBwYXJ0aWFsIGVmZmVjdHMgKGVnIHJlbW92aW5nXG4gICAgLy8gdGhlIFwiY3JlYXRlIGFjY291bnRcIiBidXR0b24gZnJvbSBhY2NvdW50cy11aSBpZiBmb3JiaWRDbGllbnRBY2NvdW50Q3JlYXRpb25cbiAgICAvLyBpcyBzZXQsIG9yIHJlZGlyZWN0aW5nIEdvb2dsZSBsb2dpbiB0byBhIHNwZWNpZmljLWRvbWFpbiBwYWdlKSB3aXRob3V0XG4gICAgLy8gaGF2aW5nIHRoZWlyIGZ1bGwgZWZmZWN0cy5cbiAgICBpZiAoTWV0ZW9yLmlzU2VydmVyKSB7XG4gICAgICBfX21ldGVvcl9ydW50aW1lX2NvbmZpZ19fLmFjY291bnRzQ29uZmlnQ2FsbGVkID0gdHJ1ZTtcbiAgICB9IGVsc2UgaWYgKCFfX21ldGVvcl9ydW50aW1lX2NvbmZpZ19fLmFjY291bnRzQ29uZmlnQ2FsbGVkKSB7XG4gICAgICAvLyBYWFggd291bGQgYmUgbmljZSB0byBcImNyYXNoXCIgdGhlIGNsaWVudCBhbmQgcmVwbGFjZSB0aGUgVUkgd2l0aCBhbiBlcnJvclxuICAgICAgLy8gbWVzc2FnZSwgYnV0IHRoZXJlJ3Mgbm8gdHJpdmlhbCB3YXkgdG8gZG8gdGhpcy5cbiAgICAgIE1ldGVvci5fZGVidWcoXG4gICAgICAgICdBY2NvdW50cy5jb25maWcgd2FzIGNhbGxlZCBvbiB0aGUgY2xpZW50IGJ1dCBub3Qgb24gdGhlICcgK1xuICAgICAgICAgICdzZXJ2ZXI7IHNvbWUgY29uZmlndXJhdGlvbiBvcHRpb25zIG1heSBub3QgdGFrZSBlZmZlY3QuJ1xuICAgICAgKTtcbiAgICB9XG5cbiAgICAvLyBXZSBuZWVkIHRvIHZhbGlkYXRlIHRoZSBvYXV0aFNlY3JldEtleSBvcHRpb24gYXQgdGhlIHRpbWVcbiAgICAvLyBBY2NvdW50cy5jb25maWcgaXMgY2FsbGVkLiBXZSBhbHNvIGRlbGliZXJhdGVseSBkb24ndCBzdG9yZSB0aGVcbiAgICAvLyBvYXV0aFNlY3JldEtleSBpbiBBY2NvdW50cy5fb3B0aW9ucy5cbiAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9wdGlvbnMsICdvYXV0aFNlY3JldEtleScpKSB7XG4gICAgICBpZiAoTWV0ZW9yLmlzQ2xpZW50KSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAnVGhlIG9hdXRoU2VjcmV0S2V5IG9wdGlvbiBtYXkgb25seSBiZSBzcGVjaWZpZWQgb24gdGhlIHNlcnZlcidcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIGlmICghUGFja2FnZVsnb2F1dGgtZW5jcnlwdGlvbiddKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAnVGhlIG9hdXRoLWVuY3J5cHRpb24gcGFja2FnZSBtdXN0IGJlIGxvYWRlZCB0byBzZXQgb2F1dGhTZWNyZXRLZXknXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgICBQYWNrYWdlWydvYXV0aC1lbmNyeXB0aW9uJ10uT0F1dGhFbmNyeXB0aW9uLmxvYWRLZXkoXG4gICAgICAgIG9wdGlvbnMub2F1dGhTZWNyZXRLZXlcbiAgICAgICk7XG4gICAgICBvcHRpb25zID0geyAuLi5vcHRpb25zIH07XG4gICAgICBkZWxldGUgb3B0aW9ucy5vYXV0aFNlY3JldEtleTtcbiAgICB9XG5cbiAgICAvLyBWYWxpZGF0ZSBjb25maWcgb3B0aW9ucyBrZXlzXG4gICAgT2JqZWN0LmtleXMob3B0aW9ucykuZm9yRWFjaChrZXkgPT4ge1xuICAgICAgaWYgKCFWQUxJRF9DT05GSUdfS0VZUy5pbmNsdWRlcyhrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBNZXRlb3IuRXJyb3IoYEFjY291bnRzLmNvbmZpZzogSW52YWxpZCBrZXk6ICR7a2V5fWApO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgLy8gc2V0IHZhbHVlcyBpbiBBY2NvdW50cy5fb3B0aW9uc1xuICAgIFZBTElEX0NPTkZJR19LRVlTLmZvckVhY2goa2V5ID0+IHtcbiAgICAgIGlmIChrZXkgaW4gb3B0aW9ucykge1xuICAgICAgICBpZiAoa2V5IGluIHRoaXMuX29wdGlvbnMpIHtcbiAgICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKGBDYW4ndCBzZXQgXFxgJHtrZXl9XFxgIG1vcmUgdGhhbiBvbmNlYCk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fb3B0aW9uc1trZXldID0gb3B0aW9uc1trZXldO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIEBzdW1tYXJ5IFJlZ2lzdGVyIGEgY2FsbGJhY2sgdG8gYmUgY2FsbGVkIGFmdGVyIGEgbG9naW4gYXR0ZW1wdCBzdWNjZWVkcy5cbiAgICogQGxvY3VzIEFueXdoZXJlXG4gICAqIEBwYXJhbSB7RnVuY3Rpb259IGZ1bmMgVGhlIGNhbGxiYWNrIHRvIGJlIGNhbGxlZCB3aGVuIGxvZ2luIGlzIHN1Y2Nlc3NmdWwuXG4gICAqICAgICAgICAgICAgICAgICAgICAgICAgVGhlIGNhbGxiYWNrIHJlY2VpdmVzIGEgc2luZ2xlIG9iamVjdCB0aGF0XG4gICAqICAgICAgICAgICAgICAgICAgICAgICAgaG9sZHMgbG9naW4gZGV0YWlscy4gVGhpcyBvYmplY3QgY29udGFpbnMgdGhlIGxvZ2luXG4gICAqICAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0IHR5cGUgKHBhc3N3b3JkLCByZXN1bWUsIGV0Yy4pIG9uIGJvdGggdGhlXG4gICAqICAgICAgICAgICAgICAgICAgICAgICAgY2xpZW50IGFuZCBzZXJ2ZXIuIGBvbkxvZ2luYCBjYWxsYmFja3MgcmVnaXN0ZXJlZFxuICAgKiAgICAgICAgICAgICAgICAgICAgICAgIG9uIHRoZSBzZXJ2ZXIgYWxzbyByZWNlaXZlIGV4dHJhIGRhdGEsIHN1Y2hcbiAgICogICAgICAgICAgICAgICAgICAgICAgICBhcyB1c2VyIGRldGFpbHMsIGNvbm5lY3Rpb24gaW5mb3JtYXRpb24sIGV0Yy5cbiAgICovXG4gIG9uTG9naW4oZnVuYykge1xuICAgIGxldCByZXQgPSB0aGlzLl9vbkxvZ2luSG9vay5yZWdpc3RlcihmdW5jKTtcbiAgICAvLyBjYWxsIHRoZSBqdXN0IHJlZ2lzdGVyZWQgY2FsbGJhY2sgaWYgYWxyZWFkeSBsb2dnZWQgaW5cbiAgICB0aGlzLl9zdGFydHVwQ2FsbGJhY2socmV0LmNhbGxiYWNrKTtcbiAgICByZXR1cm4gcmV0O1xuICB9XG5cbiAgLyoqXG4gICAqIEBzdW1tYXJ5IFJlZ2lzdGVyIGEgY2FsbGJhY2sgdG8gYmUgY2FsbGVkIGFmdGVyIGEgbG9naW4gYXR0ZW1wdCBmYWlscy5cbiAgICogQGxvY3VzIEFueXdoZXJlXG4gICAqIEBwYXJhbSB7RnVuY3Rpb259IGZ1bmMgVGhlIGNhbGxiYWNrIHRvIGJlIGNhbGxlZCBhZnRlciB0aGUgbG9naW4gaGFzIGZhaWxlZC5cbiAgICovXG4gIG9uTG9naW5GYWlsdXJlKGZ1bmMpIHtcbiAgICByZXR1cm4gdGhpcy5fb25Mb2dpbkZhaWx1cmVIb29rLnJlZ2lzdGVyKGZ1bmMpO1xuICB9XG5cbiAgLyoqXG4gICAqIEBzdW1tYXJ5IFJlZ2lzdGVyIGEgY2FsbGJhY2sgdG8gYmUgY2FsbGVkIGFmdGVyIGEgbG9nb3V0IGF0dGVtcHQgc3VjY2VlZHMuXG4gICAqIEBsb2N1cyBBbnl3aGVyZVxuICAgKiBAcGFyYW0ge0Z1bmN0aW9ufSBmdW5jIFRoZSBjYWxsYmFjayB0byBiZSBjYWxsZWQgd2hlbiBsb2dvdXQgaXMgc3VjY2Vzc2Z1bC5cbiAgICovXG4gIG9uTG9nb3V0KGZ1bmMpIHtcbiAgICByZXR1cm4gdGhpcy5fb25Mb2dvdXRIb29rLnJlZ2lzdGVyKGZ1bmMpO1xuICB9XG5cbiAgX2luaXRDb25uZWN0aW9uKG9wdGlvbnMpIHtcbiAgICBpZiAoIU1ldGVvci5pc0NsaWVudCkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIFRoZSBjb25uZWN0aW9uIHVzZWQgYnkgdGhlIEFjY291bnRzIHN5c3RlbS4gVGhpcyBpcyB0aGUgY29ubmVjdGlvblxuICAgIC8vIHRoYXQgd2lsbCBnZXQgbG9nZ2VkIGluIGJ5IE1ldGVvci5sb2dpbigpLCBhbmQgdGhpcyBpcyB0aGVcbiAgICAvLyBjb25uZWN0aW9uIHdob3NlIGxvZ2luIHN0YXRlIHdpbGwgYmUgcmVmbGVjdGVkIGJ5IE1ldGVvci51c2VySWQoKS5cbiAgICAvL1xuICAgIC8vIEl0IHdvdWxkIGJlIG11Y2ggcHJlZmVyYWJsZSBmb3IgdGhpcyB0byBiZSBpbiBhY2NvdW50c19jbGllbnQuanMsXG4gICAgLy8gYnV0IGl0IGhhcyB0byBiZSBoZXJlIGJlY2F1c2UgaXQncyBuZWVkZWQgdG8gY3JlYXRlIHRoZVxuICAgIC8vIE1ldGVvci51c2VycyBjb2xsZWN0aW9uLlxuICAgIGlmIChvcHRpb25zLmNvbm5lY3Rpb24pIHtcbiAgICAgIHRoaXMuY29ubmVjdGlvbiA9IG9wdGlvbnMuY29ubmVjdGlvbjtcbiAgICB9IGVsc2UgaWYgKG9wdGlvbnMuZGRwVXJsKSB7XG4gICAgICB0aGlzLmNvbm5lY3Rpb24gPSBERFAuY29ubmVjdChvcHRpb25zLmRkcFVybCk7XG4gICAgfSBlbHNlIGlmIChcbiAgICAgIHR5cGVvZiBfX21ldGVvcl9ydW50aW1lX2NvbmZpZ19fICE9PSAndW5kZWZpbmVkJyAmJlxuICAgICAgX19tZXRlb3JfcnVudGltZV9jb25maWdfXy5BQ0NPVU5UU19DT05ORUNUSU9OX1VSTFxuICAgICkge1xuICAgICAgLy8gVGVtcG9yYXJ5LCBpbnRlcm5hbCBob29rIHRvIGFsbG93IHRoZSBzZXJ2ZXIgdG8gcG9pbnQgdGhlIGNsaWVudFxuICAgICAgLy8gdG8gYSBkaWZmZXJlbnQgYXV0aGVudGljYXRpb24gc2VydmVyLiBUaGlzIGlzIGZvciBhIHZlcnlcbiAgICAgIC8vIHBhcnRpY3VsYXIgdXNlIGNhc2UgdGhhdCBjb21lcyB1cCB3aGVuIGltcGxlbWVudGluZyBhIG9hdXRoXG4gICAgICAvLyBzZXJ2ZXIuIFVuc3VwcG9ydGVkIGFuZCBtYXkgZ28gYXdheSBhdCBhbnkgcG9pbnQgaW4gdGltZS5cbiAgICAgIC8vXG4gICAgICAvLyBXZSB3aWxsIGV2ZW50dWFsbHkgcHJvdmlkZSBhIGdlbmVyYWwgd2F5IHRvIHVzZSBhY2NvdW50LWJhc2VcbiAgICAgIC8vIGFnYWluc3QgYW55IEREUCBjb25uZWN0aW9uLCBub3QganVzdCBvbmUgc3BlY2lhbCBvbmUuXG4gICAgICB0aGlzLmNvbm5lY3Rpb24gPSBERFAuY29ubmVjdChcbiAgICAgICAgX19tZXRlb3JfcnVudGltZV9jb25maWdfXy5BQ0NPVU5UU19DT05ORUNUSU9OX1VSTFxuICAgICAgKTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5jb25uZWN0aW9uID0gTWV0ZW9yLmNvbm5lY3Rpb247XG4gICAgfVxuICB9XG5cbiAgX2dldFRva2VuTGlmZXRpbWVNcygpIHtcbiAgICAvLyBXaGVuIGxvZ2luRXhwaXJhdGlvbkluRGF5cyBpcyBzZXQgdG8gbnVsbCwgd2UnbGwgdXNlIGEgcmVhbGx5IGhpZ2hcbiAgICAvLyBudW1iZXIgb2YgZGF5cyAoTE9HSU5fVU5FWFBJUkFCTEVfVE9LRU5fREFZUykgdG8gc2ltdWxhdGUgYW5cbiAgICAvLyB1bmV4cGlyaW5nIHRva2VuLlxuICAgIGNvbnN0IGxvZ2luRXhwaXJhdGlvbkluRGF5cyA9XG4gICAgICB0aGlzLl9vcHRpb25zLmxvZ2luRXhwaXJhdGlvbkluRGF5cyA9PT0gbnVsbFxuICAgICAgICA/IExPR0lOX1VORVhQSVJJTkdfVE9LRU5fREFZU1xuICAgICAgICA6IHRoaXMuX29wdGlvbnMubG9naW5FeHBpcmF0aW9uSW5EYXlzO1xuICAgIHJldHVybiAoXG4gICAgICB0aGlzLl9vcHRpb25zLmxvZ2luRXhwaXJhdGlvbiB8fFxuICAgICAgKGxvZ2luRXhwaXJhdGlvbkluRGF5cyB8fCBERUZBVUxUX0xPR0lOX0VYUElSQVRJT05fREFZUykgKiA4NjQwMDAwMFxuICAgICk7XG4gIH1cblxuICBfZ2V0UGFzc3dvcmRSZXNldFRva2VuTGlmZXRpbWVNcygpIHtcbiAgICByZXR1cm4gKFxuICAgICAgdGhpcy5fb3B0aW9ucy5wYXNzd29yZFJlc2V0VG9rZW5FeHBpcmF0aW9uIHx8XG4gICAgICAodGhpcy5fb3B0aW9ucy5wYXNzd29yZFJlc2V0VG9rZW5FeHBpcmF0aW9uSW5EYXlzIHx8XG4gICAgICAgIERFRkFVTFRfUEFTU1dPUkRfUkVTRVRfVE9LRU5fRVhQSVJBVElPTl9EQVlTKSAqIDg2NDAwMDAwXG4gICAgKTtcbiAgfVxuXG4gIF9nZXRQYXNzd29yZEVucm9sbFRva2VuTGlmZXRpbWVNcygpIHtcbiAgICByZXR1cm4gKFxuICAgICAgdGhpcy5fb3B0aW9ucy5wYXNzd29yZEVucm9sbFRva2VuRXhwaXJhdGlvbiB8fFxuICAgICAgKHRoaXMuX29wdGlvbnMucGFzc3dvcmRFbnJvbGxUb2tlbkV4cGlyYXRpb25JbkRheXMgfHxcbiAgICAgICAgREVGQVVMVF9QQVNTV09SRF9FTlJPTExfVE9LRU5fRVhQSVJBVElPTl9EQVlTKSAqIDg2NDAwMDAwXG4gICAgKTtcbiAgfVxuXG4gIF90b2tlbkV4cGlyYXRpb24od2hlbikge1xuICAgIC8vIFdlIHBhc3Mgd2hlbiB0aHJvdWdoIHRoZSBEYXRlIGNvbnN0cnVjdG9yIGZvciBiYWNrd2FyZHMgY29tcGF0aWJpbGl0eTtcbiAgICAvLyBgd2hlbmAgdXNlZCB0byBiZSBhIG51bWJlci5cbiAgICByZXR1cm4gbmV3IERhdGUobmV3IERhdGUod2hlbikuZ2V0VGltZSgpICsgdGhpcy5fZ2V0VG9rZW5MaWZldGltZU1zKCkpO1xuICB9XG5cbiAgX3Rva2VuRXhwaXJlc1Nvb24od2hlbikge1xuICAgIGxldCBtaW5MaWZldGltZU1zID0gMC4xICogdGhpcy5fZ2V0VG9rZW5MaWZldGltZU1zKCk7XG4gICAgY29uc3QgbWluTGlmZXRpbWVDYXBNcyA9IE1JTl9UT0tFTl9MSUZFVElNRV9DQVBfU0VDUyAqIDEwMDA7XG4gICAgaWYgKG1pbkxpZmV0aW1lTXMgPiBtaW5MaWZldGltZUNhcE1zKSB7XG4gICAgICBtaW5MaWZldGltZU1zID0gbWluTGlmZXRpbWVDYXBNcztcbiAgICB9XG4gICAgcmV0dXJuIG5ldyBEYXRlKCkgPiBuZXcgRGF0ZSh3aGVuKSAtIG1pbkxpZmV0aW1lTXM7XG4gIH1cblxuICAvLyBOby1vcCBvbiB0aGUgc2VydmVyLCBvdmVycmlkZGVuIG9uIHRoZSBjbGllbnQuXG4gIF9zdGFydHVwQ2FsbGJhY2soY2FsbGJhY2spIHt9XG59XG5cbi8vIE5vdGUgdGhhdCBBY2NvdW50cyBpcyBkZWZpbmVkIHNlcGFyYXRlbHkgaW4gYWNjb3VudHNfY2xpZW50LmpzIGFuZFxuLy8gYWNjb3VudHNfc2VydmVyLmpzLlxuXG4vKipcbiAqIEBzdW1tYXJ5IEdldCB0aGUgY3VycmVudCB1c2VyIGlkLCBvciBgbnVsbGAgaWYgbm8gdXNlciBpcyBsb2dnZWQgaW4uIEEgcmVhY3RpdmUgZGF0YSBzb3VyY2UuXG4gKiBAbG9jdXMgQW55d2hlcmUgYnV0IHB1Ymxpc2ggZnVuY3Rpb25zXG4gKiBAaW1wb3J0RnJvbVBhY2thZ2UgbWV0ZW9yXG4gKi9cbk1ldGVvci51c2VySWQgPSAoKSA9PiBBY2NvdW50cy51c2VySWQoKTtcblxuLyoqXG4gKiBAc3VtbWFyeSBHZXQgdGhlIGN1cnJlbnQgdXNlciByZWNvcmQsIG9yIGBudWxsYCBpZiBubyB1c2VyIGlzIGxvZ2dlZCBpbi4gQSByZWFjdGl2ZSBkYXRhIHNvdXJjZS5cbiAqIEBsb2N1cyBBbnl3aGVyZSBidXQgcHVibGlzaCBmdW5jdGlvbnNcbiAqIEBpbXBvcnRGcm9tUGFja2FnZSBtZXRlb3JcbiAqIEBwYXJhbSB7T2JqZWN0fSBbb3B0aW9uc11cbiAqIEBwYXJhbSB7TW9uZ29GaWVsZFNwZWNpZmllcn0gb3B0aW9ucy5maWVsZHMgRGljdGlvbmFyeSBvZiBmaWVsZHMgdG8gcmV0dXJuIG9yIGV4Y2x1ZGUuXG4gKi9cbk1ldGVvci51c2VyID0gb3B0aW9ucyA9PiBBY2NvdW50cy51c2VyKG9wdGlvbnMpO1xuXG4vLyBob3cgbG9uZyAoaW4gZGF5cykgdW50aWwgYSBsb2dpbiB0b2tlbiBleHBpcmVzXG5jb25zdCBERUZBVUxUX0xPR0lOX0VYUElSQVRJT05fREFZUyA9IDkwO1xuLy8gaG93IGxvbmcgKGluIGRheXMpIHVudGlsIHJlc2V0IHBhc3N3b3JkIHRva2VuIGV4cGlyZXNcbmNvbnN0IERFRkFVTFRfUEFTU1dPUkRfUkVTRVRfVE9LRU5fRVhQSVJBVElPTl9EQVlTID0gMztcbi8vIGhvdyBsb25nIChpbiBkYXlzKSB1bnRpbCBlbnJvbCBwYXNzd29yZCB0b2tlbiBleHBpcmVzXG5jb25zdCBERUZBVUxUX1BBU1NXT1JEX0VOUk9MTF9UT0tFTl9FWFBJUkFUSU9OX0RBWVMgPSAzMDtcbi8vIENsaWVudHMgZG9uJ3QgdHJ5IHRvIGF1dG8tbG9naW4gd2l0aCBhIHRva2VuIHRoYXQgaXMgZ29pbmcgdG8gZXhwaXJlIHdpdGhpblxuLy8gLjEgKiBERUZBVUxUX0xPR0lOX0VYUElSQVRJT05fREFZUywgY2FwcGVkIGF0IE1JTl9UT0tFTl9MSUZFVElNRV9DQVBfU0VDUy5cbi8vIFRyaWVzIHRvIGF2b2lkIGFicnVwdCBkaXNjb25uZWN0cyBmcm9tIGV4cGlyaW5nIHRva2Vucy5cbmNvbnN0IE1JTl9UT0tFTl9MSUZFVElNRV9DQVBfU0VDUyA9IDM2MDA7IC8vIG9uZSBob3VyXG4vLyBob3cgb2Z0ZW4gKGluIG1pbGxpc2Vjb25kcykgd2UgY2hlY2sgZm9yIGV4cGlyZWQgdG9rZW5zXG5leHBvcnQgY29uc3QgRVhQSVJFX1RPS0VOU19JTlRFUlZBTF9NUyA9IDYwMCAqIDEwMDA7IC8vIDEwIG1pbnV0ZXNcbi8vIGhvdyBsb25nIHdlIHdhaXQgYmVmb3JlIGxvZ2dpbmcgb3V0IGNsaWVudHMgd2hlbiBNZXRlb3IubG9nb3V0T3RoZXJDbGllbnRzIGlzXG4vLyBjYWxsZWRcbmV4cG9ydCBjb25zdCBDT05ORUNUSU9OX0NMT1NFX0RFTEFZX01TID0gMTAgKiAxMDAwO1xuLy8gQSBsYXJnZSBudW1iZXIgb2YgZXhwaXJhdGlvbiBkYXlzIChhcHByb3hpbWF0ZWx5IDEwMCB5ZWFycyB3b3J0aCkgdGhhdCBpc1xuLy8gdXNlZCB3aGVuIGNyZWF0aW5nIHVuZXhwaXJpbmcgdG9rZW5zLlxuY29uc3QgTE9HSU5fVU5FWFBJUklOR19UT0tFTl9EQVlTID0gMzY1ICogMTAwO1xuIiwiaW1wb3J0IGNyeXB0byBmcm9tICdjcnlwdG8nO1xuaW1wb3J0IHtcbiAgQWNjb3VudHNDb21tb24sXG4gIEVYUElSRV9UT0tFTlNfSU5URVJWQUxfTVMsXG59IGZyb20gJy4vYWNjb3VudHNfY29tbW9uLmpzJztcbmltcG9ydCB7IFVSTCB9IGZyb20gJ21ldGVvci91cmwnO1xuXG5jb25zdCBoYXNPd24gPSBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5O1xuXG4vLyBYWFggbWF5YmUgdGhpcyBiZWxvbmdzIGluIHRoZSBjaGVjayBwYWNrYWdlXG5jb25zdCBOb25FbXB0eVN0cmluZyA9IE1hdGNoLldoZXJlKHggPT4ge1xuICBjaGVjayh4LCBTdHJpbmcpO1xuICByZXR1cm4geC5sZW5ndGggPiAwO1xufSk7XG5cbi8qKlxuICogQHN1bW1hcnkgQ29uc3RydWN0b3IgZm9yIHRoZSBgQWNjb3VudHNgIG5hbWVzcGFjZSBvbiB0aGUgc2VydmVyLlxuICogQGxvY3VzIFNlcnZlclxuICogQGNsYXNzIEFjY291bnRzU2VydmVyXG4gKiBAZXh0ZW5kcyBBY2NvdW50c0NvbW1vblxuICogQGluc3RhbmNlbmFtZSBhY2NvdW50c1NlcnZlclxuICogQHBhcmFtIHtPYmplY3R9IHNlcnZlciBBIHNlcnZlciBvYmplY3Qgc3VjaCBhcyBgTWV0ZW9yLnNlcnZlcmAuXG4gKi9cbmV4cG9ydCBjbGFzcyBBY2NvdW50c1NlcnZlciBleHRlbmRzIEFjY291bnRzQ29tbW9uIHtcbiAgLy8gTm90ZSB0aGF0IHRoaXMgY29uc3RydWN0b3IgaXMgbGVzcyBsaWtlbHkgdG8gYmUgaW5zdGFudGlhdGVkIG11bHRpcGxlXG4gIC8vIHRpbWVzIHRoYW4gdGhlIGBBY2NvdW50c0NsaWVudGAgY29uc3RydWN0b3IsIGJlY2F1c2UgYSBzaW5nbGUgc2VydmVyXG4gIC8vIGNhbiBwcm92aWRlIG9ubHkgb25lIHNldCBvZiBtZXRob2RzLlxuICBjb25zdHJ1Y3RvcihzZXJ2ZXIpIHtcbiAgICBzdXBlcigpO1xuXG4gICAgdGhpcy5fc2VydmVyID0gc2VydmVyIHx8IE1ldGVvci5zZXJ2ZXI7XG4gICAgLy8gU2V0IHVwIHRoZSBzZXJ2ZXIncyBtZXRob2RzLCBhcyBpZiBieSBjYWxsaW5nIE1ldGVvci5tZXRob2RzLlxuICAgIHRoaXMuX2luaXRTZXJ2ZXJNZXRob2RzKCk7XG5cbiAgICB0aGlzLl9pbml0QWNjb3VudERhdGFIb29rcygpO1xuXG4gICAgLy8gSWYgYXV0b3B1Ymxpc2ggaXMgb24sIHB1Ymxpc2ggdGhlc2UgdXNlciBmaWVsZHMuIExvZ2luIHNlcnZpY2VcbiAgICAvLyBwYWNrYWdlcyAoZWcgYWNjb3VudHMtZ29vZ2xlKSBhZGQgdG8gdGhlc2UgYnkgY2FsbGluZ1xuICAgIC8vIGFkZEF1dG9wdWJsaXNoRmllbGRzLiAgTm90YWJseSwgdGhpcyBpc24ndCBpbXBsZW1lbnRlZCB3aXRoIG11bHRpcGxlXG4gICAgLy8gcHVibGlzaGVzIHNpbmNlIEREUCBvbmx5IG1lcmdlcyBvbmx5IGFjcm9zcyB0b3AtbGV2ZWwgZmllbGRzLCBub3RcbiAgICAvLyBzdWJmaWVsZHMgKHN1Y2ggYXMgJ3NlcnZpY2VzLmZhY2Vib29rLmFjY2Vzc1Rva2VuJylcbiAgICB0aGlzLl9hdXRvcHVibGlzaEZpZWxkcyA9IHtcbiAgICAgIGxvZ2dlZEluVXNlcjogWydwcm9maWxlJywgJ3VzZXJuYW1lJywgJ2VtYWlscyddLFxuICAgICAgb3RoZXJVc2VyczogWydwcm9maWxlJywgJ3VzZXJuYW1lJ11cbiAgICB9O1xuXG4gICAgLy8gdXNlIG9iamVjdCB0byBrZWVwIHRoZSByZWZlcmVuY2Ugd2hlbiB1c2VkIGluIGZ1bmN0aW9uc1xuICAgIC8vIHdoZXJlIF9kZWZhdWx0UHVibGlzaEZpZWxkcyBpcyBkZXN0cnVjdHVyZWQgaW50byBsZXhpY2FsIHNjb3BlXG4gICAgLy8gZm9yIHB1Ymxpc2ggY2FsbGJhY2tzIHRoYXQgbmVlZCBgdGhpc2BcbiAgICB0aGlzLl9kZWZhdWx0UHVibGlzaEZpZWxkcyA9IHtcbiAgICAgIHByb2plY3Rpb246IHtcbiAgICAgICAgcHJvZmlsZTogMSxcbiAgICAgICAgdXNlcm5hbWU6IDEsXG4gICAgICAgIGVtYWlsczogMSxcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgdGhpcy5faW5pdFNlcnZlclB1YmxpY2F0aW9ucygpO1xuXG4gICAgLy8gY29ubmVjdGlvbklkIC0+IHtjb25uZWN0aW9uLCBsb2dpblRva2VufVxuICAgIHRoaXMuX2FjY291bnREYXRhID0ge307XG5cbiAgICAvLyBjb25uZWN0aW9uIGlkIC0+IG9ic2VydmUgaGFuZGxlIGZvciB0aGUgbG9naW4gdG9rZW4gdGhhdCB0aGlzIGNvbm5lY3Rpb24gaXNcbiAgICAvLyBjdXJyZW50bHkgYXNzb2NpYXRlZCB3aXRoLCBvciBhIG51bWJlci4gVGhlIG51bWJlciBpbmRpY2F0ZXMgdGhhdCB3ZSBhcmUgaW5cbiAgICAvLyB0aGUgcHJvY2VzcyBvZiBzZXR0aW5nIHVwIHRoZSBvYnNlcnZlICh1c2luZyBhIG51bWJlciBpbnN0ZWFkIG9mIGEgc2luZ2xlXG4gICAgLy8gc2VudGluZWwgYWxsb3dzIG11bHRpcGxlIGF0dGVtcHRzIHRvIHNldCB1cCB0aGUgb2JzZXJ2ZSB0byBpZGVudGlmeSB3aGljaFxuICAgIC8vIG9uZSB3YXMgdGhlaXJzKS5cbiAgICB0aGlzLl91c2VyT2JzZXJ2ZXNGb3JDb25uZWN0aW9ucyA9IHt9O1xuICAgIHRoaXMuX25leHRVc2VyT2JzZXJ2ZU51bWJlciA9IDE7ICAvLyBmb3IgdGhlIG51bWJlciBkZXNjcmliZWQgYWJvdmUuXG5cbiAgICAvLyBsaXN0IG9mIGFsbCByZWdpc3RlcmVkIGhhbmRsZXJzLlxuICAgIHRoaXMuX2xvZ2luSGFuZGxlcnMgPSBbXTtcblxuICAgIHNldHVwVXNlcnNDb2xsZWN0aW9uKHRoaXMudXNlcnMpO1xuICAgIHNldHVwRGVmYXVsdExvZ2luSGFuZGxlcnModGhpcyk7XG4gICAgc2V0RXhwaXJlVG9rZW5zSW50ZXJ2YWwodGhpcyk7XG5cbiAgICB0aGlzLl92YWxpZGF0ZUxvZ2luSG9vayA9IG5ldyBIb29rKHsgYmluZEVudmlyb25tZW50OiBmYWxzZSB9KTtcbiAgICB0aGlzLl92YWxpZGF0ZU5ld1VzZXJIb29rcyA9IFtcbiAgICAgIGRlZmF1bHRWYWxpZGF0ZU5ld1VzZXJIb29rLmJpbmQodGhpcylcbiAgICBdO1xuXG4gICAgdGhpcy5fZGVsZXRlU2F2ZWRUb2tlbnNGb3JBbGxVc2Vyc09uU3RhcnR1cCgpO1xuXG4gICAgdGhpcy5fc2tpcENhc2VJbnNlbnNpdGl2ZUNoZWNrc0ZvclRlc3QgPSB7fTtcblxuICAgIHRoaXMudXJscyA9IHtcbiAgICAgIHJlc2V0UGFzc3dvcmQ6ICh0b2tlbiwgZXh0cmFQYXJhbXMpID0+IHRoaXMuYnVpbGRFbWFpbFVybChgIy9yZXNldC1wYXNzd29yZC8ke3Rva2VufWAsIGV4dHJhUGFyYW1zKSxcbiAgICAgIHZlcmlmeUVtYWlsOiAodG9rZW4sIGV4dHJhUGFyYW1zKSA9PiB0aGlzLmJ1aWxkRW1haWxVcmwoYCMvdmVyaWZ5LWVtYWlsLyR7dG9rZW59YCwgZXh0cmFQYXJhbXMpLFxuICAgICAgbG9naW5Ub2tlbjogKHNlbGVjdG9yLCB0b2tlbiwgZXh0cmFQYXJhbXMpID0+XG4gICAgICAgIHRoaXMuYnVpbGRFbWFpbFVybChgLz9sb2dpblRva2VuPSR7dG9rZW59JnNlbGVjdG9yPSR7c2VsZWN0b3J9YCwgZXh0cmFQYXJhbXMpLFxuICAgICAgZW5yb2xsQWNjb3VudDogKHRva2VuLCBleHRyYVBhcmFtcykgPT4gdGhpcy5idWlsZEVtYWlsVXJsKGAjL2Vucm9sbC1hY2NvdW50LyR7dG9rZW59YCwgZXh0cmFQYXJhbXMpLFxuICAgIH07XG5cbiAgICB0aGlzLmFkZERlZmF1bHRSYXRlTGltaXQoKTtcblxuICAgIHRoaXMuYnVpbGRFbWFpbFVybCA9IChwYXRoLCBleHRyYVBhcmFtcyA9IHt9KSA9PiB7XG4gICAgICBjb25zdCB1cmwgPSBuZXcgVVJMKE1ldGVvci5hYnNvbHV0ZVVybChwYXRoKSk7XG4gICAgICBjb25zdCBwYXJhbXMgPSBPYmplY3QuZW50cmllcyhleHRyYVBhcmFtcyk7XG4gICAgICBpZiAocGFyYW1zLmxlbmd0aCA+IDApIHtcbiAgICAgICAgLy8gQWRkIGFkZGl0aW9uYWwgcGFyYW1ldGVycyB0byB0aGUgdXJsXG4gICAgICAgIGZvciAoY29uc3QgW2tleSwgdmFsdWVdIG9mIHBhcmFtcykge1xuICAgICAgICAgIHVybC5zZWFyY2hQYXJhbXMuYXBwZW5kKGtleSwgdmFsdWUpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgICByZXR1cm4gdXJsLnRvU3RyaW5nKCk7XG4gICAgfTtcbiAgfVxuXG4gIC8vL1xuICAvLy8gQ1VSUkVOVCBVU0VSXG4gIC8vL1xuXG4gIC8vIEBvdmVycmlkZSBvZiBcImFic3RyYWN0XCIgbm9uLWltcGxlbWVudGF0aW9uIGluIGFjY291bnRzX2NvbW1vbi5qc1xuICB1c2VySWQoKSB7XG4gICAgLy8gVGhpcyBmdW5jdGlvbiBvbmx5IHdvcmtzIGlmIGNhbGxlZCBpbnNpZGUgYSBtZXRob2Qgb3IgYSBwdWJpY2F0aW9uLlxuICAgIC8vIFVzaW5nIGFueSBvZiB0aGUgaW5mb3JtYXRpb24gZnJvbSBNZXRlb3IudXNlcigpIGluIGEgbWV0aG9kIG9yXG4gICAgLy8gcHVibGlzaCBmdW5jdGlvbiB3aWxsIGFsd2F5cyB1c2UgdGhlIHZhbHVlIGZyb20gd2hlbiB0aGUgZnVuY3Rpb24gZmlyc3RcbiAgICAvLyBydW5zLiBUaGlzIGlzIGxpa2VseSBub3Qgd2hhdCB0aGUgdXNlciBleHBlY3RzLiBUaGUgd2F5IHRvIG1ha2UgdGhpcyB3b3JrXG4gICAgLy8gaW4gYSBtZXRob2Qgb3IgcHVibGlzaCBmdW5jdGlvbiBpcyB0byBkbyBNZXRlb3IuZmluZCh0aGlzLnVzZXJJZCkub2JzZXJ2ZVxuICAgIC8vIGFuZCByZWNvbXB1dGUgd2hlbiB0aGUgdXNlciByZWNvcmQgY2hhbmdlcy5cbiAgICBjb25zdCBjdXJyZW50SW52b2NhdGlvbiA9IEREUC5fQ3VycmVudE1ldGhvZEludm9jYXRpb24uZ2V0KCkgfHwgRERQLl9DdXJyZW50UHVibGljYXRpb25JbnZvY2F0aW9uLmdldCgpO1xuICAgIGlmICghY3VycmVudEludm9jYXRpb24pXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJNZXRlb3IudXNlcklkIGNhbiBvbmx5IGJlIGludm9rZWQgaW4gbWV0aG9kIGNhbGxzIG9yIHB1YmxpY2F0aW9ucy5cIik7XG4gICAgcmV0dXJuIGN1cnJlbnRJbnZvY2F0aW9uLnVzZXJJZDtcbiAgfVxuXG4gIC8vL1xuICAvLy8gTE9HSU4gSE9PS1NcbiAgLy8vXG5cbiAgLyoqXG4gICAqIEBzdW1tYXJ5IFZhbGlkYXRlIGxvZ2luIGF0dGVtcHRzLlxuICAgKiBAbG9jdXMgU2VydmVyXG4gICAqIEBwYXJhbSB7RnVuY3Rpb259IGZ1bmMgQ2FsbGVkIHdoZW5ldmVyIGEgbG9naW4gaXMgYXR0ZW1wdGVkIChlaXRoZXIgc3VjY2Vzc2Z1bCBvciB1bnN1Y2Nlc3NmdWwpLiAgQSBsb2dpbiBjYW4gYmUgYWJvcnRlZCBieSByZXR1cm5pbmcgYSBmYWxzeSB2YWx1ZSBvciB0aHJvd2luZyBhbiBleGNlcHRpb24uXG4gICAqL1xuICB2YWxpZGF0ZUxvZ2luQXR0ZW1wdChmdW5jKSB7XG4gICAgLy8gRXhjZXB0aW9ucyBpbnNpZGUgdGhlIGhvb2sgY2FsbGJhY2sgYXJlIHBhc3NlZCB1cCB0byB1cy5cbiAgICByZXR1cm4gdGhpcy5fdmFsaWRhdGVMb2dpbkhvb2sucmVnaXN0ZXIoZnVuYyk7XG4gIH1cblxuICAvKipcbiAgICogQHN1bW1hcnkgU2V0IHJlc3RyaWN0aW9ucyBvbiBuZXcgdXNlciBjcmVhdGlvbi5cbiAgICogQGxvY3VzIFNlcnZlclxuICAgKiBAcGFyYW0ge0Z1bmN0aW9ufSBmdW5jIENhbGxlZCB3aGVuZXZlciBhIG5ldyB1c2VyIGlzIGNyZWF0ZWQuIFRha2VzIHRoZSBuZXcgdXNlciBvYmplY3QsIGFuZCByZXR1cm5zIHRydWUgdG8gYWxsb3cgdGhlIGNyZWF0aW9uIG9yIGZhbHNlIHRvIGFib3J0LlxuICAgKi9cbiAgdmFsaWRhdGVOZXdVc2VyKGZ1bmMpIHtcbiAgICB0aGlzLl92YWxpZGF0ZU5ld1VzZXJIb29rcy5wdXNoKGZ1bmMpO1xuICB9XG5cbiAgLyoqXG4gICAqIEBzdW1tYXJ5IFZhbGlkYXRlIGxvZ2luIGZyb20gZXh0ZXJuYWwgc2VydmljZVxuICAgKiBAbG9jdXMgU2VydmVyXG4gICAqIEBwYXJhbSB7RnVuY3Rpb259IGZ1bmMgQ2FsbGVkIHdoZW5ldmVyIGxvZ2luL3VzZXIgY3JlYXRpb24gZnJvbSBleHRlcm5hbCBzZXJ2aWNlIGlzIGF0dGVtcHRlZC4gTG9naW4gb3IgdXNlciBjcmVhdGlvbiBiYXNlZCBvbiB0aGlzIGxvZ2luIGNhbiBiZSBhYm9ydGVkIGJ5IHBhc3NpbmcgYSBmYWxzeSB2YWx1ZSBvciB0aHJvd2luZyBhbiBleGNlcHRpb24uXG4gICAqL1xuICBiZWZvcmVFeHRlcm5hbExvZ2luKGZ1bmMpIHtcbiAgICBpZiAodGhpcy5fYmVmb3JlRXh0ZXJuYWxMb2dpbkhvb2spIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIkNhbiBvbmx5IGNhbGwgYmVmb3JlRXh0ZXJuYWxMb2dpbiBvbmNlXCIpO1xuICAgIH1cblxuICAgIHRoaXMuX2JlZm9yZUV4dGVybmFsTG9naW5Ib29rID0gZnVuYztcbiAgfVxuXG4gIC8vL1xuICAvLy8gQ1JFQVRFIFVTRVIgSE9PS1NcbiAgLy8vXG5cbiAgLyoqXG4gICAqIEBzdW1tYXJ5IEN1c3RvbWl6ZSBsb2dpbiB0b2tlbiBjcmVhdGlvbi5cbiAgICogQGxvY3VzIFNlcnZlclxuICAgKiBAcGFyYW0ge0Z1bmN0aW9ufSBmdW5jIENhbGxlZCB3aGVuZXZlciBhIG5ldyB0b2tlbiBpcyBjcmVhdGVkLlxuICAgKiBSZXR1cm4gdGhlIHNlcXVlbmNlIGFuZCB0aGUgdXNlciBvYmplY3QuIFJldHVybiB0cnVlIHRvIGtlZXAgc2VuZGluZyB0aGUgZGVmYXVsdCBlbWFpbCwgb3IgZmFsc2UgdG8gb3ZlcnJpZGUgdGhlIGJlaGF2aW9yLlxuICAgKi9cbiAgb25DcmVhdGVMb2dpblRva2VuID0gZnVuY3Rpb24oZnVuYykge1xuICAgIGlmICh0aGlzLl9vbkNyZWF0ZUxvZ2luVG9rZW5Ib29rKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0NhbiBvbmx5IGNhbGwgb25DcmVhdGVMb2dpblRva2VuIG9uY2UnKTtcbiAgICB9XG5cbiAgICB0aGlzLl9vbkNyZWF0ZUxvZ2luVG9rZW5Ib29rID0gZnVuYztcbiAgfTtcblxuICAvKipcbiAgICogQHN1bW1hcnkgQ3VzdG9taXplIG5ldyB1c2VyIGNyZWF0aW9uLlxuICAgKiBAbG9jdXMgU2VydmVyXG4gICAqIEBwYXJhbSB7RnVuY3Rpb259IGZ1bmMgQ2FsbGVkIHdoZW5ldmVyIGEgbmV3IHVzZXIgaXMgY3JlYXRlZC4gUmV0dXJuIHRoZSBuZXcgdXNlciBvYmplY3QsIG9yIHRocm93IGFuIGBFcnJvcmAgdG8gYWJvcnQgdGhlIGNyZWF0aW9uLlxuICAgKi9cbiAgb25DcmVhdGVVc2VyKGZ1bmMpIHtcbiAgICBpZiAodGhpcy5fb25DcmVhdGVVc2VySG9vaykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwiQ2FuIG9ubHkgY2FsbCBvbkNyZWF0ZVVzZXIgb25jZVwiKTtcbiAgICB9XG5cbiAgICB0aGlzLl9vbkNyZWF0ZVVzZXJIb29rID0gZnVuYztcbiAgfVxuXG4gIC8qKlxuICAgKiBAc3VtbWFyeSBDdXN0b21pemUgb2F1dGggdXNlciBwcm9maWxlIHVwZGF0ZXNcbiAgICogQGxvY3VzIFNlcnZlclxuICAgKiBAcGFyYW0ge0Z1bmN0aW9ufSBmdW5jIENhbGxlZCB3aGVuZXZlciBhIHVzZXIgaXMgbG9nZ2VkIGluIHZpYSBvYXV0aC4gUmV0dXJuIHRoZSBwcm9maWxlIG9iamVjdCB0byBiZSBtZXJnZWQsIG9yIHRocm93IGFuIGBFcnJvcmAgdG8gYWJvcnQgdGhlIGNyZWF0aW9uLlxuICAgKi9cbiAgb25FeHRlcm5hbExvZ2luKGZ1bmMpIHtcbiAgICBpZiAodGhpcy5fb25FeHRlcm5hbExvZ2luSG9vaykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwiQ2FuIG9ubHkgY2FsbCBvbkV4dGVybmFsTG9naW4gb25jZVwiKTtcbiAgICB9XG5cbiAgICB0aGlzLl9vbkV4dGVybmFsTG9naW5Ib29rID0gZnVuYztcbiAgfVxuXG4gIC8qKlxuICAgKiBAc3VtbWFyeSBDdXN0b21pemUgdXNlciBzZWxlY3Rpb24gb24gZXh0ZXJuYWwgbG9naW5zXG4gICAqIEBsb2N1cyBTZXJ2ZXJcbiAgICogQHBhcmFtIHtGdW5jdGlvbn0gZnVuYyBDYWxsZWQgd2hlbmV2ZXIgYSB1c2VyIGlzIGxvZ2dlZCBpbiB2aWEgb2F1dGggYW5kIGFcbiAgICogdXNlciBpcyBub3QgZm91bmQgd2l0aCB0aGUgc2VydmljZSBpZC4gUmV0dXJuIHRoZSB1c2VyIG9yIHVuZGVmaW5lZC5cbiAgICovXG4gIHNldEFkZGl0aW9uYWxGaW5kVXNlck9uRXh0ZXJuYWxMb2dpbihmdW5jKSB7XG4gICAgaWYgKHRoaXMuX2FkZGl0aW9uYWxGaW5kVXNlck9uRXh0ZXJuYWxMb2dpbikge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwiQ2FuIG9ubHkgY2FsbCBzZXRBZGRpdGlvbmFsRmluZFVzZXJPbkV4dGVybmFsTG9naW4gb25jZVwiKTtcbiAgICB9XG4gICAgdGhpcy5fYWRkaXRpb25hbEZpbmRVc2VyT25FeHRlcm5hbExvZ2luID0gZnVuYztcbiAgfVxuXG4gIF92YWxpZGF0ZUxvZ2luKGNvbm5lY3Rpb24sIGF0dGVtcHQpIHtcbiAgICB0aGlzLl92YWxpZGF0ZUxvZ2luSG9vay5lYWNoKGNhbGxiYWNrID0+IHtcbiAgICAgIGxldCByZXQ7XG4gICAgICB0cnkge1xuICAgICAgICByZXQgPSBjYWxsYmFjayhjbG9uZUF0dGVtcHRXaXRoQ29ubmVjdGlvbihjb25uZWN0aW9uLCBhdHRlbXB0KSk7XG4gICAgICB9XG4gICAgICBjYXRjaCAoZSkge1xuICAgICAgICBhdHRlbXB0LmFsbG93ZWQgPSBmYWxzZTtcbiAgICAgICAgLy8gWFhYIHRoaXMgbWVhbnMgdGhlIGxhc3QgdGhyb3duIGVycm9yIG92ZXJyaWRlcyBwcmV2aW91cyBlcnJvclxuICAgICAgICAvLyBtZXNzYWdlcy4gTWF5YmUgdGhpcyBpcyBzdXJwcmlzaW5nIHRvIHVzZXJzIGFuZCB3ZSBzaG91bGQgbWFrZVxuICAgICAgICAvLyBvdmVycmlkaW5nIGVycm9ycyBtb3JlIGV4cGxpY2l0LiAoc2VlXG4gICAgICAgIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9tZXRlb3IvbWV0ZW9yL2lzc3Vlcy8xOTYwKVxuICAgICAgICBhdHRlbXB0LmVycm9yID0gZTtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICB9XG4gICAgICBpZiAoISByZXQpIHtcbiAgICAgICAgYXR0ZW1wdC5hbGxvd2VkID0gZmFsc2U7XG4gICAgICAgIC8vIGRvbid0IG92ZXJyaWRlIGEgc3BlY2lmaWMgZXJyb3IgcHJvdmlkZWQgYnkgYSBwcmV2aW91c1xuICAgICAgICAvLyB2YWxpZGF0b3Igb3IgdGhlIGluaXRpYWwgYXR0ZW1wdCAoZWcgXCJpbmNvcnJlY3QgcGFzc3dvcmRcIikuXG4gICAgICAgIGlmICghYXR0ZW1wdC5lcnJvcilcbiAgICAgICAgICBhdHRlbXB0LmVycm9yID0gbmV3IE1ldGVvci5FcnJvcig0MDMsIFwiTG9naW4gZm9yYmlkZGVuXCIpO1xuICAgICAgfVxuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfSk7XG4gIH07XG5cbiAgX3N1Y2Nlc3NmdWxMb2dpbihjb25uZWN0aW9uLCBhdHRlbXB0KSB7XG4gICAgdGhpcy5fb25Mb2dpbkhvb2suZWFjaChjYWxsYmFjayA9PiB7XG4gICAgICBjYWxsYmFjayhjbG9uZUF0dGVtcHRXaXRoQ29ubmVjdGlvbihjb25uZWN0aW9uLCBhdHRlbXB0KSk7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9KTtcbiAgfTtcblxuICBfZmFpbGVkTG9naW4oY29ubmVjdGlvbiwgYXR0ZW1wdCkge1xuICAgIHRoaXMuX29uTG9naW5GYWlsdXJlSG9vay5lYWNoKGNhbGxiYWNrID0+IHtcbiAgICAgIGNhbGxiYWNrKGNsb25lQXR0ZW1wdFdpdGhDb25uZWN0aW9uKGNvbm5lY3Rpb24sIGF0dGVtcHQpKTtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH0pO1xuICB9O1xuXG4gIF9zdWNjZXNzZnVsTG9nb3V0KGNvbm5lY3Rpb24sIHVzZXJJZCkge1xuICAgIC8vIGRvbid0IGZldGNoIHRoZSB1c2VyIG9iamVjdCB1bmxlc3MgdGhlcmUgYXJlIHNvbWUgY2FsbGJhY2tzIHJlZ2lzdGVyZWRcbiAgICBsZXQgdXNlcjtcbiAgICB0aGlzLl9vbkxvZ291dEhvb2suZWFjaChjYWxsYmFjayA9PiB7XG4gICAgICBpZiAoIXVzZXIgJiYgdXNlcklkKSB1c2VyID0gdGhpcy51c2Vycy5maW5kT25lKHVzZXJJZCwge2ZpZWxkczogdGhpcy5fb3B0aW9ucy5kZWZhdWx0RmllbGRTZWxlY3Rvcn0pO1xuICAgICAgY2FsbGJhY2soeyB1c2VyLCBjb25uZWN0aW9uIH0pO1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfSk7XG4gIH07XG5cbiAgLy8gR2VuZXJhdGVzIGEgTW9uZ29EQiBzZWxlY3RvciB0aGF0IGNhbiBiZSB1c2VkIHRvIHBlcmZvcm0gYSBmYXN0IGNhc2VcbiAgLy8gaW5zZW5zaXRpdmUgbG9va3VwIGZvciB0aGUgZ2l2ZW4gZmllbGROYW1lIGFuZCBzdHJpbmcuIFNpbmNlIE1vbmdvREIgZG9lc1xuICAvLyBub3Qgc3VwcG9ydCBjYXNlIGluc2Vuc2l0aXZlIGluZGV4ZXMsIGFuZCBjYXNlIGluc2Vuc2l0aXZlIHJlZ2V4IHF1ZXJpZXNcbiAgLy8gYXJlIHNsb3csIHdlIGNvbnN0cnVjdCBhIHNldCBvZiBwcmVmaXggc2VsZWN0b3JzIGZvciBhbGwgcGVybXV0YXRpb25zIG9mXG4gIC8vIHRoZSBmaXJzdCA0IGNoYXJhY3RlcnMgb3Vyc2VsdmVzLiBXZSBmaXJzdCBhdHRlbXB0IHRvIG1hdGNoaW5nIGFnYWluc3RcbiAgLy8gdGhlc2UsIGFuZCBiZWNhdXNlICdwcmVmaXggZXhwcmVzc2lvbicgcmVnZXggcXVlcmllcyBkbyB1c2UgaW5kZXhlcyAoc2VlXG4gIC8vIGh0dHA6Ly9kb2NzLm1vbmdvZGIub3JnL3YyLjYvcmVmZXJlbmNlL29wZXJhdG9yL3F1ZXJ5L3JlZ2V4LyNpbmRleC11c2UpLFxuICAvLyB0aGlzIGhhcyBiZWVuIGZvdW5kIHRvIGdyZWF0bHkgaW1wcm92ZSBwZXJmb3JtYW5jZSAoZnJvbSAxMjAwbXMgdG8gNW1zIGluIGFcbiAgLy8gdGVzdCB3aXRoIDEuMDAwLjAwMCB1c2VycykuXG4gIF9zZWxlY3RvckZvckZhc3RDYXNlSW5zZW5zaXRpdmVMb29rdXAgPSAoZmllbGROYW1lLCBzdHJpbmcpID0+IHtcbiAgICAvLyBQZXJmb3JtYW5jZSBzZWVtcyB0byBpbXByb3ZlIHVwIHRvIDQgcHJlZml4IGNoYXJhY3RlcnNcbiAgICBjb25zdCBwcmVmaXggPSBzdHJpbmcuc3Vic3RyaW5nKDAsIE1hdGgubWluKHN0cmluZy5sZW5ndGgsIDQpKTtcbiAgICBjb25zdCBvckNsYXVzZSA9IGdlbmVyYXRlQ2FzZVBlcm11dGF0aW9uc0ZvclN0cmluZyhwcmVmaXgpLm1hcChcbiAgICAgICAgcHJlZml4UGVybXV0YXRpb24gPT4ge1xuICAgICAgICAgIGNvbnN0IHNlbGVjdG9yID0ge307XG4gICAgICAgICAgc2VsZWN0b3JbZmllbGROYW1lXSA9XG4gICAgICAgICAgICAgIG5ldyBSZWdFeHAoYF4ke01ldGVvci5fZXNjYXBlUmVnRXhwKHByZWZpeFBlcm11dGF0aW9uKX1gKTtcbiAgICAgICAgICByZXR1cm4gc2VsZWN0b3I7XG4gICAgICAgIH0pO1xuICAgIGNvbnN0IGNhc2VJbnNlbnNpdGl2ZUNsYXVzZSA9IHt9O1xuICAgIGNhc2VJbnNlbnNpdGl2ZUNsYXVzZVtmaWVsZE5hbWVdID1cbiAgICAgICAgbmV3IFJlZ0V4cChgXiR7TWV0ZW9yLl9lc2NhcGVSZWdFeHAoc3RyaW5nKX0kYCwgJ2knKVxuICAgIHJldHVybiB7JGFuZDogW3skb3I6IG9yQ2xhdXNlfSwgY2FzZUluc2Vuc2l0aXZlQ2xhdXNlXX07XG4gIH1cblxuICBfZmluZFVzZXJCeVF1ZXJ5ID0gKHF1ZXJ5LCBvcHRpb25zKSA9PiB7XG4gICAgbGV0IHVzZXIgPSBudWxsO1xuXG4gICAgaWYgKHF1ZXJ5LmlkKSB7XG4gICAgICAvLyBkZWZhdWx0IGZpZWxkIHNlbGVjdG9yIGlzIGFkZGVkIHdpdGhpbiBnZXRVc2VyQnlJZCgpXG4gICAgICB1c2VyID0gTWV0ZW9yLnVzZXJzLmZpbmRPbmUocXVlcnkuaWQsIHRoaXMuX2FkZERlZmF1bHRGaWVsZFNlbGVjdG9yKG9wdGlvbnMpKTtcbiAgICB9IGVsc2Uge1xuICAgICAgb3B0aW9ucyA9IHRoaXMuX2FkZERlZmF1bHRGaWVsZFNlbGVjdG9yKG9wdGlvbnMpO1xuICAgICAgbGV0IGZpZWxkTmFtZTtcbiAgICAgIGxldCBmaWVsZFZhbHVlO1xuICAgICAgaWYgKHF1ZXJ5LnVzZXJuYW1lKSB7XG4gICAgICAgIGZpZWxkTmFtZSA9ICd1c2VybmFtZSc7XG4gICAgICAgIGZpZWxkVmFsdWUgPSBxdWVyeS51c2VybmFtZTtcbiAgICAgIH0gZWxzZSBpZiAocXVlcnkuZW1haWwpIHtcbiAgICAgICAgZmllbGROYW1lID0gJ2VtYWlscy5hZGRyZXNzJztcbiAgICAgICAgZmllbGRWYWx1ZSA9IHF1ZXJ5LmVtYWlsO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwic2hvdWxkbid0IGhhcHBlbiAodmFsaWRhdGlvbiBtaXNzZWQgc29tZXRoaW5nKVwiKTtcbiAgICAgIH1cbiAgICAgIGxldCBzZWxlY3RvciA9IHt9O1xuICAgICAgc2VsZWN0b3JbZmllbGROYW1lXSA9IGZpZWxkVmFsdWU7XG4gICAgICB1c2VyID0gTWV0ZW9yLnVzZXJzLmZpbmRPbmUoc2VsZWN0b3IsIG9wdGlvbnMpO1xuICAgICAgLy8gSWYgdXNlciBpcyBub3QgZm91bmQsIHRyeSBhIGNhc2UgaW5zZW5zaXRpdmUgbG9va3VwXG4gICAgICBpZiAoIXVzZXIpIHtcbiAgICAgICAgc2VsZWN0b3IgPSB0aGlzLl9zZWxlY3RvckZvckZhc3RDYXNlSW5zZW5zaXRpdmVMb29rdXAoZmllbGROYW1lLCBmaWVsZFZhbHVlKTtcbiAgICAgICAgY29uc3QgY2FuZGlkYXRlVXNlcnMgPSBNZXRlb3IudXNlcnMuZmluZChzZWxlY3Rvciwgb3B0aW9ucykuZmV0Y2goKTtcbiAgICAgICAgLy8gTm8gbWF0Y2ggaWYgbXVsdGlwbGUgY2FuZGlkYXRlcyBhcmUgZm91bmRcbiAgICAgICAgaWYgKGNhbmRpZGF0ZVVzZXJzLmxlbmd0aCA9PT0gMSkge1xuICAgICAgICAgIHVzZXIgPSBjYW5kaWRhdGVVc2Vyc1swXTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiB1c2VyO1xuICB9XG5cbiAgLy8vXG4gIC8vLyBMT0dJTiBNRVRIT0RTXG4gIC8vL1xuXG4gIC8vIExvZ2luIG1ldGhvZHMgcmV0dXJuIHRvIHRoZSBjbGllbnQgYW4gb2JqZWN0IGNvbnRhaW5pbmcgdGhlc2VcbiAgLy8gZmllbGRzIHdoZW4gdGhlIHVzZXIgd2FzIGxvZ2dlZCBpbiBzdWNjZXNzZnVsbHk6XG4gIC8vXG4gIC8vICAgaWQ6IHVzZXJJZFxuICAvLyAgIHRva2VuOiAqXG4gIC8vICAgdG9rZW5FeHBpcmVzOiAqXG4gIC8vXG4gIC8vIHRva2VuRXhwaXJlcyBpcyBvcHRpb25hbCBhbmQgaW50ZW5kcyB0byBwcm92aWRlIGEgaGludCB0byB0aGVcbiAgLy8gY2xpZW50IGFzIHRvIHdoZW4gdGhlIHRva2VuIHdpbGwgZXhwaXJlLiBJZiBub3QgcHJvdmlkZWQsIHRoZVxuICAvLyBjbGllbnQgd2lsbCBjYWxsIEFjY291bnRzLl90b2tlbkV4cGlyYXRpb24sIHBhc3NpbmcgaXQgdGhlIGRhdGVcbiAgLy8gdGhhdCBpdCByZWNlaXZlZCB0aGUgdG9rZW4uXG4gIC8vXG4gIC8vIFRoZSBsb2dpbiBtZXRob2Qgd2lsbCB0aHJvdyBhbiBlcnJvciBiYWNrIHRvIHRoZSBjbGllbnQgaWYgdGhlIHVzZXJcbiAgLy8gZmFpbGVkIHRvIGxvZyBpbi5cbiAgLy9cbiAgLy9cbiAgLy8gTG9naW4gaGFuZGxlcnMgYW5kIHNlcnZpY2Ugc3BlY2lmaWMgbG9naW4gbWV0aG9kcyBzdWNoIGFzXG4gIC8vIGBjcmVhdGVVc2VyYCBpbnRlcm5hbGx5IHJldHVybiBhIGByZXN1bHRgIG9iamVjdCBjb250YWluaW5nIHRoZXNlXG4gIC8vIGZpZWxkczpcbiAgLy9cbiAgLy8gICB0eXBlOlxuICAvLyAgICAgb3B0aW9uYWwgc3RyaW5nOyB0aGUgc2VydmljZSBuYW1lLCBvdmVycmlkZXMgdGhlIGhhbmRsZXJcbiAgLy8gICAgIGRlZmF1bHQgaWYgcHJlc2VudC5cbiAgLy9cbiAgLy8gICBlcnJvcjpcbiAgLy8gICAgIGV4Y2VwdGlvbjsgaWYgdGhlIHVzZXIgaXMgbm90IGFsbG93ZWQgdG8gbG9naW4sIHRoZSByZWFzb24gd2h5LlxuICAvL1xuICAvLyAgIHVzZXJJZDpcbiAgLy8gICAgIHN0cmluZzsgdGhlIHVzZXIgaWQgb2YgdGhlIHVzZXIgYXR0ZW1wdGluZyB0byBsb2dpbiAoaWZcbiAgLy8gICAgIGtub3duKSwgcmVxdWlyZWQgZm9yIGFuIGFsbG93ZWQgbG9naW4uXG4gIC8vXG4gIC8vICAgb3B0aW9uczpcbiAgLy8gICAgIG9wdGlvbmFsIG9iamVjdCBtZXJnZWQgaW50byB0aGUgcmVzdWx0IHJldHVybmVkIGJ5IHRoZSBsb2dpblxuICAvLyAgICAgbWV0aG9kOyB1c2VkIGJ5IEhBTUsgZnJvbSBTUlAuXG4gIC8vXG4gIC8vICAgc3RhbXBlZExvZ2luVG9rZW46XG4gIC8vICAgICBvcHRpb25hbCBvYmplY3Qgd2l0aCBgdG9rZW5gIGFuZCBgd2hlbmAgaW5kaWNhdGluZyB0aGUgbG9naW5cbiAgLy8gICAgIHRva2VuIGlzIGFscmVhZHkgcHJlc2VudCBpbiB0aGUgZGF0YWJhc2UsIHJldHVybmVkIGJ5IHRoZVxuICAvLyAgICAgXCJyZXN1bWVcIiBsb2dpbiBoYW5kbGVyLlxuICAvL1xuICAvLyBGb3IgY29udmVuaWVuY2UsIGxvZ2luIG1ldGhvZHMgY2FuIGFsc28gdGhyb3cgYW4gZXhjZXB0aW9uLCB3aGljaFxuICAvLyBpcyBjb252ZXJ0ZWQgaW50byBhbiB7ZXJyb3J9IHJlc3VsdC4gIEhvd2V2ZXIsIGlmIHRoZSBpZCBvZiB0aGVcbiAgLy8gdXNlciBhdHRlbXB0aW5nIHRoZSBsb2dpbiBpcyBrbm93biwgYSB7dXNlcklkLCBlcnJvcn0gcmVzdWx0IHNob3VsZFxuICAvLyBiZSByZXR1cm5lZCBpbnN0ZWFkIHNpbmNlIHRoZSB1c2VyIGlkIGlzIG5vdCBjYXB0dXJlZCB3aGVuIGFuXG4gIC8vIGV4Y2VwdGlvbiBpcyB0aHJvd24uXG4gIC8vXG4gIC8vIFRoaXMgaW50ZXJuYWwgYHJlc3VsdGAgb2JqZWN0IGlzIGF1dG9tYXRpY2FsbHkgY29udmVydGVkIGludG8gdGhlXG4gIC8vIHB1YmxpYyB7aWQsIHRva2VuLCB0b2tlbkV4cGlyZXN9IG9iamVjdCByZXR1cm5lZCB0byB0aGUgY2xpZW50LlxuXG4gIC8vIFRyeSBhIGxvZ2luIG1ldGhvZCwgY29udmVydGluZyB0aHJvd24gZXhjZXB0aW9ucyBpbnRvIGFuIHtlcnJvcn1cbiAgLy8gcmVzdWx0LiAgVGhlIGB0eXBlYCBhcmd1bWVudCBpcyBhIGRlZmF1bHQsIGluc2VydGVkIGludG8gdGhlIHJlc3VsdFxuICAvLyBvYmplY3QgaWYgbm90IGV4cGxpY2l0bHkgcmV0dXJuZWQuXG4gIC8vXG4gIC8vIExvZyBpbiBhIHVzZXIgb24gYSBjb25uZWN0aW9uLlxuICAvL1xuICAvLyBXZSB1c2UgdGhlIG1ldGhvZCBpbnZvY2F0aW9uIHRvIHNldCB0aGUgdXNlciBpZCBvbiB0aGUgY29ubmVjdGlvbixcbiAgLy8gbm90IHRoZSBjb25uZWN0aW9uIG9iamVjdCBkaXJlY3RseS4gc2V0VXNlcklkIGlzIHRpZWQgdG8gbWV0aG9kcyB0b1xuICAvLyBlbmZvcmNlIGNsZWFyIG9yZGVyaW5nIG9mIG1ldGhvZCBhcHBsaWNhdGlvbiAodXNpbmcgd2FpdCBtZXRob2RzIG9uXG4gIC8vIHRoZSBjbGllbnQsIGFuZCBhIG5vIHNldFVzZXJJZCBhZnRlciB1bmJsb2NrIHJlc3RyaWN0aW9uIG9uIHRoZVxuICAvLyBzZXJ2ZXIpXG4gIC8vXG4gIC8vIFRoZSBgc3RhbXBlZExvZ2luVG9rZW5gIHBhcmFtZXRlciBpcyBvcHRpb25hbC4gIFdoZW4gcHJlc2VudCwgaXRcbiAgLy8gaW5kaWNhdGVzIHRoYXQgdGhlIGxvZ2luIHRva2VuIGhhcyBhbHJlYWR5IGJlZW4gaW5zZXJ0ZWQgaW50byB0aGVcbiAgLy8gZGF0YWJhc2UgYW5kIGRvZXNuJ3QgbmVlZCB0byBiZSBpbnNlcnRlZCBhZ2Fpbi4gIChJdCdzIHVzZWQgYnkgdGhlXG4gIC8vIFwicmVzdW1lXCIgbG9naW4gaGFuZGxlcikuXG4gIF9sb2dpblVzZXIobWV0aG9kSW52b2NhdGlvbiwgdXNlcklkLCBzdGFtcGVkTG9naW5Ub2tlbikge1xuICAgIGlmICghIHN0YW1wZWRMb2dpblRva2VuKSB7XG4gICAgICBzdGFtcGVkTG9naW5Ub2tlbiA9IHRoaXMuX2dlbmVyYXRlU3RhbXBlZExvZ2luVG9rZW4oKTtcbiAgICAgIHRoaXMuX2luc2VydExvZ2luVG9rZW4odXNlcklkLCBzdGFtcGVkTG9naW5Ub2tlbik7XG4gICAgfVxuXG4gICAgLy8gVGhpcyBvcmRlciAoYW5kIHRoZSBhdm9pZGFuY2Ugb2YgeWllbGRzKSBpcyBpbXBvcnRhbnQgdG8gbWFrZVxuICAgIC8vIHN1cmUgdGhhdCB3aGVuIHB1Ymxpc2ggZnVuY3Rpb25zIGFyZSByZXJ1biwgdGhleSBzZWUgYVxuICAgIC8vIGNvbnNpc3RlbnQgdmlldyBvZiB0aGUgd29ybGQ6IHRoZSB1c2VySWQgaXMgc2V0IGFuZCBtYXRjaGVzXG4gICAgLy8gdGhlIGxvZ2luIHRva2VuIG9uIHRoZSBjb25uZWN0aW9uIChub3QgdGhhdCB0aGVyZSBpc1xuICAgIC8vIGN1cnJlbnRseSBhIHB1YmxpYyBBUEkgZm9yIHJlYWRpbmcgdGhlIGxvZ2luIHRva2VuIG9uIGFcbiAgICAvLyBjb25uZWN0aW9uKS5cbiAgICBNZXRlb3IuX25vWWllbGRzQWxsb3dlZCgoKSA9PlxuICAgICAgdGhpcy5fc2V0TG9naW5Ub2tlbihcbiAgICAgICAgdXNlcklkLFxuICAgICAgICBtZXRob2RJbnZvY2F0aW9uLmNvbm5lY3Rpb24sXG4gICAgICAgIHRoaXMuX2hhc2hMb2dpblRva2VuKHN0YW1wZWRMb2dpblRva2VuLnRva2VuKVxuICAgICAgKVxuICAgICk7XG5cbiAgICBtZXRob2RJbnZvY2F0aW9uLnNldFVzZXJJZCh1c2VySWQpO1xuXG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiB1c2VySWQsXG4gICAgICB0b2tlbjogc3RhbXBlZExvZ2luVG9rZW4udG9rZW4sXG4gICAgICB0b2tlbkV4cGlyZXM6IHRoaXMuX3Rva2VuRXhwaXJhdGlvbihzdGFtcGVkTG9naW5Ub2tlbi53aGVuKVxuICAgIH07XG4gIH07XG5cbiAgLy8gQWZ0ZXIgYSBsb2dpbiBtZXRob2QgaGFzIGNvbXBsZXRlZCwgY2FsbCB0aGUgbG9naW4gaG9va3MuICBOb3RlXG4gIC8vIHRoYXQgYGF0dGVtcHRMb2dpbmAgaXMgY2FsbGVkIGZvciAqYWxsKiBsb2dpbiBhdHRlbXB0cywgZXZlbiBvbmVzXG4gIC8vIHdoaWNoIGFyZW4ndCBzdWNjZXNzZnVsIChzdWNoIGFzIGFuIGludmFsaWQgcGFzc3dvcmQsIGV0YykuXG4gIC8vXG4gIC8vIElmIHRoZSBsb2dpbiBpcyBhbGxvd2VkIGFuZCBpc24ndCBhYm9ydGVkIGJ5IGEgdmFsaWRhdGUgbG9naW4gaG9va1xuICAvLyBjYWxsYmFjaywgbG9nIGluIHRoZSB1c2VyLlxuICAvL1xuICBfYXR0ZW1wdExvZ2luKFxuICAgIG1ldGhvZEludm9jYXRpb24sXG4gICAgbWV0aG9kTmFtZSxcbiAgICBtZXRob2RBcmdzLFxuICAgIHJlc3VsdFxuICApIHtcbiAgICBpZiAoIXJlc3VsdClcbiAgICAgIHRocm93IG5ldyBFcnJvcihcInJlc3VsdCBpcyByZXF1aXJlZFwiKTtcblxuICAgIC8vIFhYWCBBIHByb2dyYW1taW5nIGVycm9yIGluIGEgbG9naW4gaGFuZGxlciBjYW4gbGVhZCB0byB0aGlzIG9jY3VycmluZywgYW5kXG4gICAgLy8gdGhlbiB3ZSBkb24ndCBjYWxsIG9uTG9naW4gb3Igb25Mb2dpbkZhaWx1cmUgY2FsbGJhY2tzLiBTaG91bGRcbiAgICAvLyB0cnlMb2dpbk1ldGhvZCBjYXRjaCB0aGlzIGNhc2UgYW5kIHR1cm4gaXQgaW50byBhbiBlcnJvcj9cbiAgICBpZiAoIXJlc3VsdC51c2VySWQgJiYgIXJlc3VsdC5lcnJvcilcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIkEgbG9naW4gbWV0aG9kIG11c3Qgc3BlY2lmeSBhIHVzZXJJZCBvciBhbiBlcnJvclwiKTtcblxuICAgIGxldCB1c2VyO1xuICAgIGlmIChyZXN1bHQudXNlcklkKVxuICAgICAgdXNlciA9IHRoaXMudXNlcnMuZmluZE9uZShyZXN1bHQudXNlcklkLCB7ZmllbGRzOiB0aGlzLl9vcHRpb25zLmRlZmF1bHRGaWVsZFNlbGVjdG9yfSk7XG5cbiAgICBjb25zdCBhdHRlbXB0ID0ge1xuICAgICAgdHlwZTogcmVzdWx0LnR5cGUgfHwgXCJ1bmtub3duXCIsXG4gICAgICBhbGxvd2VkOiAhISAocmVzdWx0LnVzZXJJZCAmJiAhcmVzdWx0LmVycm9yKSxcbiAgICAgIG1ldGhvZE5hbWU6IG1ldGhvZE5hbWUsXG4gICAgICBtZXRob2RBcmd1bWVudHM6IEFycmF5LmZyb20obWV0aG9kQXJncylcbiAgICB9O1xuICAgIGlmIChyZXN1bHQuZXJyb3IpIHtcbiAgICAgIGF0dGVtcHQuZXJyb3IgPSByZXN1bHQuZXJyb3I7XG4gICAgfVxuICAgIGlmICh1c2VyKSB7XG4gICAgICBhdHRlbXB0LnVzZXIgPSB1c2VyO1xuICAgIH1cblxuICAgIC8vIF92YWxpZGF0ZUxvZ2luIG1heSBtdXRhdGUgYGF0dGVtcHRgIGJ5IGFkZGluZyBhbiBlcnJvciBhbmQgY2hhbmdpbmcgYWxsb3dlZFxuICAgIC8vIHRvIGZhbHNlLCBidXQgdGhhdCdzIHRoZSBvbmx5IGNoYW5nZSBpdCBjYW4gbWFrZSAoYW5kIHRoZSB1c2VyJ3MgY2FsbGJhY2tzXG4gICAgLy8gb25seSBnZXQgYSBjbG9uZSBvZiBgYXR0ZW1wdGApLlxuICAgIHRoaXMuX3ZhbGlkYXRlTG9naW4obWV0aG9kSW52b2NhdGlvbi5jb25uZWN0aW9uLCBhdHRlbXB0KTtcblxuICAgIGlmIChhdHRlbXB0LmFsbG93ZWQpIHtcbiAgICAgIGNvbnN0IHJldCA9IHtcbiAgICAgICAgLi4udGhpcy5fbG9naW5Vc2VyKFxuICAgICAgICAgIG1ldGhvZEludm9jYXRpb24sXG4gICAgICAgICAgcmVzdWx0LnVzZXJJZCxcbiAgICAgICAgICByZXN1bHQuc3RhbXBlZExvZ2luVG9rZW5cbiAgICAgICAgKSxcbiAgICAgICAgLi4ucmVzdWx0Lm9wdGlvbnNcbiAgICAgIH07XG4gICAgICByZXQudHlwZSA9IGF0dGVtcHQudHlwZTtcbiAgICAgIHRoaXMuX3N1Y2Nlc3NmdWxMb2dpbihtZXRob2RJbnZvY2F0aW9uLmNvbm5lY3Rpb24sIGF0dGVtcHQpO1xuICAgICAgcmV0dXJuIHJldDtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICB0aGlzLl9mYWlsZWRMb2dpbihtZXRob2RJbnZvY2F0aW9uLmNvbm5lY3Rpb24sIGF0dGVtcHQpO1xuICAgICAgdGhyb3cgYXR0ZW1wdC5lcnJvcjtcbiAgICB9XG4gIH07XG5cbiAgLy8gQWxsIHNlcnZpY2Ugc3BlY2lmaWMgbG9naW4gbWV0aG9kcyBzaG91bGQgZ28gdGhyb3VnaCB0aGlzIGZ1bmN0aW9uLlxuICAvLyBFbnN1cmUgdGhhdCB0aHJvd24gZXhjZXB0aW9ucyBhcmUgY2F1Z2h0IGFuZCB0aGF0IGxvZ2luIGhvb2tcbiAgLy8gY2FsbGJhY2tzIGFyZSBzdGlsbCBjYWxsZWQuXG4gIC8vXG4gIF9sb2dpbk1ldGhvZChcbiAgICBtZXRob2RJbnZvY2F0aW9uLFxuICAgIG1ldGhvZE5hbWUsXG4gICAgbWV0aG9kQXJncyxcbiAgICB0eXBlLFxuICAgIGZuXG4gICkge1xuICAgIHJldHVybiB0aGlzLl9hdHRlbXB0TG9naW4oXG4gICAgICBtZXRob2RJbnZvY2F0aW9uLFxuICAgICAgbWV0aG9kTmFtZSxcbiAgICAgIG1ldGhvZEFyZ3MsXG4gICAgICB0cnlMb2dpbk1ldGhvZCh0eXBlLCBmbilcbiAgICApO1xuICB9O1xuXG5cbiAgLy8gUmVwb3J0IGEgbG9naW4gYXR0ZW1wdCBmYWlsZWQgb3V0c2lkZSB0aGUgY29udGV4dCBvZiBhIG5vcm1hbCBsb2dpblxuICAvLyBtZXRob2QuIFRoaXMgaXMgZm9yIHVzZSBpbiB0aGUgY2FzZSB3aGVyZSB0aGVyZSBpcyBhIG11bHRpLXN0ZXAgbG9naW5cbiAgLy8gcHJvY2VkdXJlIChlZyBTUlAgYmFzZWQgcGFzc3dvcmQgbG9naW4pLiBJZiBhIG1ldGhvZCBlYXJseSBpbiB0aGVcbiAgLy8gY2hhaW4gZmFpbHMsIGl0IHNob3VsZCBjYWxsIHRoaXMgZnVuY3Rpb24gdG8gcmVwb3J0IGEgZmFpbHVyZS4gVGhlcmVcbiAgLy8gaXMgbm8gY29ycmVzcG9uZGluZyBtZXRob2QgZm9yIGEgc3VjY2Vzc2Z1bCBsb2dpbjsgbWV0aG9kcyB0aGF0IGNhblxuICAvLyBzdWNjZWVkIGF0IGxvZ2dpbmcgYSB1c2VyIGluIHNob3VsZCBhbHdheXMgYmUgYWN0dWFsIGxvZ2luIG1ldGhvZHNcbiAgLy8gKHVzaW5nIGVpdGhlciBBY2NvdW50cy5fbG9naW5NZXRob2Qgb3IgQWNjb3VudHMucmVnaXN0ZXJMb2dpbkhhbmRsZXIpLlxuICBfcmVwb3J0TG9naW5GYWlsdXJlKFxuICAgIG1ldGhvZEludm9jYXRpb24sXG4gICAgbWV0aG9kTmFtZSxcbiAgICBtZXRob2RBcmdzLFxuICAgIHJlc3VsdFxuICApIHtcbiAgICBjb25zdCBhdHRlbXB0ID0ge1xuICAgICAgdHlwZTogcmVzdWx0LnR5cGUgfHwgXCJ1bmtub3duXCIsXG4gICAgICBhbGxvd2VkOiBmYWxzZSxcbiAgICAgIGVycm9yOiByZXN1bHQuZXJyb3IsXG4gICAgICBtZXRob2ROYW1lOiBtZXRob2ROYW1lLFxuICAgICAgbWV0aG9kQXJndW1lbnRzOiBBcnJheS5mcm9tKG1ldGhvZEFyZ3MpXG4gICAgfTtcblxuICAgIGlmIChyZXN1bHQudXNlcklkKSB7XG4gICAgICBhdHRlbXB0LnVzZXIgPSB0aGlzLnVzZXJzLmZpbmRPbmUocmVzdWx0LnVzZXJJZCwge2ZpZWxkczogdGhpcy5fb3B0aW9ucy5kZWZhdWx0RmllbGRTZWxlY3Rvcn0pO1xuICAgIH1cblxuICAgIHRoaXMuX3ZhbGlkYXRlTG9naW4obWV0aG9kSW52b2NhdGlvbi5jb25uZWN0aW9uLCBhdHRlbXB0KTtcbiAgICB0aGlzLl9mYWlsZWRMb2dpbihtZXRob2RJbnZvY2F0aW9uLmNvbm5lY3Rpb24sIGF0dGVtcHQpO1xuXG4gICAgLy8gX3ZhbGlkYXRlTG9naW4gbWF5IG11dGF0ZSBhdHRlbXB0IHRvIHNldCBhIG5ldyBlcnJvciBtZXNzYWdlLiBSZXR1cm5cbiAgICAvLyB0aGUgbW9kaWZpZWQgdmVyc2lvbi5cbiAgICByZXR1cm4gYXR0ZW1wdDtcbiAgfTtcblxuICAvLy9cbiAgLy8vIExPR0lOIEhBTkRMRVJTXG4gIC8vL1xuXG4gIC8vIFRoZSBtYWluIGVudHJ5IHBvaW50IGZvciBhdXRoIHBhY2thZ2VzIHRvIGhvb2sgaW4gdG8gbG9naW4uXG4gIC8vXG4gIC8vIEEgbG9naW4gaGFuZGxlciBpcyBhIGxvZ2luIG1ldGhvZCB3aGljaCBjYW4gcmV0dXJuIGB1bmRlZmluZWRgIHRvXG4gIC8vIGluZGljYXRlIHRoYXQgdGhlIGxvZ2luIHJlcXVlc3QgaXMgbm90IGhhbmRsZWQgYnkgdGhpcyBoYW5kbGVyLlxuICAvL1xuICAvLyBAcGFyYW0gbmFtZSB7U3RyaW5nfSBPcHRpb25hbC4gIFRoZSBzZXJ2aWNlIG5hbWUsIHVzZWQgYnkgZGVmYXVsdFxuICAvLyBpZiBhIHNwZWNpZmljIHNlcnZpY2UgbmFtZSBpc24ndCByZXR1cm5lZCBpbiB0aGUgcmVzdWx0LlxuICAvL1xuICAvLyBAcGFyYW0gaGFuZGxlciB7RnVuY3Rpb259IEEgZnVuY3Rpb24gdGhhdCByZWNlaXZlcyBhbiBvcHRpb25zIG9iamVjdFxuICAvLyAoYXMgcGFzc2VkIGFzIGFuIGFyZ3VtZW50IHRvIHRoZSBgbG9naW5gIG1ldGhvZCkgYW5kIHJldHVybnMgb25lIG9mOlxuICAvLyAtIGB1bmRlZmluZWRgLCBtZWFuaW5nIGRvbid0IGhhbmRsZTtcbiAgLy8gLSBhIGxvZ2luIG1ldGhvZCByZXN1bHQgb2JqZWN0XG5cbiAgcmVnaXN0ZXJMb2dpbkhhbmRsZXIobmFtZSwgaGFuZGxlcikge1xuICAgIGlmICghIGhhbmRsZXIpIHtcbiAgICAgIGhhbmRsZXIgPSBuYW1lO1xuICAgICAgbmFtZSA9IG51bGw7XG4gICAgfVxuXG4gICAgdGhpcy5fbG9naW5IYW5kbGVycy5wdXNoKHtcbiAgICAgIG5hbWU6IG5hbWUsXG4gICAgICBoYW5kbGVyOiBoYW5kbGVyXG4gICAgfSk7XG4gIH07XG5cblxuICAvLyBDaGVja3MgYSB1c2VyJ3MgY3JlZGVudGlhbHMgYWdhaW5zdCBhbGwgdGhlIHJlZ2lzdGVyZWQgbG9naW5cbiAgLy8gaGFuZGxlcnMsIGFuZCByZXR1cm5zIGEgbG9naW4gdG9rZW4gaWYgdGhlIGNyZWRlbnRpYWxzIGFyZSB2YWxpZC4gSXRcbiAgLy8gaXMgbGlrZSB0aGUgbG9naW4gbWV0aG9kLCBleGNlcHQgdGhhdCBpdCBkb2Vzbid0IHNldCB0aGUgbG9nZ2VkLWluXG4gIC8vIHVzZXIgb24gdGhlIGNvbm5lY3Rpb24uIFRocm93cyBhIE1ldGVvci5FcnJvciBpZiBsb2dnaW5nIGluIGZhaWxzLFxuICAvLyBpbmNsdWRpbmcgdGhlIGNhc2Ugd2hlcmUgbm9uZSBvZiB0aGUgbG9naW4gaGFuZGxlcnMgaGFuZGxlZCB0aGUgbG9naW5cbiAgLy8gcmVxdWVzdC4gT3RoZXJ3aXNlLCByZXR1cm5zIHtpZDogdXNlcklkLCB0b2tlbjogKiwgdG9rZW5FeHBpcmVzOiAqfS5cbiAgLy9cbiAgLy8gRm9yIGV4YW1wbGUsIGlmIHlvdSB3YW50IHRvIGxvZ2luIHdpdGggYSBwbGFpbnRleHQgcGFzc3dvcmQsIGBvcHRpb25zYCBjb3VsZCBiZVxuICAvLyAgIHsgdXNlcjogeyB1c2VybmFtZTogPHVzZXJuYW1lPiB9LCBwYXNzd29yZDogPHBhc3N3b3JkPiB9LCBvclxuICAvLyAgIHsgdXNlcjogeyBlbWFpbDogPGVtYWlsPiB9LCBwYXNzd29yZDogPHBhc3N3b3JkPiB9LlxuXG4gIC8vIFRyeSBhbGwgb2YgdGhlIHJlZ2lzdGVyZWQgbG9naW4gaGFuZGxlcnMgdW50aWwgb25lIG9mIHRoZW0gZG9lc24ndFxuICAvLyByZXR1cm4gYHVuZGVmaW5lZGAsIG1lYW5pbmcgaXQgaGFuZGxlZCB0aGlzIGNhbGwgdG8gYGxvZ2luYC4gUmV0dXJuXG4gIC8vIHRoYXQgcmV0dXJuIHZhbHVlLlxuICBfcnVuTG9naW5IYW5kbGVycyhtZXRob2RJbnZvY2F0aW9uLCBvcHRpb25zKSB7XG4gICAgZm9yIChsZXQgaGFuZGxlciBvZiB0aGlzLl9sb2dpbkhhbmRsZXJzKSB7XG4gICAgICBjb25zdCByZXN1bHQgPSB0cnlMb2dpbk1ldGhvZChcbiAgICAgICAgaGFuZGxlci5uYW1lLFxuICAgICAgICAoKSA9PiBoYW5kbGVyLmhhbmRsZXIuY2FsbChtZXRob2RJbnZvY2F0aW9uLCBvcHRpb25zKVxuICAgICAgKTtcblxuICAgICAgaWYgKHJlc3VsdCkge1xuICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgfVxuXG4gICAgICBpZiAocmVzdWx0ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IE1ldGVvci5FcnJvcig0MDAsIFwiQSBsb2dpbiBoYW5kbGVyIHNob3VsZCByZXR1cm4gYSByZXN1bHQgb3IgdW5kZWZpbmVkXCIpO1xuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiB7XG4gICAgICB0eXBlOiBudWxsLFxuICAgICAgZXJyb3I6IG5ldyBNZXRlb3IuRXJyb3IoNDAwLCBcIlVucmVjb2duaXplZCBvcHRpb25zIGZvciBsb2dpbiByZXF1ZXN0XCIpXG4gICAgfTtcbiAgfTtcblxuICAvLyBEZWxldGVzIHRoZSBnaXZlbiBsb2dpblRva2VuIGZyb20gdGhlIGRhdGFiYXNlLlxuICAvL1xuICAvLyBGb3IgbmV3LXN0eWxlIGhhc2hlZCB0b2tlbiwgdGhpcyB3aWxsIGNhdXNlIGFsbCBjb25uZWN0aW9uc1xuICAvLyBhc3NvY2lhdGVkIHdpdGggdGhlIHRva2VuIHRvIGJlIGNsb3NlZC5cbiAgLy9cbiAgLy8gQW55IGNvbm5lY3Rpb25zIGFzc29jaWF0ZWQgd2l0aCBvbGQtc3R5bGUgdW5oYXNoZWQgdG9rZW5zIHdpbGwgYmVcbiAgLy8gaW4gdGhlIHByb2Nlc3Mgb2YgYmVjb21pbmcgYXNzb2NpYXRlZCB3aXRoIGhhc2hlZCB0b2tlbnMgYW5kIHRoZW5cbiAgLy8gdGhleSdsbCBnZXQgY2xvc2VkLlxuICBkZXN0cm95VG9rZW4odXNlcklkLCBsb2dpblRva2VuKSB7XG4gICAgdGhpcy51c2Vycy51cGRhdGUodXNlcklkLCB7XG4gICAgICAkcHVsbDoge1xuICAgICAgICBcInNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vuc1wiOiB7XG4gICAgICAgICAgJG9yOiBbXG4gICAgICAgICAgICB7IGhhc2hlZFRva2VuOiBsb2dpblRva2VuIH0sXG4gICAgICAgICAgICB7IHRva2VuOiBsb2dpblRva2VuIH1cbiAgICAgICAgICBdXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfTtcblxuICBfaW5pdFNlcnZlck1ldGhvZHMoKSB7XG4gICAgLy8gVGhlIG1ldGhvZHMgY3JlYXRlZCBpbiB0aGlzIGZ1bmN0aW9uIG5lZWQgdG8gYmUgY3JlYXRlZCBoZXJlIHNvIHRoYXRcbiAgICAvLyB0aGlzIHZhcmlhYmxlIGlzIGF2YWlsYWJsZSBpbiB0aGVpciBzY29wZS5cbiAgICBjb25zdCBhY2NvdW50cyA9IHRoaXM7XG5cblxuICAgIC8vIFRoaXMgb2JqZWN0IHdpbGwgYmUgcG9wdWxhdGVkIHdpdGggbWV0aG9kcyBhbmQgdGhlbiBwYXNzZWQgdG9cbiAgICAvLyBhY2NvdW50cy5fc2VydmVyLm1ldGhvZHMgZnVydGhlciBiZWxvdy5cbiAgICBjb25zdCBtZXRob2RzID0ge307XG5cbiAgICAvLyBAcmV0dXJucyB7T2JqZWN0fG51bGx9XG4gICAgLy8gICBJZiBzdWNjZXNzZnVsLCByZXR1cm5zIHt0b2tlbjogcmVjb25uZWN0VG9rZW4sIGlkOiB1c2VySWR9XG4gICAgLy8gICBJZiB1bnN1Y2Nlc3NmdWwgKGZvciBleGFtcGxlLCBpZiB0aGUgdXNlciBjbG9zZWQgdGhlIG9hdXRoIGxvZ2luIHBvcHVwKSxcbiAgICAvLyAgICAgdGhyb3dzIGFuIGVycm9yIGRlc2NyaWJpbmcgdGhlIHJlYXNvblxuICAgIG1ldGhvZHMubG9naW4gPSBmdW5jdGlvbiAob3B0aW9ucykge1xuICAgICAgLy8gTG9naW4gaGFuZGxlcnMgc2hvdWxkIHJlYWxseSBhbHNvIGNoZWNrIHdoYXRldmVyIGZpZWxkIHRoZXkgbG9vayBhdCBpblxuICAgICAgLy8gb3B0aW9ucywgYnV0IHdlIGRvbid0IGVuZm9yY2UgaXQuXG4gICAgICBjaGVjayhvcHRpb25zLCBPYmplY3QpO1xuXG4gICAgICBjb25zdCByZXN1bHQgPSBhY2NvdW50cy5fcnVuTG9naW5IYW5kbGVycyh0aGlzLCBvcHRpb25zKTtcblxuICAgICAgcmV0dXJuIGFjY291bnRzLl9hdHRlbXB0TG9naW4odGhpcywgXCJsb2dpblwiLCBhcmd1bWVudHMsIHJlc3VsdCk7XG4gICAgfTtcblxuICAgIG1ldGhvZHMubG9nb3V0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgY29uc3QgdG9rZW4gPSBhY2NvdW50cy5fZ2V0TG9naW5Ub2tlbih0aGlzLmNvbm5lY3Rpb24uaWQpO1xuICAgICAgYWNjb3VudHMuX3NldExvZ2luVG9rZW4odGhpcy51c2VySWQsIHRoaXMuY29ubmVjdGlvbiwgbnVsbCk7XG4gICAgICBpZiAodG9rZW4gJiYgdGhpcy51c2VySWQpIHtcbiAgICAgICAgYWNjb3VudHMuZGVzdHJveVRva2VuKHRoaXMudXNlcklkLCB0b2tlbik7XG4gICAgICB9XG4gICAgICBhY2NvdW50cy5fc3VjY2Vzc2Z1bExvZ291dCh0aGlzLmNvbm5lY3Rpb24sIHRoaXMudXNlcklkKTtcbiAgICAgIHRoaXMuc2V0VXNlcklkKG51bGwpO1xuICAgIH07XG5cbiAgICAvLyBHZW5lcmF0ZXMgYSBuZXcgbG9naW4gdG9rZW4gd2l0aCB0aGUgc2FtZSBleHBpcmF0aW9uIGFzIHRoZVxuICAgIC8vIGNvbm5lY3Rpb24ncyBjdXJyZW50IHRva2VuIGFuZCBzYXZlcyBpdCB0byB0aGUgZGF0YWJhc2UuIEFzc29jaWF0ZXNcbiAgICAvLyB0aGUgY29ubmVjdGlvbiB3aXRoIHRoaXMgbmV3IHRva2VuIGFuZCByZXR1cm5zIGl0LiBUaHJvd3MgYW4gZXJyb3JcbiAgICAvLyBpZiBjYWxsZWQgb24gYSBjb25uZWN0aW9uIHRoYXQgaXNuJ3QgbG9nZ2VkIGluLlxuICAgIC8vXG4gICAgLy8gQHJldHVybnMgT2JqZWN0XG4gICAgLy8gICBJZiBzdWNjZXNzZnVsLCByZXR1cm5zIHsgdG9rZW46IDxuZXcgdG9rZW4+LCBpZDogPHVzZXIgaWQ+LFxuICAgIC8vICAgdG9rZW5FeHBpcmVzOiA8ZXhwaXJhdGlvbiBkYXRlPiB9LlxuICAgIG1ldGhvZHMuZ2V0TmV3VG9rZW4gPSBmdW5jdGlvbiAoKSB7XG4gICAgICBjb25zdCB1c2VyID0gYWNjb3VudHMudXNlcnMuZmluZE9uZSh0aGlzLnVzZXJJZCwge1xuICAgICAgICBmaWVsZHM6IHsgXCJzZXJ2aWNlcy5yZXN1bWUubG9naW5Ub2tlbnNcIjogMSB9XG4gICAgICB9KTtcbiAgICAgIGlmICghIHRoaXMudXNlcklkIHx8ICEgdXNlcikge1xuICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKFwiWW91IGFyZSBub3QgbG9nZ2VkIGluLlwiKTtcbiAgICAgIH1cbiAgICAgIC8vIEJlIGNhcmVmdWwgbm90IHRvIGdlbmVyYXRlIGEgbmV3IHRva2VuIHRoYXQgaGFzIGEgbGF0ZXJcbiAgICAgIC8vIGV4cGlyYXRpb24gdGhhbiB0aGUgY3VycmVuIHRva2VuLiBPdGhlcndpc2UsIGEgYmFkIGd1eSB3aXRoIGFcbiAgICAgIC8vIHN0b2xlbiB0b2tlbiBjb3VsZCB1c2UgdGhpcyBtZXRob2QgdG8gc3RvcCBoaXMgc3RvbGVuIHRva2VuIGZyb21cbiAgICAgIC8vIGV2ZXIgZXhwaXJpbmcuXG4gICAgICBjb25zdCBjdXJyZW50SGFzaGVkVG9rZW4gPSBhY2NvdW50cy5fZ2V0TG9naW5Ub2tlbih0aGlzLmNvbm5lY3Rpb24uaWQpO1xuICAgICAgY29uc3QgY3VycmVudFN0YW1wZWRUb2tlbiA9IHVzZXIuc2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zLmZpbmQoXG4gICAgICAgIHN0YW1wZWRUb2tlbiA9PiBzdGFtcGVkVG9rZW4uaGFzaGVkVG9rZW4gPT09IGN1cnJlbnRIYXNoZWRUb2tlblxuICAgICAgKTtcbiAgICAgIGlmICghIGN1cnJlbnRTdGFtcGVkVG9rZW4pIHsgLy8gc2FmZXR5IGJlbHQ6IHRoaXMgc2hvdWxkIG5ldmVyIGhhcHBlblxuICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKFwiSW52YWxpZCBsb2dpbiB0b2tlblwiKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IG5ld1N0YW1wZWRUb2tlbiA9IGFjY291bnRzLl9nZW5lcmF0ZVN0YW1wZWRMb2dpblRva2VuKCk7XG4gICAgICBuZXdTdGFtcGVkVG9rZW4ud2hlbiA9IGN1cnJlbnRTdGFtcGVkVG9rZW4ud2hlbjtcbiAgICAgIGFjY291bnRzLl9pbnNlcnRMb2dpblRva2VuKHRoaXMudXNlcklkLCBuZXdTdGFtcGVkVG9rZW4pO1xuICAgICAgcmV0dXJuIGFjY291bnRzLl9sb2dpblVzZXIodGhpcywgdGhpcy51c2VySWQsIG5ld1N0YW1wZWRUb2tlbik7XG4gICAgfTtcblxuICAgIC8vIFJlbW92ZXMgYWxsIHRva2VucyBleGNlcHQgdGhlIHRva2VuIGFzc29jaWF0ZWQgd2l0aCB0aGUgY3VycmVudFxuICAgIC8vIGNvbm5lY3Rpb24uIFRocm93cyBhbiBlcnJvciBpZiB0aGUgY29ubmVjdGlvbiBpcyBub3QgbG9nZ2VkXG4gICAgLy8gaW4uIFJldHVybnMgbm90aGluZyBvbiBzdWNjZXNzLlxuICAgIG1ldGhvZHMucmVtb3ZlT3RoZXJUb2tlbnMgPSBmdW5jdGlvbiAoKSB7XG4gICAgICBpZiAoISB0aGlzLnVzZXJJZCkge1xuICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKFwiWW91IGFyZSBub3QgbG9nZ2VkIGluLlwiKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IGN1cnJlbnRUb2tlbiA9IGFjY291bnRzLl9nZXRMb2dpblRva2VuKHRoaXMuY29ubmVjdGlvbi5pZCk7XG4gICAgICBhY2NvdW50cy51c2Vycy51cGRhdGUodGhpcy51c2VySWQsIHtcbiAgICAgICAgJHB1bGw6IHtcbiAgICAgICAgICBcInNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vuc1wiOiB7IGhhc2hlZFRva2VuOiB7ICRuZTogY3VycmVudFRva2VuIH0gfVxuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgLy8gQWxsb3cgYSBvbmUtdGltZSBjb25maWd1cmF0aW9uIGZvciBhIGxvZ2luIHNlcnZpY2UuIE1vZGlmaWNhdGlvbnNcbiAgICAvLyB0byB0aGlzIGNvbGxlY3Rpb24gYXJlIGFsc28gYWxsb3dlZCBpbiBpbnNlY3VyZSBtb2RlLlxuICAgIG1ldGhvZHMuY29uZmlndXJlTG9naW5TZXJ2aWNlID0gKG9wdGlvbnMpID0+IHtcbiAgICAgIGNoZWNrKG9wdGlvbnMsIE1hdGNoLk9iamVjdEluY2x1ZGluZyh7c2VydmljZTogU3RyaW5nfSkpO1xuICAgICAgLy8gRG9uJ3QgbGV0IHJhbmRvbSB1c2VycyBjb25maWd1cmUgYSBzZXJ2aWNlIHdlIGhhdmVuJ3QgYWRkZWQgeWV0IChzb1xuICAgICAgLy8gdGhhdCB3aGVuIHdlIGRvIGxhdGVyIGFkZCBpdCwgaXQncyBzZXQgdXAgd2l0aCB0aGVpciBjb25maWd1cmF0aW9uXG4gICAgICAvLyBpbnN0ZWFkIG9mIG91cnMpLlxuICAgICAgLy8gWFhYIGlmIHNlcnZpY2UgY29uZmlndXJhdGlvbiBpcyBvYXV0aC1zcGVjaWZpYyB0aGVuIHRoaXMgY29kZSBzaG91bGRcbiAgICAgIC8vICAgICBiZSBpbiBhY2NvdW50cy1vYXV0aDsgaWYgaXQncyBub3QgdGhlbiB0aGUgcmVnaXN0cnkgc2hvdWxkIGJlXG4gICAgICAvLyAgICAgaW4gdGhpcyBwYWNrYWdlXG4gICAgICBpZiAoIShhY2NvdW50cy5vYXV0aFxuICAgICAgICAmJiBhY2NvdW50cy5vYXV0aC5zZXJ2aWNlTmFtZXMoKS5pbmNsdWRlcyhvcHRpb25zLnNlcnZpY2UpKSkge1xuICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMywgXCJTZXJ2aWNlIHVua25vd25cIik7XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IHsgU2VydmljZUNvbmZpZ3VyYXRpb24gfSA9IFBhY2thZ2VbJ3NlcnZpY2UtY29uZmlndXJhdGlvbiddO1xuICAgICAgaWYgKFNlcnZpY2VDb25maWd1cmF0aW9uLmNvbmZpZ3VyYXRpb25zLmZpbmRPbmUoe3NlcnZpY2U6IG9wdGlvbnMuc2VydmljZX0pKVxuICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMywgYFNlcnZpY2UgJHtvcHRpb25zLnNlcnZpY2V9IGFscmVhZHkgY29uZmlndXJlZGApO1xuXG4gICAgICBpZiAoaGFzT3duLmNhbGwob3B0aW9ucywgJ3NlY3JldCcpICYmIHVzaW5nT0F1dGhFbmNyeXB0aW9uKCkpXG4gICAgICAgIG9wdGlvbnMuc2VjcmV0ID0gT0F1dGhFbmNyeXB0aW9uLnNlYWwob3B0aW9ucy5zZWNyZXQpO1xuXG4gICAgICBTZXJ2aWNlQ29uZmlndXJhdGlvbi5jb25maWd1cmF0aW9ucy5pbnNlcnQob3B0aW9ucyk7XG4gICAgfTtcblxuICAgIGFjY291bnRzLl9zZXJ2ZXIubWV0aG9kcyhtZXRob2RzKTtcbiAgfTtcblxuICBfaW5pdEFjY291bnREYXRhSG9va3MoKSB7XG4gICAgdGhpcy5fc2VydmVyLm9uQ29ubmVjdGlvbihjb25uZWN0aW9uID0+IHtcbiAgICAgIHRoaXMuX2FjY291bnREYXRhW2Nvbm5lY3Rpb24uaWRdID0ge1xuICAgICAgICBjb25uZWN0aW9uOiBjb25uZWN0aW9uXG4gICAgICB9O1xuXG4gICAgICBjb25uZWN0aW9uLm9uQ2xvc2UoKCkgPT4ge1xuICAgICAgICB0aGlzLl9yZW1vdmVUb2tlbkZyb21Db25uZWN0aW9uKGNvbm5lY3Rpb24uaWQpO1xuICAgICAgICBkZWxldGUgdGhpcy5fYWNjb3VudERhdGFbY29ubmVjdGlvbi5pZF07XG4gICAgICB9KTtcbiAgICB9KTtcbiAgfTtcblxuICBfaW5pdFNlcnZlclB1YmxpY2F0aW9ucygpIHtcbiAgICAvLyBCcmluZyBpbnRvIGxleGljYWwgc2NvcGUgZm9yIHB1Ymxpc2ggY2FsbGJhY2tzIHRoYXQgbmVlZCBgdGhpc2BcbiAgICBjb25zdCB7IHVzZXJzLCBfYXV0b3B1Ymxpc2hGaWVsZHMsIF9kZWZhdWx0UHVibGlzaEZpZWxkcyB9ID0gdGhpcztcblxuICAgIC8vIFB1Ymxpc2ggYWxsIGxvZ2luIHNlcnZpY2UgY29uZmlndXJhdGlvbiBmaWVsZHMgb3RoZXIgdGhhbiBzZWNyZXQuXG4gICAgdGhpcy5fc2VydmVyLnB1Ymxpc2goXCJtZXRlb3IubG9naW5TZXJ2aWNlQ29uZmlndXJhdGlvblwiLCAoKSA9PiB7XG4gICAgICBjb25zdCB7IFNlcnZpY2VDb25maWd1cmF0aW9uIH0gPSBQYWNrYWdlWydzZXJ2aWNlLWNvbmZpZ3VyYXRpb24nXTtcbiAgICAgIHJldHVybiBTZXJ2aWNlQ29uZmlndXJhdGlvbi5jb25maWd1cmF0aW9ucy5maW5kKHt9LCB7ZmllbGRzOiB7c2VjcmV0OiAwfX0pO1xuICAgIH0sIHtpc19hdXRvOiB0cnVlfSk7IC8vIG5vdCB0ZWNobmljYWxseSBhdXRvcHVibGlzaCwgYnV0IHN0b3BzIHRoZSB3YXJuaW5nLlxuXG4gICAgLy8gVXNlIE1ldGVvci5zdGFydHVwIHRvIGdpdmUgb3RoZXIgcGFja2FnZXMgYSBjaGFuY2UgdG8gY2FsbFxuICAgIC8vIHNldERlZmF1bHRQdWJsaXNoRmllbGRzLlxuICAgIE1ldGVvci5zdGFydHVwKCgpID0+IHtcbiAgICAgIC8vIFB1Ymxpc2ggdGhlIGN1cnJlbnQgdXNlcidzIHJlY29yZCB0byB0aGUgY2xpZW50LlxuICAgICAgdGhpcy5fc2VydmVyLnB1Ymxpc2gobnVsbCwgZnVuY3Rpb24gKCkge1xuICAgICAgICBpZiAodGhpcy51c2VySWQpIHtcbiAgICAgICAgICByZXR1cm4gdXNlcnMuZmluZCh7XG4gICAgICAgICAgICBfaWQ6IHRoaXMudXNlcklkXG4gICAgICAgICAgfSwge1xuICAgICAgICAgICAgZmllbGRzOiBfZGVmYXVsdFB1Ymxpc2hGaWVsZHMucHJvamVjdGlvbixcbiAgICAgICAgICB9KTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgfVxuICAgICAgfSwgLypzdXBwcmVzcyBhdXRvcHVibGlzaCB3YXJuaW5nKi97aXNfYXV0bzogdHJ1ZX0pO1xuICAgIH0pO1xuXG4gICAgLy8gVXNlIE1ldGVvci5zdGFydHVwIHRvIGdpdmUgb3RoZXIgcGFja2FnZXMgYSBjaGFuY2UgdG8gY2FsbFxuICAgIC8vIGFkZEF1dG9wdWJsaXNoRmllbGRzLlxuICAgIFBhY2thZ2UuYXV0b3B1Ymxpc2ggJiYgTWV0ZW9yLnN0YXJ0dXAoKCkgPT4ge1xuICAgICAgLy8gWydwcm9maWxlJywgJ3VzZXJuYW1lJ10gLT4ge3Byb2ZpbGU6IDEsIHVzZXJuYW1lOiAxfVxuICAgICAgY29uc3QgdG9GaWVsZFNlbGVjdG9yID0gZmllbGRzID0+IGZpZWxkcy5yZWR1Y2UoKHByZXYsIGZpZWxkKSA9PiAoXG4gICAgICAgICAgeyAuLi5wcmV2LCBbZmllbGRdOiAxIH0pLFxuICAgICAgICB7fVxuICAgICAgKTtcbiAgICAgIHRoaXMuX3NlcnZlci5wdWJsaXNoKG51bGwsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKHRoaXMudXNlcklkKSB7XG4gICAgICAgICAgcmV0dXJuIHVzZXJzLmZpbmQoeyBfaWQ6IHRoaXMudXNlcklkIH0sIHtcbiAgICAgICAgICAgIGZpZWxkczogdG9GaWVsZFNlbGVjdG9yKF9hdXRvcHVibGlzaEZpZWxkcy5sb2dnZWRJblVzZXIpLFxuICAgICAgICAgIH0pXG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgIH1cbiAgICAgIH0sIC8qc3VwcHJlc3MgYXV0b3B1Ymxpc2ggd2FybmluZyove2lzX2F1dG86IHRydWV9KTtcblxuICAgICAgLy8gWFhYIHRoaXMgcHVibGlzaCBpcyBuZWl0aGVyIGRlZHVwLWFibGUgbm9yIGlzIGl0IG9wdGltaXplZCBieSBvdXIgc3BlY2lhbFxuICAgICAgLy8gdHJlYXRtZW50IG9mIHF1ZXJpZXMgb24gYSBzcGVjaWZpYyBfaWQuIFRoZXJlZm9yZSB0aGlzIHdpbGwgaGF2ZSBPKG5eMilcbiAgICAgIC8vIHJ1bi10aW1lIHBlcmZvcm1hbmNlIGV2ZXJ5IHRpbWUgYSB1c2VyIGRvY3VtZW50IGlzIGNoYW5nZWQgKGVnIHNvbWVvbmVcbiAgICAgIC8vIGxvZ2dpbmcgaW4pLiBJZiB0aGlzIGlzIGEgcHJvYmxlbSwgd2UgY2FuIGluc3RlYWQgd3JpdGUgYSBtYW51YWwgcHVibGlzaFxuICAgICAgLy8gZnVuY3Rpb24gd2hpY2ggZmlsdGVycyBvdXQgZmllbGRzIGJhc2VkIG9uICd0aGlzLnVzZXJJZCcuXG4gICAgICB0aGlzLl9zZXJ2ZXIucHVibGlzaChudWxsLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGNvbnN0IHNlbGVjdG9yID0gdGhpcy51c2VySWQgPyB7IF9pZDogeyAkbmU6IHRoaXMudXNlcklkIH0gfSA6IHt9O1xuICAgICAgICByZXR1cm4gdXNlcnMuZmluZChzZWxlY3Rvciwge1xuICAgICAgICAgIGZpZWxkczogdG9GaWVsZFNlbGVjdG9yKF9hdXRvcHVibGlzaEZpZWxkcy5vdGhlclVzZXJzKSxcbiAgICAgICAgfSlcbiAgICAgIH0sIC8qc3VwcHJlc3MgYXV0b3B1Ymxpc2ggd2FybmluZyove2lzX2F1dG86IHRydWV9KTtcbiAgICB9KTtcbiAgfTtcblxuICAvLyBBZGQgdG8gdGhlIGxpc3Qgb2YgZmllbGRzIG9yIHN1YmZpZWxkcyB0byBiZSBhdXRvbWF0aWNhbGx5XG4gIC8vIHB1Ymxpc2hlZCBpZiBhdXRvcHVibGlzaCBpcyBvbi4gTXVzdCBiZSBjYWxsZWQgZnJvbSB0b3AtbGV2ZWxcbiAgLy8gY29kZSAoaWUsIGJlZm9yZSBNZXRlb3Iuc3RhcnR1cCBob29rcyBydW4pLlxuICAvL1xuICAvLyBAcGFyYW0gb3B0cyB7T2JqZWN0fSB3aXRoOlxuICAvLyAgIC0gZm9yTG9nZ2VkSW5Vc2VyIHtBcnJheX0gQXJyYXkgb2YgZmllbGRzIHB1Ymxpc2hlZCB0byB0aGUgbG9nZ2VkLWluIHVzZXJcbiAgLy8gICAtIGZvck90aGVyVXNlcnMge0FycmF5fSBBcnJheSBvZiBmaWVsZHMgcHVibGlzaGVkIHRvIHVzZXJzIHRoYXQgYXJlbid0IGxvZ2dlZCBpblxuICBhZGRBdXRvcHVibGlzaEZpZWxkcyhvcHRzKSB7XG4gICAgdGhpcy5fYXV0b3B1Ymxpc2hGaWVsZHMubG9nZ2VkSW5Vc2VyLnB1c2guYXBwbHkoXG4gICAgICB0aGlzLl9hdXRvcHVibGlzaEZpZWxkcy5sb2dnZWRJblVzZXIsIG9wdHMuZm9yTG9nZ2VkSW5Vc2VyKTtcbiAgICB0aGlzLl9hdXRvcHVibGlzaEZpZWxkcy5vdGhlclVzZXJzLnB1c2guYXBwbHkoXG4gICAgICB0aGlzLl9hdXRvcHVibGlzaEZpZWxkcy5vdGhlclVzZXJzLCBvcHRzLmZvck90aGVyVXNlcnMpO1xuICB9O1xuXG4gIC8vIFJlcGxhY2VzIHRoZSBmaWVsZHMgdG8gYmUgYXV0b21hdGljYWxseVxuICAvLyBwdWJsaXNoZWQgd2hlbiB0aGUgdXNlciBsb2dzIGluXG4gIC8vXG4gIC8vIEBwYXJhbSB7TW9uZ29GaWVsZFNwZWNpZmllcn0gZmllbGRzIERpY3Rpb25hcnkgb2YgZmllbGRzIHRvIHJldHVybiBvciBleGNsdWRlLlxuICBzZXREZWZhdWx0UHVibGlzaEZpZWxkcyhmaWVsZHMpIHtcbiAgICB0aGlzLl9kZWZhdWx0UHVibGlzaEZpZWxkcy5wcm9qZWN0aW9uID0gZmllbGRzO1xuICB9O1xuXG4gIC8vL1xuICAvLy8gQUNDT1VOVCBEQVRBXG4gIC8vL1xuXG4gIC8vIEhBQ0s6IFRoaXMgaXMgdXNlZCBieSAnbWV0ZW9yLWFjY291bnRzJyB0byBnZXQgdGhlIGxvZ2luVG9rZW4gZm9yIGFcbiAgLy8gY29ubmVjdGlvbi4gTWF5YmUgdGhlcmUgc2hvdWxkIGJlIGEgcHVibGljIHdheSB0byBkbyB0aGF0LlxuICBfZ2V0QWNjb3VudERhdGEoY29ubmVjdGlvbklkLCBmaWVsZCkge1xuICAgIGNvbnN0IGRhdGEgPSB0aGlzLl9hY2NvdW50RGF0YVtjb25uZWN0aW9uSWRdO1xuICAgIHJldHVybiBkYXRhICYmIGRhdGFbZmllbGRdO1xuICB9O1xuXG4gIF9zZXRBY2NvdW50RGF0YShjb25uZWN0aW9uSWQsIGZpZWxkLCB2YWx1ZSkge1xuICAgIGNvbnN0IGRhdGEgPSB0aGlzLl9hY2NvdW50RGF0YVtjb25uZWN0aW9uSWRdO1xuXG4gICAgLy8gc2FmZXR5IGJlbHQuIHNob3VsZG4ndCBoYXBwZW4uIGFjY291bnREYXRhIGlzIHNldCBpbiBvbkNvbm5lY3Rpb24sXG4gICAgLy8gd2UgZG9uJ3QgaGF2ZSBhIGNvbm5lY3Rpb25JZCB1bnRpbCBpdCBpcyBzZXQuXG4gICAgaWYgKCFkYXRhKVxuICAgICAgcmV0dXJuO1xuXG4gICAgaWYgKHZhbHVlID09PSB1bmRlZmluZWQpXG4gICAgICBkZWxldGUgZGF0YVtmaWVsZF07XG4gICAgZWxzZVxuICAgICAgZGF0YVtmaWVsZF0gPSB2YWx1ZTtcbiAgfTtcblxuICAvLy9cbiAgLy8vIFJFQ09OTkVDVCBUT0tFTlNcbiAgLy8vXG4gIC8vLyBzdXBwb3J0IHJlY29ubmVjdGluZyB1c2luZyBhIG1ldGVvciBsb2dpbiB0b2tlblxuXG4gIF9oYXNoTG9naW5Ub2tlbihsb2dpblRva2VuKSB7XG4gICAgY29uc3QgaGFzaCA9IGNyeXB0by5jcmVhdGVIYXNoKCdzaGEyNTYnKTtcbiAgICBoYXNoLnVwZGF0ZShsb2dpblRva2VuKTtcbiAgICByZXR1cm4gaGFzaC5kaWdlc3QoJ2Jhc2U2NCcpO1xuICB9O1xuXG4gIC8vIHt0b2tlbiwgd2hlbn0gPT4ge2hhc2hlZFRva2VuLCB3aGVufVxuICBfaGFzaFN0YW1wZWRUb2tlbihzdGFtcGVkVG9rZW4pIHtcbiAgICBjb25zdCB7IHRva2VuLCAuLi5oYXNoZWRTdGFtcGVkVG9rZW4gfSA9IHN0YW1wZWRUb2tlbjtcbiAgICByZXR1cm4ge1xuICAgICAgLi4uaGFzaGVkU3RhbXBlZFRva2VuLFxuICAgICAgaGFzaGVkVG9rZW46IHRoaXMuX2hhc2hMb2dpblRva2VuKHRva2VuKVxuICAgIH07XG4gIH07XG5cbiAgLy8gVXNpbmcgJGFkZFRvU2V0IGF2b2lkcyBnZXR0aW5nIGFuIGluZGV4IGVycm9yIGlmIGFub3RoZXIgY2xpZW50XG4gIC8vIGxvZ2dpbmcgaW4gc2ltdWx0YW5lb3VzbHkgaGFzIGFscmVhZHkgaW5zZXJ0ZWQgdGhlIG5ldyBoYXNoZWRcbiAgLy8gdG9rZW4uXG4gIF9pbnNlcnRIYXNoZWRMb2dpblRva2VuKHVzZXJJZCwgaGFzaGVkVG9rZW4sIHF1ZXJ5KSB7XG4gICAgcXVlcnkgPSBxdWVyeSA/IHsgLi4ucXVlcnkgfSA6IHt9O1xuICAgIHF1ZXJ5Ll9pZCA9IHVzZXJJZDtcbiAgICB0aGlzLnVzZXJzLnVwZGF0ZShxdWVyeSwge1xuICAgICAgJGFkZFRvU2V0OiB7XG4gICAgICAgIFwic2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zXCI6IGhhc2hlZFRva2VuXG4gICAgICB9XG4gICAgfSk7XG4gIH07XG5cbiAgLy8gRXhwb3J0ZWQgZm9yIHRlc3RzLlxuICBfaW5zZXJ0TG9naW5Ub2tlbih1c2VySWQsIHN0YW1wZWRUb2tlbiwgcXVlcnkpIHtcbiAgICB0aGlzLl9pbnNlcnRIYXNoZWRMb2dpblRva2VuKFxuICAgICAgdXNlcklkLFxuICAgICAgdGhpcy5faGFzaFN0YW1wZWRUb2tlbihzdGFtcGVkVG9rZW4pLFxuICAgICAgcXVlcnlcbiAgICApO1xuICB9O1xuXG4gIF9jbGVhckFsbExvZ2luVG9rZW5zKHVzZXJJZCkge1xuICAgIHRoaXMudXNlcnMudXBkYXRlKHVzZXJJZCwge1xuICAgICAgJHNldDoge1xuICAgICAgICAnc2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zJzogW11cbiAgICAgIH1cbiAgICB9KTtcbiAgfTtcblxuICAvLyB0ZXN0IGhvb2tcbiAgX2dldFVzZXJPYnNlcnZlKGNvbm5lY3Rpb25JZCkge1xuICAgIHJldHVybiB0aGlzLl91c2VyT2JzZXJ2ZXNGb3JDb25uZWN0aW9uc1tjb25uZWN0aW9uSWRdO1xuICB9O1xuXG4gIC8vIENsZWFuIHVwIHRoaXMgY29ubmVjdGlvbidzIGFzc29jaWF0aW9uIHdpdGggdGhlIHRva2VuOiB0aGF0IGlzLCBzdG9wXG4gIC8vIHRoZSBvYnNlcnZlIHRoYXQgd2Ugc3RhcnRlZCB3aGVuIHdlIGFzc29jaWF0ZWQgdGhlIGNvbm5lY3Rpb24gd2l0aFxuICAvLyB0aGlzIHRva2VuLlxuICBfcmVtb3ZlVG9rZW5Gcm9tQ29ubmVjdGlvbihjb25uZWN0aW9uSWQpIHtcbiAgICBpZiAoaGFzT3duLmNhbGwodGhpcy5fdXNlck9ic2VydmVzRm9yQ29ubmVjdGlvbnMsIGNvbm5lY3Rpb25JZCkpIHtcbiAgICAgIGNvbnN0IG9ic2VydmUgPSB0aGlzLl91c2VyT2JzZXJ2ZXNGb3JDb25uZWN0aW9uc1tjb25uZWN0aW9uSWRdO1xuICAgICAgaWYgKHR5cGVvZiBvYnNlcnZlID09PSAnbnVtYmVyJykge1xuICAgICAgICAvLyBXZSdyZSBpbiB0aGUgcHJvY2VzcyBvZiBzZXR0aW5nIHVwIGFuIG9ic2VydmUgZm9yIHRoaXMgY29ubmVjdGlvbi4gV2VcbiAgICAgICAgLy8gY2FuJ3QgY2xlYW4gdXAgdGhhdCBvYnNlcnZlIHlldCwgYnV0IGlmIHdlIGRlbGV0ZSB0aGUgcGxhY2Vob2xkZXIgZm9yXG4gICAgICAgIC8vIHRoaXMgY29ubmVjdGlvbiwgdGhlbiB0aGUgb2JzZXJ2ZSB3aWxsIGdldCBjbGVhbmVkIHVwIGFzIHNvb24gYXMgaXQgaGFzXG4gICAgICAgIC8vIGJlZW4gc2V0IHVwLlxuICAgICAgICBkZWxldGUgdGhpcy5fdXNlck9ic2VydmVzRm9yQ29ubmVjdGlvbnNbY29ubmVjdGlvbklkXTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGRlbGV0ZSB0aGlzLl91c2VyT2JzZXJ2ZXNGb3JDb25uZWN0aW9uc1tjb25uZWN0aW9uSWRdO1xuICAgICAgICBvYnNlcnZlLnN0b3AoKTtcbiAgICAgIH1cbiAgICB9XG4gIH07XG5cbiAgX2dldExvZ2luVG9rZW4oY29ubmVjdGlvbklkKSB7XG4gICAgcmV0dXJuIHRoaXMuX2dldEFjY291bnREYXRhKGNvbm5lY3Rpb25JZCwgJ2xvZ2luVG9rZW4nKTtcbiAgfTtcblxuICAvLyBuZXdUb2tlbiBpcyBhIGhhc2hlZCB0b2tlbi5cbiAgX3NldExvZ2luVG9rZW4odXNlcklkLCBjb25uZWN0aW9uLCBuZXdUb2tlbikge1xuICAgIHRoaXMuX3JlbW92ZVRva2VuRnJvbUNvbm5lY3Rpb24oY29ubmVjdGlvbi5pZCk7XG4gICAgdGhpcy5fc2V0QWNjb3VudERhdGEoY29ubmVjdGlvbi5pZCwgJ2xvZ2luVG9rZW4nLCBuZXdUb2tlbik7XG5cbiAgICBpZiAobmV3VG9rZW4pIHtcbiAgICAgIC8vIFNldCB1cCBhbiBvYnNlcnZlIGZvciB0aGlzIHRva2VuLiBJZiB0aGUgdG9rZW4gZ29lcyBhd2F5LCB3ZSBuZWVkXG4gICAgICAvLyB0byBjbG9zZSB0aGUgY29ubmVjdGlvbi4gIFdlIGRlZmVyIHRoZSBvYnNlcnZlIGJlY2F1c2UgdGhlcmUnc1xuICAgICAgLy8gbm8gbmVlZCBmb3IgaXQgdG8gYmUgb24gdGhlIGNyaXRpY2FsIHBhdGggZm9yIGxvZ2luOyB3ZSBqdXN0IG5lZWRcbiAgICAgIC8vIHRvIGVuc3VyZSB0aGF0IHRoZSBjb25uZWN0aW9uIHdpbGwgZ2V0IGNsb3NlZCBhdCBzb21lIHBvaW50IGlmXG4gICAgICAvLyB0aGUgdG9rZW4gZ2V0cyBkZWxldGVkLlxuICAgICAgLy9cbiAgICAgIC8vIEluaXRpYWxseSwgd2Ugc2V0IHRoZSBvYnNlcnZlIGZvciB0aGlzIGNvbm5lY3Rpb24gdG8gYSBudW1iZXI7IHRoaXNcbiAgICAgIC8vIHNpZ25pZmllcyB0byBvdGhlciBjb2RlICh3aGljaCBtaWdodCBydW4gd2hpbGUgd2UgeWllbGQpIHRoYXQgd2UgYXJlIGluXG4gICAgICAvLyB0aGUgcHJvY2VzcyBvZiBzZXR0aW5nIHVwIGFuIG9ic2VydmUgZm9yIHRoaXMgY29ubmVjdGlvbi4gT25jZSB0aGVcbiAgICAgIC8vIG9ic2VydmUgaXMgcmVhZHkgdG8gZ28sIHdlIHJlcGxhY2UgdGhlIG51bWJlciB3aXRoIHRoZSByZWFsIG9ic2VydmVcbiAgICAgIC8vIGhhbmRsZSAodW5sZXNzIHRoZSBwbGFjZWhvbGRlciBoYXMgYmVlbiBkZWxldGVkIG9yIHJlcGxhY2VkIGJ5IGFcbiAgICAgIC8vIGRpZmZlcmVudCBwbGFjZWhvbGQgbnVtYmVyLCBzaWduaWZ5aW5nIHRoYXQgdGhlIGNvbm5lY3Rpb24gd2FzIGNsb3NlZFxuICAgICAgLy8gYWxyZWFkeSAtLSBpbiB0aGlzIGNhc2Ugd2UganVzdCBjbGVhbiB1cCB0aGUgb2JzZXJ2ZSB0aGF0IHdlIHN0YXJ0ZWQpLlxuICAgICAgY29uc3QgbXlPYnNlcnZlTnVtYmVyID0gKyt0aGlzLl9uZXh0VXNlck9ic2VydmVOdW1iZXI7XG4gICAgICB0aGlzLl91c2VyT2JzZXJ2ZXNGb3JDb25uZWN0aW9uc1tjb25uZWN0aW9uLmlkXSA9IG15T2JzZXJ2ZU51bWJlcjtcbiAgICAgIE1ldGVvci5kZWZlcigoKSA9PiB7XG4gICAgICAgIC8vIElmIHNvbWV0aGluZyBlbHNlIGhhcHBlbmVkIG9uIHRoaXMgY29ubmVjdGlvbiBpbiB0aGUgbWVhbnRpbWUgKGl0IGdvdFxuICAgICAgICAvLyBjbG9zZWQsIG9yIGFub3RoZXIgY2FsbCB0byBfc2V0TG9naW5Ub2tlbiBoYXBwZW5lZCksIGp1c3QgZG9cbiAgICAgICAgLy8gbm90aGluZy4gV2UgZG9uJ3QgbmVlZCB0byBzdGFydCBhbiBvYnNlcnZlIGZvciBhbiBvbGQgY29ubmVjdGlvbiBvciBvbGRcbiAgICAgICAgLy8gdG9rZW4uXG4gICAgICAgIGlmICh0aGlzLl91c2VyT2JzZXJ2ZXNGb3JDb25uZWN0aW9uc1tjb25uZWN0aW9uLmlkXSAhPT0gbXlPYnNlcnZlTnVtYmVyKSB7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgbGV0IGZvdW5kTWF0Y2hpbmdVc2VyO1xuICAgICAgICAvLyBCZWNhdXNlIHdlIHVwZ3JhZGUgdW5oYXNoZWQgbG9naW4gdG9rZW5zIHRvIGhhc2hlZCB0b2tlbnMgYXRcbiAgICAgICAgLy8gbG9naW4gdGltZSwgc2Vzc2lvbnMgd2lsbCBvbmx5IGJlIGxvZ2dlZCBpbiB3aXRoIGEgaGFzaGVkXG4gICAgICAgIC8vIHRva2VuLiBUaHVzIHdlIG9ubHkgbmVlZCB0byBvYnNlcnZlIGhhc2hlZCB0b2tlbnMgaGVyZS5cbiAgICAgICAgY29uc3Qgb2JzZXJ2ZSA9IHRoaXMudXNlcnMuZmluZCh7XG4gICAgICAgICAgX2lkOiB1c2VySWQsXG4gICAgICAgICAgJ3NlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vucy5oYXNoZWRUb2tlbic6IG5ld1Rva2VuXG4gICAgICAgIH0sIHsgZmllbGRzOiB7IF9pZDogMSB9IH0pLm9ic2VydmVDaGFuZ2VzKHtcbiAgICAgICAgICBhZGRlZDogKCkgPT4ge1xuICAgICAgICAgICAgZm91bmRNYXRjaGluZ1VzZXIgPSB0cnVlO1xuICAgICAgICAgIH0sXG4gICAgICAgICAgcmVtb3ZlZDogY29ubmVjdGlvbi5jbG9zZSxcbiAgICAgICAgICAvLyBUaGUgb25DbG9zZSBjYWxsYmFjayBmb3IgdGhlIGNvbm5lY3Rpb24gdGFrZXMgY2FyZSBvZlxuICAgICAgICAgIC8vIGNsZWFuaW5nIHVwIHRoZSBvYnNlcnZlIGhhbmRsZSBhbmQgYW55IG90aGVyIHN0YXRlIHdlIGhhdmVcbiAgICAgICAgICAvLyBseWluZyBhcm91bmQuXG4gICAgICAgIH0sIHsgbm9uTXV0YXRpbmdDYWxsYmFja3M6IHRydWUgfSk7XG5cbiAgICAgICAgLy8gSWYgdGhlIHVzZXIgcmFuIGFub3RoZXIgbG9naW4gb3IgbG9nb3V0IGNvbW1hbmQgd2Ugd2VyZSB3YWl0aW5nIGZvciB0aGVcbiAgICAgICAgLy8gZGVmZXIgb3IgYWRkZWQgdG8gZmlyZSAoaWUsIGFub3RoZXIgY2FsbCB0byBfc2V0TG9naW5Ub2tlbiBvY2N1cnJlZCksXG4gICAgICAgIC8vIHRoZW4gd2UgbGV0IHRoZSBsYXRlciBvbmUgd2luIChzdGFydCBhbiBvYnNlcnZlLCBldGMpIGFuZCBqdXN0IHN0b3Agb3VyXG4gICAgICAgIC8vIG9ic2VydmUgbm93LlxuICAgICAgICAvL1xuICAgICAgICAvLyBTaW1pbGFybHksIGlmIHRoZSBjb25uZWN0aW9uIHdhcyBhbHJlYWR5IGNsb3NlZCwgdGhlbiB0aGUgb25DbG9zZVxuICAgICAgICAvLyBjYWxsYmFjayB3b3VsZCBoYXZlIGNhbGxlZCBfcmVtb3ZlVG9rZW5Gcm9tQ29ubmVjdGlvbiBhbmQgdGhlcmUgd29uJ3RcbiAgICAgICAgLy8gYmUgYW4gZW50cnkgaW4gX3VzZXJPYnNlcnZlc0ZvckNvbm5lY3Rpb25zLiBXZSBjYW4gc3RvcCB0aGUgb2JzZXJ2ZS5cbiAgICAgICAgaWYgKHRoaXMuX3VzZXJPYnNlcnZlc0ZvckNvbm5lY3Rpb25zW2Nvbm5lY3Rpb24uaWRdICE9PSBteU9ic2VydmVOdW1iZXIpIHtcbiAgICAgICAgICBvYnNlcnZlLnN0b3AoKTtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICB0aGlzLl91c2VyT2JzZXJ2ZXNGb3JDb25uZWN0aW9uc1tjb25uZWN0aW9uLmlkXSA9IG9ic2VydmU7XG5cbiAgICAgICAgaWYgKCEgZm91bmRNYXRjaGluZ1VzZXIpIHtcbiAgICAgICAgICAvLyBXZSd2ZSBzZXQgdXAgYW4gb2JzZXJ2ZSBvbiB0aGUgdXNlciBhc3NvY2lhdGVkIHdpdGggYG5ld1Rva2VuYCxcbiAgICAgICAgICAvLyBzbyBpZiB0aGUgbmV3IHRva2VuIGlzIHJlbW92ZWQgZnJvbSB0aGUgZGF0YWJhc2UsIHdlJ2xsIGNsb3NlXG4gICAgICAgICAgLy8gdGhlIGNvbm5lY3Rpb24uIEJ1dCB0aGUgdG9rZW4gbWlnaHQgaGF2ZSBhbHJlYWR5IGJlZW4gZGVsZXRlZFxuICAgICAgICAgIC8vIGJlZm9yZSB3ZSBzZXQgdXAgdGhlIG9ic2VydmUsIHdoaWNoIHdvdWxkbid0IGhhdmUgY2xvc2VkIHRoZVxuICAgICAgICAgIC8vIGNvbm5lY3Rpb24gYmVjYXVzZSB0aGUgb2JzZXJ2ZSB3YXNuJ3QgcnVubmluZyB5ZXQuXG4gICAgICAgICAgY29ubmVjdGlvbi5jbG9zZSgpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG4gIH07XG5cbiAgLy8gKEFsc28gdXNlZCBieSBNZXRlb3IgQWNjb3VudHMgc2VydmVyIGFuZCB0ZXN0cykuXG4gIC8vXG4gIF9nZW5lcmF0ZVN0YW1wZWRMb2dpblRva2VuKCkge1xuICAgIHJldHVybiB7XG4gICAgICB0b2tlbjogUmFuZG9tLnNlY3JldCgpLFxuICAgICAgd2hlbjogbmV3IERhdGVcbiAgICB9O1xuICB9O1xuXG4gIC8vL1xuICAvLy8gVE9LRU4gRVhQSVJBVElPTlxuICAvLy9cblxuICAvLyBEZWxldGVzIGV4cGlyZWQgcGFzc3dvcmQgcmVzZXQgdG9rZW5zIGZyb20gdGhlIGRhdGFiYXNlLlxuICAvL1xuICAvLyBFeHBvcnRlZCBmb3IgdGVzdHMuIEFsc28sIHRoZSBhcmd1bWVudHMgYXJlIG9ubHkgdXNlZCBieVxuICAvLyB0ZXN0cy4gb2xkZXN0VmFsaWREYXRlIGlzIHNpbXVsYXRlIGV4cGlyaW5nIHRva2VucyB3aXRob3V0IHdhaXRpbmdcbiAgLy8gZm9yIHRoZW0gdG8gYWN0dWFsbHkgZXhwaXJlLiB1c2VySWQgaXMgdXNlZCBieSB0ZXN0cyB0byBvbmx5IGV4cGlyZVxuICAvLyB0b2tlbnMgZm9yIHRoZSB0ZXN0IHVzZXIuXG4gIF9leHBpcmVQYXNzd29yZFJlc2V0VG9rZW5zKG9sZGVzdFZhbGlkRGF0ZSwgdXNlcklkKSB7XG4gICAgY29uc3QgdG9rZW5MaWZldGltZU1zID0gdGhpcy5fZ2V0UGFzc3dvcmRSZXNldFRva2VuTGlmZXRpbWVNcygpO1xuXG4gICAgLy8gd2hlbiBjYWxsaW5nIGZyb20gYSB0ZXN0IHdpdGggZXh0cmEgYXJndW1lbnRzLCB5b3UgbXVzdCBzcGVjaWZ5IGJvdGghXG4gICAgaWYgKChvbGRlc3RWYWxpZERhdGUgJiYgIXVzZXJJZCkgfHwgKCFvbGRlc3RWYWxpZERhdGUgJiYgdXNlcklkKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwiQmFkIHRlc3QuIE11c3Qgc3BlY2lmeSBib3RoIG9sZGVzdFZhbGlkRGF0ZSBhbmQgdXNlcklkLlwiKTtcbiAgICB9XG5cbiAgICBvbGRlc3RWYWxpZERhdGUgPSBvbGRlc3RWYWxpZERhdGUgfHxcbiAgICAgIChuZXcgRGF0ZShuZXcgRGF0ZSgpIC0gdG9rZW5MaWZldGltZU1zKSk7XG5cbiAgICBjb25zdCB0b2tlbkZpbHRlciA9IHtcbiAgICAgICRvcjogW1xuICAgICAgICB7IFwic2VydmljZXMucGFzc3dvcmQucmVzZXQucmVhc29uXCI6IFwicmVzZXRcIn0sXG4gICAgICAgIHsgXCJzZXJ2aWNlcy5wYXNzd29yZC5yZXNldC5yZWFzb25cIjogeyRleGlzdHM6IGZhbHNlfX1cbiAgICAgIF1cbiAgICB9O1xuXG4gICAgZXhwaXJlUGFzc3dvcmRUb2tlbih0aGlzLCBvbGRlc3RWYWxpZERhdGUsIHRva2VuRmlsdGVyLCB1c2VySWQpO1xuICB9XG5cbiAgLy8gRGVsZXRlcyBleHBpcmVkIHBhc3N3b3JkIGVucm9sbCB0b2tlbnMgZnJvbSB0aGUgZGF0YWJhc2UuXG4gIC8vXG4gIC8vIEV4cG9ydGVkIGZvciB0ZXN0cy4gQWxzbywgdGhlIGFyZ3VtZW50cyBhcmUgb25seSB1c2VkIGJ5XG4gIC8vIHRlc3RzLiBvbGRlc3RWYWxpZERhdGUgaXMgc2ltdWxhdGUgZXhwaXJpbmcgdG9rZW5zIHdpdGhvdXQgd2FpdGluZ1xuICAvLyBmb3IgdGhlbSB0byBhY3R1YWxseSBleHBpcmUuIHVzZXJJZCBpcyB1c2VkIGJ5IHRlc3RzIHRvIG9ubHkgZXhwaXJlXG4gIC8vIHRva2VucyBmb3IgdGhlIHRlc3QgdXNlci5cbiAgX2V4cGlyZVBhc3N3b3JkRW5yb2xsVG9rZW5zKG9sZGVzdFZhbGlkRGF0ZSwgdXNlcklkKSB7XG4gICAgY29uc3QgdG9rZW5MaWZldGltZU1zID0gdGhpcy5fZ2V0UGFzc3dvcmRFbnJvbGxUb2tlbkxpZmV0aW1lTXMoKTtcblxuICAgIC8vIHdoZW4gY2FsbGluZyBmcm9tIGEgdGVzdCB3aXRoIGV4dHJhIGFyZ3VtZW50cywgeW91IG11c3Qgc3BlY2lmeSBib3RoIVxuICAgIGlmICgob2xkZXN0VmFsaWREYXRlICYmICF1c2VySWQpIHx8ICghb2xkZXN0VmFsaWREYXRlICYmIHVzZXJJZCkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIkJhZCB0ZXN0LiBNdXN0IHNwZWNpZnkgYm90aCBvbGRlc3RWYWxpZERhdGUgYW5kIHVzZXJJZC5cIik7XG4gICAgfVxuXG4gICAgb2xkZXN0VmFsaWREYXRlID0gb2xkZXN0VmFsaWREYXRlIHx8XG4gICAgICAobmV3IERhdGUobmV3IERhdGUoKSAtIHRva2VuTGlmZXRpbWVNcykpO1xuXG4gICAgY29uc3QgdG9rZW5GaWx0ZXIgPSB7XG4gICAgICBcInNlcnZpY2VzLnBhc3N3b3JkLmVucm9sbC5yZWFzb25cIjogXCJlbnJvbGxcIlxuICAgIH07XG5cbiAgICBleHBpcmVQYXNzd29yZFRva2VuKHRoaXMsIG9sZGVzdFZhbGlkRGF0ZSwgdG9rZW5GaWx0ZXIsIHVzZXJJZCk7XG4gIH1cblxuICAvLyBEZWxldGVzIGV4cGlyZWQgdG9rZW5zIGZyb20gdGhlIGRhdGFiYXNlIGFuZCBjbG9zZXMgYWxsIG9wZW4gY29ubmVjdGlvbnNcbiAgLy8gYXNzb2NpYXRlZCB3aXRoIHRoZXNlIHRva2Vucy5cbiAgLy9cbiAgLy8gRXhwb3J0ZWQgZm9yIHRlc3RzLiBBbHNvLCB0aGUgYXJndW1lbnRzIGFyZSBvbmx5IHVzZWQgYnlcbiAgLy8gdGVzdHMuIG9sZGVzdFZhbGlkRGF0ZSBpcyBzaW11bGF0ZSBleHBpcmluZyB0b2tlbnMgd2l0aG91dCB3YWl0aW5nXG4gIC8vIGZvciB0aGVtIHRvIGFjdHVhbGx5IGV4cGlyZS4gdXNlcklkIGlzIHVzZWQgYnkgdGVzdHMgdG8gb25seSBleHBpcmVcbiAgLy8gdG9rZW5zIGZvciB0aGUgdGVzdCB1c2VyLlxuICBfZXhwaXJlVG9rZW5zKG9sZGVzdFZhbGlkRGF0ZSwgdXNlcklkKSB7XG4gICAgY29uc3QgdG9rZW5MaWZldGltZU1zID0gdGhpcy5fZ2V0VG9rZW5MaWZldGltZU1zKCk7XG5cbiAgICAvLyB3aGVuIGNhbGxpbmcgZnJvbSBhIHRlc3Qgd2l0aCBleHRyYSBhcmd1bWVudHMsIHlvdSBtdXN0IHNwZWNpZnkgYm90aCFcbiAgICBpZiAoKG9sZGVzdFZhbGlkRGF0ZSAmJiAhdXNlcklkKSB8fCAoIW9sZGVzdFZhbGlkRGF0ZSAmJiB1c2VySWQpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJCYWQgdGVzdC4gTXVzdCBzcGVjaWZ5IGJvdGggb2xkZXN0VmFsaWREYXRlIGFuZCB1c2VySWQuXCIpO1xuICAgIH1cblxuICAgIG9sZGVzdFZhbGlkRGF0ZSA9IG9sZGVzdFZhbGlkRGF0ZSB8fFxuICAgICAgKG5ldyBEYXRlKG5ldyBEYXRlKCkgLSB0b2tlbkxpZmV0aW1lTXMpKTtcbiAgICBjb25zdCB1c2VyRmlsdGVyID0gdXNlcklkID8ge19pZDogdXNlcklkfSA6IHt9O1xuXG5cbiAgICAvLyBCYWNrd2FyZHMgY29tcGF0aWJsZSB3aXRoIG9sZGVyIHZlcnNpb25zIG9mIG1ldGVvciB0aGF0IHN0b3JlZCBsb2dpbiB0b2tlblxuICAgIC8vIHRpbWVzdGFtcHMgYXMgbnVtYmVycy5cbiAgICB0aGlzLnVzZXJzLnVwZGF0ZSh7IC4uLnVzZXJGaWx0ZXIsXG4gICAgICAkb3I6IFtcbiAgICAgICAgeyBcInNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vucy53aGVuXCI6IHsgJGx0OiBvbGRlc3RWYWxpZERhdGUgfSB9LFxuICAgICAgICB7IFwic2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zLndoZW5cIjogeyAkbHQ6ICtvbGRlc3RWYWxpZERhdGUgfSB9XG4gICAgICBdXG4gICAgfSwge1xuICAgICAgJHB1bGw6IHtcbiAgICAgICAgXCJzZXJ2aWNlcy5yZXN1bWUubG9naW5Ub2tlbnNcIjoge1xuICAgICAgICAgICRvcjogW1xuICAgICAgICAgICAgeyB3aGVuOiB7ICRsdDogb2xkZXN0VmFsaWREYXRlIH0gfSxcbiAgICAgICAgICAgIHsgd2hlbjogeyAkbHQ6ICtvbGRlc3RWYWxpZERhdGUgfSB9XG4gICAgICAgICAgXVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfSwgeyBtdWx0aTogdHJ1ZSB9KTtcbiAgICAvLyBUaGUgb2JzZXJ2ZSBvbiBNZXRlb3IudXNlcnMgd2lsbCB0YWtlIGNhcmUgb2YgY2xvc2luZyBjb25uZWN0aW9ucyBmb3JcbiAgICAvLyBleHBpcmVkIHRva2Vucy5cbiAgfTtcblxuICAvLyBAb3ZlcnJpZGUgZnJvbSBhY2NvdW50c19jb21tb24uanNcbiAgY29uZmlnKG9wdGlvbnMpIHtcbiAgICAvLyBDYWxsIHRoZSBvdmVycmlkZGVuIGltcGxlbWVudGF0aW9uIG9mIHRoZSBtZXRob2QuXG4gICAgY29uc3Qgc3VwZXJSZXN1bHQgPSBBY2NvdW50c0NvbW1vbi5wcm90b3R5cGUuY29uZmlnLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XG5cbiAgICAvLyBJZiB0aGUgdXNlciBzZXQgbG9naW5FeHBpcmF0aW9uSW5EYXlzIHRvIG51bGwsIHRoZW4gd2UgbmVlZCB0byBjbGVhciB0aGVcbiAgICAvLyB0aW1lciB0aGF0IHBlcmlvZGljYWxseSBleHBpcmVzIHRva2Vucy5cbiAgICBpZiAoaGFzT3duLmNhbGwodGhpcy5fb3B0aW9ucywgJ2xvZ2luRXhwaXJhdGlvbkluRGF5cycpICYmXG4gICAgICB0aGlzLl9vcHRpb25zLmxvZ2luRXhwaXJhdGlvbkluRGF5cyA9PT0gbnVsbCAmJlxuICAgICAgdGhpcy5leHBpcmVUb2tlbkludGVydmFsKSB7XG4gICAgICBNZXRlb3IuY2xlYXJJbnRlcnZhbCh0aGlzLmV4cGlyZVRva2VuSW50ZXJ2YWwpO1xuICAgICAgdGhpcy5leHBpcmVUb2tlbkludGVydmFsID0gbnVsbDtcbiAgICB9XG5cbiAgICByZXR1cm4gc3VwZXJSZXN1bHQ7XG4gIH07XG5cbiAgLy8gQ2FsbGVkIGJ5IGFjY291bnRzLXBhc3N3b3JkXG4gIGluc2VydFVzZXJEb2Mob3B0aW9ucywgdXNlcikge1xuICAgIC8vIC0gY2xvbmUgdXNlciBkb2N1bWVudCwgdG8gcHJvdGVjdCBmcm9tIG1vZGlmaWNhdGlvblxuICAgIC8vIC0gYWRkIGNyZWF0ZWRBdCB0aW1lc3RhbXBcbiAgICAvLyAtIHByZXBhcmUgYW4gX2lkLCBzbyB0aGF0IHlvdSBjYW4gbW9kaWZ5IG90aGVyIGNvbGxlY3Rpb25zIChlZ1xuICAgIC8vIGNyZWF0ZSBhIGZpcnN0IHRhc2sgZm9yIGV2ZXJ5IG5ldyB1c2VyKVxuICAgIC8vXG4gICAgLy8gWFhYIElmIHRoZSBvbkNyZWF0ZVVzZXIgb3IgdmFsaWRhdGVOZXdVc2VyIGhvb2tzIGZhaWwsIHdlIG1pZ2h0XG4gICAgLy8gZW5kIHVwIGhhdmluZyBtb2RpZmllZCBzb21lIG90aGVyIGNvbGxlY3Rpb25cbiAgICAvLyBpbmFwcHJvcHJpYXRlbHkuIFRoZSBzb2x1dGlvbiBpcyBwcm9iYWJseSB0byBoYXZlIG9uQ3JlYXRlVXNlclxuICAgIC8vIGFjY2VwdCB0d28gY2FsbGJhY2tzIC0gb25lIHRoYXQgZ2V0cyBjYWxsZWQgYmVmb3JlIGluc2VydGluZ1xuICAgIC8vIHRoZSB1c2VyIGRvY3VtZW50IChpbiB3aGljaCB5b3UgY2FuIG1vZGlmeSBpdHMgY29udGVudHMpLCBhbmRcbiAgICAvLyBvbmUgdGhhdCBnZXRzIGNhbGxlZCBhZnRlciAoaW4gd2hpY2ggeW91IHNob3VsZCBjaGFuZ2Ugb3RoZXJcbiAgICAvLyBjb2xsZWN0aW9ucylcbiAgICB1c2VyID0ge1xuICAgICAgY3JlYXRlZEF0OiBuZXcgRGF0ZSgpLFxuICAgICAgX2lkOiBSYW5kb20uaWQoKSxcbiAgICAgIC4uLnVzZXIsXG4gICAgfTtcblxuICAgIGlmICh1c2VyLnNlcnZpY2VzKSB7XG4gICAgICBPYmplY3Qua2V5cyh1c2VyLnNlcnZpY2VzKS5mb3JFYWNoKHNlcnZpY2UgPT5cbiAgICAgICAgcGluRW5jcnlwdGVkRmllbGRzVG9Vc2VyKHVzZXIuc2VydmljZXNbc2VydmljZV0sIHVzZXIuX2lkKVxuICAgICAgKTtcbiAgICB9XG5cbiAgICBsZXQgZnVsbFVzZXI7XG4gICAgaWYgKHRoaXMuX29uQ3JlYXRlVXNlckhvb2spIHtcbiAgICAgIGZ1bGxVc2VyID0gdGhpcy5fb25DcmVhdGVVc2VySG9vayhvcHRpb25zLCB1c2VyKTtcblxuICAgICAgLy8gVGhpcyBpcyAqbm90KiBwYXJ0IG9mIHRoZSBBUEkuIFdlIG5lZWQgdGhpcyBiZWNhdXNlIHdlIGNhbid0IGlzb2xhdGVcbiAgICAgIC8vIHRoZSBnbG9iYWwgc2VydmVyIGVudmlyb25tZW50IGJldHdlZW4gdGVzdHMsIG1lYW5pbmcgd2UgY2FuJ3QgdGVzdFxuICAgICAgLy8gYm90aCBoYXZpbmcgYSBjcmVhdGUgdXNlciBob29rIHNldCBhbmQgbm90IGhhdmluZyBvbmUgc2V0LlxuICAgICAgaWYgKGZ1bGxVc2VyID09PSAnVEVTVCBERUZBVUxUIEhPT0snKVxuICAgICAgICBmdWxsVXNlciA9IGRlZmF1bHRDcmVhdGVVc2VySG9vayhvcHRpb25zLCB1c2VyKTtcbiAgICB9IGVsc2Uge1xuICAgICAgZnVsbFVzZXIgPSBkZWZhdWx0Q3JlYXRlVXNlckhvb2sob3B0aW9ucywgdXNlcik7XG4gICAgfVxuXG4gICAgdGhpcy5fdmFsaWRhdGVOZXdVc2VySG9va3MuZm9yRWFjaChob29rID0+IHtcbiAgICAgIGlmICghIGhvb2soZnVsbFVzZXIpKVxuICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMywgXCJVc2VyIHZhbGlkYXRpb24gZmFpbGVkXCIpO1xuICAgIH0pO1xuXG4gICAgbGV0IHVzZXJJZDtcbiAgICB0cnkge1xuICAgICAgdXNlcklkID0gdGhpcy51c2Vycy5pbnNlcnQoZnVsbFVzZXIpO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIC8vIFhYWCBzdHJpbmcgcGFyc2luZyBzdWNrcywgbWF5YmVcbiAgICAgIC8vIGh0dHBzOi8vamlyYS5tb25nb2RiLm9yZy9icm93c2UvU0VSVkVSLTMwNjkgd2lsbCBnZXQgZml4ZWQgb25lIGRheVxuICAgICAgLy8gaHR0cHM6Ly9qaXJhLm1vbmdvZGIub3JnL2Jyb3dzZS9TRVJWRVItNDYzN1xuICAgICAgaWYgKCFlLmVycm1zZykgdGhyb3cgZTtcbiAgICAgIGlmIChlLmVycm1zZy5pbmNsdWRlcygnZW1haWxzLmFkZHJlc3MnKSlcbiAgICAgICAgdGhyb3cgbmV3IE1ldGVvci5FcnJvcig0MDMsIFwiRW1haWwgYWxyZWFkeSBleGlzdHMuXCIpO1xuICAgICAgaWYgKGUuZXJybXNnLmluY2x1ZGVzKCd1c2VybmFtZScpKVxuICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMywgXCJVc2VybmFtZSBhbHJlYWR5IGV4aXN0cy5cIik7XG4gICAgICB0aHJvdyBlO1xuICAgIH1cbiAgICByZXR1cm4gdXNlcklkO1xuICB9O1xuXG4gIC8vIEhlbHBlciBmdW5jdGlvbjogcmV0dXJucyBmYWxzZSBpZiBlbWFpbCBkb2VzIG5vdCBtYXRjaCBjb21wYW55IGRvbWFpbiBmcm9tXG4gIC8vIHRoZSBjb25maWd1cmF0aW9uLlxuICBfdGVzdEVtYWlsRG9tYWluKGVtYWlsKSB7XG4gICAgY29uc3QgZG9tYWluID0gdGhpcy5fb3B0aW9ucy5yZXN0cmljdENyZWF0aW9uQnlFbWFpbERvbWFpbjtcblxuICAgIHJldHVybiAhZG9tYWluIHx8XG4gICAgICAodHlwZW9mIGRvbWFpbiA9PT0gJ2Z1bmN0aW9uJyAmJiBkb21haW4oZW1haWwpKSB8fFxuICAgICAgKHR5cGVvZiBkb21haW4gPT09ICdzdHJpbmcnICYmXG4gICAgICAgIChuZXcgUmVnRXhwKGBAJHtNZXRlb3IuX2VzY2FwZVJlZ0V4cChkb21haW4pfSRgLCAnaScpKS50ZXN0KGVtYWlsKSk7XG4gIH07XG5cbiAgLy8vXG4gIC8vLyBDTEVBTiBVUCBGT1IgYGxvZ291dE90aGVyQ2xpZW50c2BcbiAgLy8vXG5cbiAgX2RlbGV0ZVNhdmVkVG9rZW5zRm9yVXNlcih1c2VySWQsIHRva2Vuc1RvRGVsZXRlKSB7XG4gICAgaWYgKHRva2Vuc1RvRGVsZXRlKSB7XG4gICAgICB0aGlzLnVzZXJzLnVwZGF0ZSh1c2VySWQsIHtcbiAgICAgICAgJHVuc2V0OiB7XG4gICAgICAgICAgXCJzZXJ2aWNlcy5yZXN1bWUuaGF2ZUxvZ2luVG9rZW5zVG9EZWxldGVcIjogMSxcbiAgICAgICAgICBcInNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vuc1RvRGVsZXRlXCI6IDFcbiAgICAgICAgfSxcbiAgICAgICAgJHB1bGxBbGw6IHtcbiAgICAgICAgICBcInNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vuc1wiOiB0b2tlbnNUb0RlbGV0ZVxuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG4gIH07XG5cbiAgX2RlbGV0ZVNhdmVkVG9rZW5zRm9yQWxsVXNlcnNPblN0YXJ0dXAoKSB7XG4gICAgLy8gSWYgd2UgZmluZCB1c2VycyB3aG8gaGF2ZSBzYXZlZCB0b2tlbnMgdG8gZGVsZXRlIG9uIHN0YXJ0dXAsIGRlbGV0ZVxuICAgIC8vIHRoZW0gbm93LiBJdCdzIHBvc3NpYmxlIHRoYXQgdGhlIHNlcnZlciBjb3VsZCBoYXZlIGNyYXNoZWQgYW5kIGNvbWVcbiAgICAvLyBiYWNrIHVwIGJlZm9yZSBuZXcgdG9rZW5zIGFyZSBmb3VuZCBpbiBsb2NhbFN0b3JhZ2UsIGJ1dCB0aGlzXG4gICAgLy8gc2hvdWxkbid0IGhhcHBlbiB2ZXJ5IG9mdGVuLiBXZSBzaG91bGRuJ3QgcHV0IGEgZGVsYXkgaGVyZSBiZWNhdXNlXG4gICAgLy8gdGhhdCB3b3VsZCBnaXZlIGEgbG90IG9mIHBvd2VyIHRvIGFuIGF0dGFja2VyIHdpdGggYSBzdG9sZW4gbG9naW5cbiAgICAvLyB0b2tlbiBhbmQgdGhlIGFiaWxpdHkgdG8gY3Jhc2ggdGhlIHNlcnZlci5cbiAgICBNZXRlb3Iuc3RhcnR1cCgoKSA9PiB7XG4gICAgICB0aGlzLnVzZXJzLmZpbmQoe1xuICAgICAgICBcInNlcnZpY2VzLnJlc3VtZS5oYXZlTG9naW5Ub2tlbnNUb0RlbGV0ZVwiOiB0cnVlXG4gICAgICB9LCB7ZmllbGRzOiB7XG4gICAgICAgICAgXCJzZXJ2aWNlcy5yZXN1bWUubG9naW5Ub2tlbnNUb0RlbGV0ZVwiOiAxXG4gICAgICAgIH19KS5mb3JFYWNoKHVzZXIgPT4ge1xuICAgICAgICB0aGlzLl9kZWxldGVTYXZlZFRva2Vuc0ZvclVzZXIoXG4gICAgICAgICAgdXNlci5faWQsXG4gICAgICAgICAgdXNlci5zZXJ2aWNlcy5yZXN1bWUubG9naW5Ub2tlbnNUb0RlbGV0ZVxuICAgICAgICApO1xuICAgICAgfSk7XG4gICAgfSk7XG4gIH07XG5cbiAgLy8vXG4gIC8vLyBNQU5BR0lORyBVU0VSIE9CSkVDVFNcbiAgLy8vXG5cbiAgLy8gVXBkYXRlcyBvciBjcmVhdGVzIGEgdXNlciBhZnRlciB3ZSBhdXRoZW50aWNhdGUgd2l0aCBhIDNyZCBwYXJ0eS5cbiAgLy9cbiAgLy8gQHBhcmFtIHNlcnZpY2VOYW1lIHtTdHJpbmd9IFNlcnZpY2UgbmFtZSAoZWcsIHR3aXR0ZXIpLlxuICAvLyBAcGFyYW0gc2VydmljZURhdGEge09iamVjdH0gRGF0YSB0byBzdG9yZSBpbiB0aGUgdXNlcidzIHJlY29yZFxuICAvLyAgICAgICAgdW5kZXIgc2VydmljZXNbc2VydmljZU5hbWVdLiBNdXN0IGluY2x1ZGUgYW4gXCJpZFwiIGZpZWxkXG4gIC8vICAgICAgICB3aGljaCBpcyBhIHVuaXF1ZSBpZGVudGlmaWVyIGZvciB0aGUgdXNlciBpbiB0aGUgc2VydmljZS5cbiAgLy8gQHBhcmFtIG9wdGlvbnMge09iamVjdCwgb3B0aW9uYWx9IE90aGVyIG9wdGlvbnMgdG8gcGFzcyB0byBpbnNlcnRVc2VyRG9jXG4gIC8vICAgICAgICAoZWcsIHByb2ZpbGUpXG4gIC8vIEByZXR1cm5zIHtPYmplY3R9IE9iamVjdCB3aXRoIHRva2VuIGFuZCBpZCBrZXlzLCBsaWtlIHRoZSByZXN1bHRcbiAgLy8gICAgICAgIG9mIHRoZSBcImxvZ2luXCIgbWV0aG9kLlxuICAvL1xuICB1cGRhdGVPckNyZWF0ZVVzZXJGcm9tRXh0ZXJuYWxTZXJ2aWNlKFxuICAgIHNlcnZpY2VOYW1lLFxuICAgIHNlcnZpY2VEYXRhLFxuICAgIG9wdGlvbnNcbiAgKSB7XG4gICAgb3B0aW9ucyA9IHsgLi4ub3B0aW9ucyB9O1xuXG4gICAgaWYgKHNlcnZpY2VOYW1lID09PSBcInBhc3N3b3JkXCIgfHwgc2VydmljZU5hbWUgPT09IFwicmVzdW1lXCIpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgXCJDYW4ndCB1c2UgdXBkYXRlT3JDcmVhdGVVc2VyRnJvbUV4dGVybmFsU2VydmljZSB3aXRoIGludGVybmFsIHNlcnZpY2UgXCJcbiAgICAgICAgKyBzZXJ2aWNlTmFtZSk7XG4gICAgfVxuICAgIGlmICghaGFzT3duLmNhbGwoc2VydmljZURhdGEsICdpZCcpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgIGBTZXJ2aWNlIGRhdGEgZm9yIHNlcnZpY2UgJHtzZXJ2aWNlTmFtZX0gbXVzdCBpbmNsdWRlIGlkYCk7XG4gICAgfVxuXG4gICAgLy8gTG9vayBmb3IgYSB1c2VyIHdpdGggdGhlIGFwcHJvcHJpYXRlIHNlcnZpY2UgdXNlciBpZC5cbiAgICBjb25zdCBzZWxlY3RvciA9IHt9O1xuICAgIGNvbnN0IHNlcnZpY2VJZEtleSA9IGBzZXJ2aWNlcy4ke3NlcnZpY2VOYW1lfS5pZGA7XG5cbiAgICAvLyBYWFggVGVtcG9yYXJ5IHNwZWNpYWwgY2FzZSBmb3IgVHdpdHRlci4gKElzc3VlICM2MjkpXG4gICAgLy8gICBUaGUgc2VydmljZURhdGEuaWQgd2lsbCBiZSBhIHN0cmluZyByZXByZXNlbnRhdGlvbiBvZiBhbiBpbnRlZ2VyLlxuICAgIC8vICAgV2Ugd2FudCBpdCB0byBtYXRjaCBlaXRoZXIgYSBzdG9yZWQgc3RyaW5nIG9yIGludCByZXByZXNlbnRhdGlvbi5cbiAgICAvLyAgIFRoaXMgaXMgdG8gY2F0ZXIgdG8gZWFybGllciB2ZXJzaW9ucyBvZiBNZXRlb3Igc3RvcmluZyB0d2l0dGVyXG4gICAgLy8gICB1c2VyIElEcyBpbiBudW1iZXIgZm9ybSwgYW5kIHJlY2VudCB2ZXJzaW9ucyBzdG9yaW5nIHRoZW0gYXMgc3RyaW5ncy5cbiAgICAvLyAgIFRoaXMgY2FuIGJlIHJlbW92ZWQgb25jZSBtaWdyYXRpb24gdGVjaG5vbG9neSBpcyBpbiBwbGFjZSwgYW5kIHR3aXR0ZXJcbiAgICAvLyAgIHVzZXJzIHN0b3JlZCB3aXRoIGludGVnZXIgSURzIGhhdmUgYmVlbiBtaWdyYXRlZCB0byBzdHJpbmcgSURzLlxuICAgIGlmIChzZXJ2aWNlTmFtZSA9PT0gXCJ0d2l0dGVyXCIgJiYgIWlzTmFOKHNlcnZpY2VEYXRhLmlkKSkge1xuICAgICAgc2VsZWN0b3JbXCIkb3JcIl0gPSBbe30se31dO1xuICAgICAgc2VsZWN0b3JbXCIkb3JcIl1bMF1bc2VydmljZUlkS2V5XSA9IHNlcnZpY2VEYXRhLmlkO1xuICAgICAgc2VsZWN0b3JbXCIkb3JcIl1bMV1bc2VydmljZUlkS2V5XSA9IHBhcnNlSW50KHNlcnZpY2VEYXRhLmlkLCAxMCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHNlbGVjdG9yW3NlcnZpY2VJZEtleV0gPSBzZXJ2aWNlRGF0YS5pZDtcbiAgICB9XG5cbiAgICBsZXQgdXNlciA9IHRoaXMudXNlcnMuZmluZE9uZShzZWxlY3Rvciwge2ZpZWxkczogdGhpcy5fb3B0aW9ucy5kZWZhdWx0RmllbGRTZWxlY3Rvcn0pO1xuXG4gICAgLy8gQ2hlY2sgdG8gc2VlIGlmIHRoZSBkZXZlbG9wZXIgaGFzIGEgY3VzdG9tIHdheSB0byBmaW5kIHRoZSB1c2VyIG91dHNpZGVcbiAgICAvLyBvZiB0aGUgZ2VuZXJhbCBzZWxlY3RvcnMgYWJvdmUuXG4gICAgaWYgKCF1c2VyICYmIHRoaXMuX2FkZGl0aW9uYWxGaW5kVXNlck9uRXh0ZXJuYWxMb2dpbikge1xuICAgICAgdXNlciA9IHRoaXMuX2FkZGl0aW9uYWxGaW5kVXNlck9uRXh0ZXJuYWxMb2dpbih7c2VydmljZU5hbWUsIHNlcnZpY2VEYXRhLCBvcHRpb25zfSlcbiAgICB9XG5cbiAgICAvLyBCZWZvcmUgY29udGludWluZywgcnVuIHVzZXIgaG9vayB0byBzZWUgaWYgd2Ugc2hvdWxkIGNvbnRpbnVlXG4gICAgaWYgKHRoaXMuX2JlZm9yZUV4dGVybmFsTG9naW5Ib29rICYmICF0aGlzLl9iZWZvcmVFeHRlcm5hbExvZ2luSG9vayhzZXJ2aWNlTmFtZSwgc2VydmljZURhdGEsIHVzZXIpKSB7XG4gICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMywgXCJMb2dpbiBmb3JiaWRkZW5cIik7XG4gICAgfVxuXG4gICAgLy8gV2hlbiBjcmVhdGluZyBhIG5ldyB1c2VyIHdlIHBhc3MgdGhyb3VnaCBhbGwgb3B0aW9ucy4gV2hlbiB1cGRhdGluZyBhblxuICAgIC8vIGV4aXN0aW5nIHVzZXIsIGJ5IGRlZmF1bHQgd2Ugb25seSBwcm9jZXNzL3Bhc3MgdGhyb3VnaCB0aGUgc2VydmljZURhdGFcbiAgICAvLyAoZWcsIHNvIHRoYXQgd2Uga2VlcCBhbiB1bmV4cGlyZWQgYWNjZXNzIHRva2VuIGFuZCBkb24ndCBjYWNoZSBvbGQgZW1haWxcbiAgICAvLyBhZGRyZXNzZXMgaW4gc2VydmljZURhdGEuZW1haWwpLiBUaGUgb25FeHRlcm5hbExvZ2luIGhvb2sgY2FuIGJlIHVzZWQgd2hlblxuICAgIC8vIGNyZWF0aW5nIG9yIHVwZGF0aW5nIGEgdXNlciwgdG8gbW9kaWZ5IG9yIHBhc3MgdGhyb3VnaCBtb3JlIG9wdGlvbnMgYXNcbiAgICAvLyBuZWVkZWQuXG4gICAgbGV0IG9wdHMgPSB1c2VyID8ge30gOiBvcHRpb25zO1xuICAgIGlmICh0aGlzLl9vbkV4dGVybmFsTG9naW5Ib29rKSB7XG4gICAgICBvcHRzID0gdGhpcy5fb25FeHRlcm5hbExvZ2luSG9vayhvcHRpb25zLCB1c2VyKTtcbiAgICB9XG5cbiAgICBpZiAodXNlcikge1xuICAgICAgcGluRW5jcnlwdGVkRmllbGRzVG9Vc2VyKHNlcnZpY2VEYXRhLCB1c2VyLl9pZCk7XG5cbiAgICAgIGxldCBzZXRBdHRycyA9IHt9O1xuICAgICAgT2JqZWN0LmtleXMoc2VydmljZURhdGEpLmZvckVhY2goa2V5ID0+XG4gICAgICAgIHNldEF0dHJzW2BzZXJ2aWNlcy4ke3NlcnZpY2VOYW1lfS4ke2tleX1gXSA9IHNlcnZpY2VEYXRhW2tleV1cbiAgICAgICk7XG5cbiAgICAgIC8vIFhYWCBNYXliZSB3ZSBzaG91bGQgcmUtdXNlIHRoZSBzZWxlY3RvciBhYm92ZSBhbmQgbm90aWNlIGlmIHRoZSB1cGRhdGVcbiAgICAgIC8vICAgICB0b3VjaGVzIG5vdGhpbmc/XG4gICAgICBzZXRBdHRycyA9IHsgLi4uc2V0QXR0cnMsIC4uLm9wdHMgfTtcbiAgICAgIHRoaXMudXNlcnMudXBkYXRlKHVzZXIuX2lkLCB7XG4gICAgICAgICRzZXQ6IHNldEF0dHJzXG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIHtcbiAgICAgICAgdHlwZTogc2VydmljZU5hbWUsXG4gICAgICAgIHVzZXJJZDogdXNlci5faWRcbiAgICAgIH07XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIENyZWF0ZSBhIG5ldyB1c2VyIHdpdGggdGhlIHNlcnZpY2UgZGF0YS5cbiAgICAgIHVzZXIgPSB7c2VydmljZXM6IHt9fTtcbiAgICAgIHVzZXIuc2VydmljZXNbc2VydmljZU5hbWVdID0gc2VydmljZURhdGE7XG4gICAgICByZXR1cm4ge1xuICAgICAgICB0eXBlOiBzZXJ2aWNlTmFtZSxcbiAgICAgICAgdXNlcklkOiB0aGlzLmluc2VydFVzZXJEb2Mob3B0cywgdXNlcilcbiAgICAgIH07XG4gICAgfVxuICB9O1xuXG4gIC8vIFJlbW92ZXMgZGVmYXVsdCByYXRlIGxpbWl0aW5nIHJ1bGVcbiAgcmVtb3ZlRGVmYXVsdFJhdGVMaW1pdCgpIHtcbiAgICBjb25zdCByZXNwID0gRERQUmF0ZUxpbWl0ZXIucmVtb3ZlUnVsZSh0aGlzLmRlZmF1bHRSYXRlTGltaXRlclJ1bGVJZCk7XG4gICAgdGhpcy5kZWZhdWx0UmF0ZUxpbWl0ZXJSdWxlSWQgPSBudWxsO1xuICAgIHJldHVybiByZXNwO1xuICB9O1xuXG4gIC8vIEFkZCBhIGRlZmF1bHQgcnVsZSBvZiBsaW1pdGluZyBsb2dpbnMsIGNyZWF0aW5nIG5ldyB1c2VycyBhbmQgcGFzc3dvcmQgcmVzZXRcbiAgLy8gdG8gNSB0aW1lcyBldmVyeSAxMCBzZWNvbmRzIHBlciBjb25uZWN0aW9uLlxuICBhZGREZWZhdWx0UmF0ZUxpbWl0KCkge1xuICAgIGlmICghdGhpcy5kZWZhdWx0UmF0ZUxpbWl0ZXJSdWxlSWQpIHtcbiAgICAgIHRoaXMuZGVmYXVsdFJhdGVMaW1pdGVyUnVsZUlkID0gRERQUmF0ZUxpbWl0ZXIuYWRkUnVsZSh7XG4gICAgICAgIHVzZXJJZDogbnVsbCxcbiAgICAgICAgY2xpZW50QWRkcmVzczogbnVsbCxcbiAgICAgICAgdHlwZTogJ21ldGhvZCcsXG4gICAgICAgIG5hbWU6IG5hbWUgPT4gWydsb2dpbicsICdjcmVhdGVVc2VyJywgJ3Jlc2V0UGFzc3dvcmQnLCAnZm9yZ290UGFzc3dvcmQnXVxuICAgICAgICAgIC5pbmNsdWRlcyhuYW1lKSxcbiAgICAgICAgY29ubmVjdGlvbklkOiAoY29ubmVjdGlvbklkKSA9PiB0cnVlLFxuICAgICAgfSwgNSwgMTAwMDApO1xuICAgIH1cbiAgfTtcblxuICAvKipcbiAgICogQHN1bW1hcnkgQ3JlYXRlcyBvcHRpb25zIGZvciBlbWFpbCBzZW5kaW5nIGZvciByZXNldCBwYXNzd29yZCBhbmQgZW5yb2xsIGFjY291bnQgZW1haWxzLlxuICAgKiBZb3UgY2FuIHVzZSB0aGlzIGZ1bmN0aW9uIHdoZW4gY3VzdG9taXppbmcgYSByZXNldCBwYXNzd29yZCBvciBlbnJvbGwgYWNjb3VudCBlbWFpbCBzZW5kaW5nLlxuICAgKiBAbG9jdXMgU2VydmVyXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBlbWFpbCBXaGljaCBhZGRyZXNzIG9mIHRoZSB1c2VyJ3MgdG8gc2VuZCB0aGUgZW1haWwgdG8uXG4gICAqIEBwYXJhbSB7T2JqZWN0fSB1c2VyIFRoZSB1c2VyIG9iamVjdCB0byBnZW5lcmF0ZSBvcHRpb25zIGZvci5cbiAgICogQHBhcmFtIHtTdHJpbmd9IHVybCBVUkwgdG8gd2hpY2ggdXNlciBpcyBkaXJlY3RlZCB0byBjb25maXJtIHRoZSBlbWFpbC5cbiAgICogQHBhcmFtIHtTdHJpbmd9IHJlYXNvbiBgcmVzZXRQYXNzd29yZGAgb3IgYGVucm9sbEFjY291bnRgLlxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSBPcHRpb25zIHdoaWNoIGNhbiBiZSBwYXNzZWQgdG8gYEVtYWlsLnNlbmRgLlxuICAgKiBAaW1wb3J0RnJvbVBhY2thZ2UgYWNjb3VudHMtYmFzZVxuICAgKi9cbiAgZ2VuZXJhdGVPcHRpb25zRm9yRW1haWwoZW1haWwsIHVzZXIsIHVybCwgcmVhc29uLCBleHRyYSA9IHt9KXtcbiAgICBjb25zdCBvcHRpb25zID0ge1xuICAgICAgdG86IGVtYWlsLFxuICAgICAgZnJvbTogdGhpcy5lbWFpbFRlbXBsYXRlc1tyZWFzb25dLmZyb21cbiAgICAgICAgPyB0aGlzLmVtYWlsVGVtcGxhdGVzW3JlYXNvbl0uZnJvbSh1c2VyKVxuICAgICAgICA6IHRoaXMuZW1haWxUZW1wbGF0ZXMuZnJvbSxcbiAgICAgIHN1YmplY3Q6IHRoaXMuZW1haWxUZW1wbGF0ZXNbcmVhc29uXS5zdWJqZWN0KHVzZXIsIHVybCwgZXh0cmEpLFxuICAgIH07XG5cbiAgICBpZiAodHlwZW9mIHRoaXMuZW1haWxUZW1wbGF0ZXNbcmVhc29uXS50ZXh0ID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICBvcHRpb25zLnRleHQgPSB0aGlzLmVtYWlsVGVtcGxhdGVzW3JlYXNvbl0udGV4dCh1c2VyLCB1cmwsIGV4dHJhKTtcbiAgICB9XG5cbiAgICBpZiAodHlwZW9mIHRoaXMuZW1haWxUZW1wbGF0ZXNbcmVhc29uXS5odG1sID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICBvcHRpb25zLmh0bWwgPSB0aGlzLmVtYWlsVGVtcGxhdGVzW3JlYXNvbl0uaHRtbCh1c2VyLCB1cmwsIGV4dHJhKTtcbiAgICB9XG5cbiAgICBpZiAodHlwZW9mIHRoaXMuZW1haWxUZW1wbGF0ZXMuaGVhZGVycyA9PT0gJ29iamVjdCcpIHtcbiAgICAgIG9wdGlvbnMuaGVhZGVycyA9IHRoaXMuZW1haWxUZW1wbGF0ZXMuaGVhZGVycztcbiAgICB9XG5cbiAgICByZXR1cm4gb3B0aW9ucztcbiAgfTtcblxuICBfY2hlY2tGb3JDYXNlSW5zZW5zaXRpdmVEdXBsaWNhdGVzKFxuICAgIGZpZWxkTmFtZSxcbiAgICBkaXNwbGF5TmFtZSxcbiAgICBmaWVsZFZhbHVlLFxuICAgIG93blVzZXJJZFxuICApIHtcbiAgICAvLyBTb21lIHRlc3RzIG5lZWQgdGhlIGFiaWxpdHkgdG8gYWRkIHVzZXJzIHdpdGggdGhlIHNhbWUgY2FzZSBpbnNlbnNpdGl2ZVxuICAgIC8vIHZhbHVlLCBoZW5jZSB0aGUgX3NraXBDYXNlSW5zZW5zaXRpdmVDaGVja3NGb3JUZXN0IGNoZWNrXG4gICAgY29uc3Qgc2tpcENoZWNrID0gT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKFxuICAgICAgdGhpcy5fc2tpcENhc2VJbnNlbnNpdGl2ZUNoZWNrc0ZvclRlc3QsXG4gICAgICBmaWVsZFZhbHVlXG4gICAgKTtcblxuICAgIGlmIChmaWVsZFZhbHVlICYmICFza2lwQ2hlY2spIHtcbiAgICAgIGNvbnN0IG1hdGNoZWRVc2VycyA9IE1ldGVvci51c2Vyc1xuICAgICAgICAuZmluZChcbiAgICAgICAgICB0aGlzLl9zZWxlY3RvckZvckZhc3RDYXNlSW5zZW5zaXRpdmVMb29rdXAoZmllbGROYW1lLCBmaWVsZFZhbHVlKSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBmaWVsZHM6IHsgX2lkOiAxIH0sXG4gICAgICAgICAgICAvLyB3ZSBvbmx5IG5lZWQgYSBtYXhpbXVtIG9mIDIgdXNlcnMgZm9yIHRoZSBsb2dpYyBiZWxvdyB0byB3b3JrXG4gICAgICAgICAgICBsaW1pdDogMixcbiAgICAgICAgICB9XG4gICAgICAgIClcbiAgICAgICAgLmZldGNoKCk7XG5cbiAgICAgIGlmIChcbiAgICAgICAgbWF0Y2hlZFVzZXJzLmxlbmd0aCA+IDAgJiZcbiAgICAgICAgLy8gSWYgd2UgZG9uJ3QgaGF2ZSBhIHVzZXJJZCB5ZXQsIGFueSBtYXRjaCB3ZSBmaW5kIGlzIGEgZHVwbGljYXRlXG4gICAgICAgICghb3duVXNlcklkIHx8XG4gICAgICAgICAgLy8gT3RoZXJ3aXNlLCBjaGVjayB0byBzZWUgaWYgdGhlcmUgYXJlIG11bHRpcGxlIG1hdGNoZXMgb3IgYSBtYXRjaFxuICAgICAgICAgIC8vIHRoYXQgaXMgbm90IHVzXG4gICAgICAgICAgbWF0Y2hlZFVzZXJzLmxlbmd0aCA+IDEgfHwgbWF0Y2hlZFVzZXJzWzBdLl9pZCAhPT0gb3duVXNlcklkKVxuICAgICAgKSB7XG4gICAgICAgIHRoaXMuX2hhbmRsZUVycm9yKGAke2Rpc3BsYXlOYW1lfSBhbHJlYWR5IGV4aXN0cy5gKTtcbiAgICAgIH1cbiAgICB9XG4gIH07XG5cbiAgX2NyZWF0ZVVzZXJDaGVja2luZ0R1cGxpY2F0ZXMoeyB1c2VyLCBlbWFpbCwgdXNlcm5hbWUsIG9wdGlvbnMgfSkge1xuICAgIGNvbnN0IG5ld1VzZXIgPSB7XG4gICAgICAuLi51c2VyLFxuICAgICAgLi4uKHVzZXJuYW1lID8geyB1c2VybmFtZSB9IDoge30pLFxuICAgICAgLi4uKGVtYWlsID8geyBlbWFpbHM6IFt7IGFkZHJlc3M6IGVtYWlsLCB2ZXJpZmllZDogZmFsc2UgfV0gfSA6IHt9KSxcbiAgICB9O1xuXG4gICAgLy8gUGVyZm9ybSBhIGNhc2UgaW5zZW5zaXRpdmUgY2hlY2sgYmVmb3JlIGluc2VydFxuICAgIHRoaXMuX2NoZWNrRm9yQ2FzZUluc2Vuc2l0aXZlRHVwbGljYXRlcygndXNlcm5hbWUnLCAnVXNlcm5hbWUnLCB1c2VybmFtZSk7XG4gICAgdGhpcy5fY2hlY2tGb3JDYXNlSW5zZW5zaXRpdmVEdXBsaWNhdGVzKCdlbWFpbHMuYWRkcmVzcycsICdFbWFpbCcsIGVtYWlsKTtcblxuICAgIGNvbnN0IHVzZXJJZCA9IHRoaXMuaW5zZXJ0VXNlckRvYyhvcHRpb25zLCBuZXdVc2VyKTtcbiAgICAvLyBQZXJmb3JtIGFub3RoZXIgY2hlY2sgYWZ0ZXIgaW5zZXJ0LCBpbiBjYXNlIGEgbWF0Y2hpbmcgdXNlciBoYXMgYmVlblxuICAgIC8vIGluc2VydGVkIGluIHRoZSBtZWFudGltZVxuICAgIHRyeSB7XG4gICAgICB0aGlzLl9jaGVja0ZvckNhc2VJbnNlbnNpdGl2ZUR1cGxpY2F0ZXMoJ3VzZXJuYW1lJywgJ1VzZXJuYW1lJywgdXNlcm5hbWUsIHVzZXJJZCk7XG4gICAgICB0aGlzLl9jaGVja0ZvckNhc2VJbnNlbnNpdGl2ZUR1cGxpY2F0ZXMoJ2VtYWlscy5hZGRyZXNzJywgJ0VtYWlsJywgZW1haWwsIHVzZXJJZCk7XG4gICAgfSBjYXRjaCAoZXgpIHtcbiAgICAgIC8vIFJlbW92ZSBpbnNlcnRlZCB1c2VyIGlmIHRoZSBjaGVjayBmYWlsc1xuICAgICAgTWV0ZW9yLnVzZXJzLnJlbW92ZSh1c2VySWQpO1xuICAgICAgdGhyb3cgZXg7XG4gICAgfVxuICAgIHJldHVybiB1c2VySWQ7XG4gIH1cblxuICBfaGFuZGxlRXJyb3IgPSAobXNnLCB0aHJvd0Vycm9yID0gdHJ1ZSkgPT4ge1xuICAgIGNvbnN0IGVycm9yID0gbmV3IE1ldGVvci5FcnJvcihcbiAgICAgIDQwMyxcbiAgICAgIHRoaXMuX29wdGlvbnMuYW1iaWd1b3VzRXJyb3JNZXNzYWdlc1xuICAgICAgICA/IFwiU29tZXRoaW5nIHdlbnQgd3JvbmcuIFBsZWFzZSBjaGVjayB5b3VyIGNyZWRlbnRpYWxzLlwiXG4gICAgICAgIDogbXNnXG4gICAgKTtcbiAgICBpZiAodGhyb3dFcnJvcikge1xuICAgICAgdGhyb3cgZXJyb3I7XG4gICAgfVxuICAgIHJldHVybiBlcnJvcjtcbiAgfVxuXG4gIF91c2VyUXVlcnlWYWxpZGF0b3IgPSBNYXRjaC5XaGVyZSh1c2VyID0+IHtcbiAgICBjaGVjayh1c2VyLCB7XG4gICAgICBpZDogTWF0Y2guT3B0aW9uYWwoTm9uRW1wdHlTdHJpbmcpLFxuICAgICAgdXNlcm5hbWU6IE1hdGNoLk9wdGlvbmFsKE5vbkVtcHR5U3RyaW5nKSxcbiAgICAgIGVtYWlsOiBNYXRjaC5PcHRpb25hbChOb25FbXB0eVN0cmluZylcbiAgICB9KTtcbiAgICBpZiAoT2JqZWN0LmtleXModXNlcikubGVuZ3RoICE9PSAxKVxuICAgICAgdGhyb3cgbmV3IE1hdGNoLkVycm9yKFwiVXNlciBwcm9wZXJ0eSBtdXN0IGhhdmUgZXhhY3RseSBvbmUgZmllbGRcIik7XG4gICAgcmV0dXJuIHRydWU7XG4gIH0pO1xuXG59XG5cbi8vIEdpdmUgZWFjaCBsb2dpbiBob29rIGNhbGxiYWNrIGEgZnJlc2ggY2xvbmVkIGNvcHkgb2YgdGhlIGF0dGVtcHRcbi8vIG9iamVjdCwgYnV0IGRvbid0IGNsb25lIHRoZSBjb25uZWN0aW9uLlxuLy9cbmNvbnN0IGNsb25lQXR0ZW1wdFdpdGhDb25uZWN0aW9uID0gKGNvbm5lY3Rpb24sIGF0dGVtcHQpID0+IHtcbiAgY29uc3QgY2xvbmVkQXR0ZW1wdCA9IEVKU09OLmNsb25lKGF0dGVtcHQpO1xuICBjbG9uZWRBdHRlbXB0LmNvbm5lY3Rpb24gPSBjb25uZWN0aW9uO1xuICByZXR1cm4gY2xvbmVkQXR0ZW1wdDtcbn07XG5cbmNvbnN0IHRyeUxvZ2luTWV0aG9kID0gKHR5cGUsIGZuKSA9PiB7XG4gIGxldCByZXN1bHQ7XG4gIHRyeSB7XG4gICAgcmVzdWx0ID0gZm4oKTtcbiAgfVxuICBjYXRjaCAoZSkge1xuICAgIHJlc3VsdCA9IHtlcnJvcjogZX07XG4gIH1cblxuICBpZiAocmVzdWx0ICYmICFyZXN1bHQudHlwZSAmJiB0eXBlKVxuICAgIHJlc3VsdC50eXBlID0gdHlwZTtcblxuICByZXR1cm4gcmVzdWx0O1xufTtcblxuY29uc3Qgc2V0dXBEZWZhdWx0TG9naW5IYW5kbGVycyA9IGFjY291bnRzID0+IHtcbiAgYWNjb3VudHMucmVnaXN0ZXJMb2dpbkhhbmRsZXIoXCJyZXN1bWVcIiwgZnVuY3Rpb24gKG9wdGlvbnMpIHtcbiAgICByZXR1cm4gZGVmYXVsdFJlc3VtZUxvZ2luSGFuZGxlci5jYWxsKHRoaXMsIGFjY291bnRzLCBvcHRpb25zKTtcbiAgfSk7XG59O1xuXG4vLyBMb2dpbiBoYW5kbGVyIGZvciByZXN1bWUgdG9rZW5zLlxuY29uc3QgZGVmYXVsdFJlc3VtZUxvZ2luSGFuZGxlciA9IChhY2NvdW50cywgb3B0aW9ucykgPT4ge1xuICBpZiAoIW9wdGlvbnMucmVzdW1lKVxuICAgIHJldHVybiB1bmRlZmluZWQ7XG5cbiAgY2hlY2sob3B0aW9ucy5yZXN1bWUsIFN0cmluZyk7XG5cbiAgY29uc3QgaGFzaGVkVG9rZW4gPSBhY2NvdW50cy5faGFzaExvZ2luVG9rZW4ob3B0aW9ucy5yZXN1bWUpO1xuXG4gIC8vIEZpcnN0IGxvb2sgZm9yIGp1c3QgdGhlIG5ldy1zdHlsZSBoYXNoZWQgbG9naW4gdG9rZW4sIHRvIGF2b2lkXG4gIC8vIHNlbmRpbmcgdGhlIHVuaGFzaGVkIHRva2VuIHRvIHRoZSBkYXRhYmFzZSBpbiBhIHF1ZXJ5IGlmIHdlIGRvbid0XG4gIC8vIG5lZWQgdG8uXG4gIGxldCB1c2VyID0gYWNjb3VudHMudXNlcnMuZmluZE9uZShcbiAgICB7XCJzZXJ2aWNlcy5yZXN1bWUubG9naW5Ub2tlbnMuaGFzaGVkVG9rZW5cIjogaGFzaGVkVG9rZW59LFxuICAgIHtmaWVsZHM6IHtcInNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vucy4kXCI6IDF9fSk7XG5cbiAgaWYgKCEgdXNlcikge1xuICAgIC8vIElmIHdlIGRpZG4ndCBmaW5kIHRoZSBoYXNoZWQgbG9naW4gdG9rZW4sIHRyeSBhbHNvIGxvb2tpbmcgZm9yXG4gICAgLy8gdGhlIG9sZC1zdHlsZSB1bmhhc2hlZCB0b2tlbi4gIEJ1dCB3ZSBuZWVkIHRvIGxvb2sgZm9yIGVpdGhlclxuICAgIC8vIHRoZSBvbGQtc3R5bGUgdG9rZW4gT1IgdGhlIG5ldy1zdHlsZSB0b2tlbiwgYmVjYXVzZSBhbm90aGVyXG4gICAgLy8gY2xpZW50IGNvbm5lY3Rpb24gbG9nZ2luZyBpbiBzaW11bHRhbmVvdXNseSBtaWdodCBoYXZlIGFscmVhZHlcbiAgICAvLyBjb252ZXJ0ZWQgdGhlIHRva2VuLlxuICAgIHVzZXIgPSBhY2NvdW50cy51c2Vycy5maW5kT25lKHtcbiAgICAgICAgJG9yOiBbXG4gICAgICAgICAge1wic2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zLmhhc2hlZFRva2VuXCI6IGhhc2hlZFRva2VufSxcbiAgICAgICAgICB7XCJzZXJ2aWNlcy5yZXN1bWUubG9naW5Ub2tlbnMudG9rZW5cIjogb3B0aW9ucy5yZXN1bWV9XG4gICAgICAgIF1cbiAgICAgIH0sXG4gICAgICAvLyBOb3RlOiBDYW5ub3QgdXNlIC4uLmxvZ2luVG9rZW5zLiQgcG9zaXRpb25hbCBvcGVyYXRvciB3aXRoICRvciBxdWVyeS5cbiAgICAgIHtmaWVsZHM6IHtcInNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vuc1wiOiAxfX0pO1xuICB9XG5cbiAgaWYgKCEgdXNlcilcbiAgICByZXR1cm4ge1xuICAgICAgZXJyb3I6IG5ldyBNZXRlb3IuRXJyb3IoNDAzLCBcIllvdSd2ZSBiZWVuIGxvZ2dlZCBvdXQgYnkgdGhlIHNlcnZlci4gUGxlYXNlIGxvZyBpbiBhZ2Fpbi5cIilcbiAgICB9O1xuXG4gIC8vIEZpbmQgdGhlIHRva2VuLCB3aGljaCB3aWxsIGVpdGhlciBiZSBhbiBvYmplY3Qgd2l0aCBmaWVsZHNcbiAgLy8ge2hhc2hlZFRva2VuLCB3aGVufSBmb3IgYSBoYXNoZWQgdG9rZW4gb3Ige3Rva2VuLCB3aGVufSBmb3IgYW5cbiAgLy8gdW5oYXNoZWQgdG9rZW4uXG4gIGxldCBvbGRVbmhhc2hlZFN0eWxlVG9rZW47XG4gIGxldCB0b2tlbiA9IHVzZXIuc2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zLmZpbmQodG9rZW4gPT5cbiAgICB0b2tlbi5oYXNoZWRUb2tlbiA9PT0gaGFzaGVkVG9rZW5cbiAgKTtcbiAgaWYgKHRva2VuKSB7XG4gICAgb2xkVW5oYXNoZWRTdHlsZVRva2VuID0gZmFsc2U7XG4gIH0gZWxzZSB7XG4gICAgdG9rZW4gPSB1c2VyLnNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vucy5maW5kKHRva2VuID0+XG4gICAgICB0b2tlbi50b2tlbiA9PT0gb3B0aW9ucy5yZXN1bWVcbiAgICApO1xuICAgIG9sZFVuaGFzaGVkU3R5bGVUb2tlbiA9IHRydWU7XG4gIH1cblxuICBjb25zdCB0b2tlbkV4cGlyZXMgPSBhY2NvdW50cy5fdG9rZW5FeHBpcmF0aW9uKHRva2VuLndoZW4pO1xuICBpZiAobmV3IERhdGUoKSA+PSB0b2tlbkV4cGlyZXMpXG4gICAgcmV0dXJuIHtcbiAgICAgIHVzZXJJZDogdXNlci5faWQsXG4gICAgICBlcnJvcjogbmV3IE1ldGVvci5FcnJvcig0MDMsIFwiWW91ciBzZXNzaW9uIGhhcyBleHBpcmVkLiBQbGVhc2UgbG9nIGluIGFnYWluLlwiKVxuICAgIH07XG5cbiAgLy8gVXBkYXRlIHRvIGEgaGFzaGVkIHRva2VuIHdoZW4gYW4gdW5oYXNoZWQgdG9rZW4gaXMgZW5jb3VudGVyZWQuXG4gIGlmIChvbGRVbmhhc2hlZFN0eWxlVG9rZW4pIHtcbiAgICAvLyBPbmx5IGFkZCB0aGUgbmV3IGhhc2hlZCB0b2tlbiBpZiB0aGUgb2xkIHVuaGFzaGVkIHRva2VuIHN0aWxsXG4gICAgLy8gZXhpc3RzICh0aGlzIGF2b2lkcyByZXN1cnJlY3RpbmcgdGhlIHRva2VuIGlmIGl0IHdhcyBkZWxldGVkXG4gICAgLy8gYWZ0ZXIgd2UgcmVhZCBpdCkuICBVc2luZyAkYWRkVG9TZXQgYXZvaWRzIGdldHRpbmcgYW4gaW5kZXhcbiAgICAvLyBlcnJvciBpZiBhbm90aGVyIGNsaWVudCBsb2dnaW5nIGluIHNpbXVsdGFuZW91c2x5IGhhcyBhbHJlYWR5XG4gICAgLy8gaW5zZXJ0ZWQgdGhlIG5ldyBoYXNoZWQgdG9rZW4uXG4gICAgYWNjb3VudHMudXNlcnMudXBkYXRlKFxuICAgICAge1xuICAgICAgICBfaWQ6IHVzZXIuX2lkLFxuICAgICAgICBcInNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vucy50b2tlblwiOiBvcHRpb25zLnJlc3VtZVxuICAgICAgfSxcbiAgICAgIHskYWRkVG9TZXQ6IHtcbiAgICAgICAgICBcInNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vuc1wiOiB7XG4gICAgICAgICAgICBcImhhc2hlZFRva2VuXCI6IGhhc2hlZFRva2VuLFxuICAgICAgICAgICAgXCJ3aGVuXCI6IHRva2VuLndoZW5cbiAgICAgICAgICB9XG4gICAgICAgIH19XG4gICAgKTtcblxuICAgIC8vIFJlbW92ZSB0aGUgb2xkIHRva2VuICphZnRlciogYWRkaW5nIHRoZSBuZXcsIHNpbmNlIG90aGVyd2lzZVxuICAgIC8vIGFub3RoZXIgY2xpZW50IHRyeWluZyB0byBsb2dpbiBiZXR3ZWVuIG91ciByZW1vdmluZyB0aGUgb2xkIGFuZFxuICAgIC8vIGFkZGluZyB0aGUgbmV3IHdvdWxkbid0IGZpbmQgYSB0b2tlbiB0byBsb2dpbiB3aXRoLlxuICAgIGFjY291bnRzLnVzZXJzLnVwZGF0ZSh1c2VyLl9pZCwge1xuICAgICAgJHB1bGw6IHtcbiAgICAgICAgXCJzZXJ2aWNlcy5yZXN1bWUubG9naW5Ub2tlbnNcIjogeyBcInRva2VuXCI6IG9wdGlvbnMucmVzdW1lIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG4gIHJldHVybiB7XG4gICAgdXNlcklkOiB1c2VyLl9pZCxcbiAgICBzdGFtcGVkTG9naW5Ub2tlbjoge1xuICAgICAgdG9rZW46IG9wdGlvbnMucmVzdW1lLFxuICAgICAgd2hlbjogdG9rZW4ud2hlblxuICAgIH1cbiAgfTtcbn07XG5cbmNvbnN0IGV4cGlyZVBhc3N3b3JkVG9rZW4gPSAoXG4gIGFjY291bnRzLFxuICBvbGRlc3RWYWxpZERhdGUsXG4gIHRva2VuRmlsdGVyLFxuICB1c2VySWRcbikgPT4ge1xuICAvLyBib29sZWFuIHZhbHVlIHVzZWQgdG8gZGV0ZXJtaW5lIGlmIHRoaXMgbWV0aG9kIHdhcyBjYWxsZWQgZnJvbSBlbnJvbGwgYWNjb3VudCB3b3JrZmxvd1xuICBsZXQgaXNFbnJvbGwgPSBmYWxzZTtcbiAgY29uc3QgdXNlckZpbHRlciA9IHVzZXJJZCA/IHtfaWQ6IHVzZXJJZH0gOiB7fTtcbiAgLy8gY2hlY2sgaWYgdGhpcyBtZXRob2Qgd2FzIGNhbGxlZCBmcm9tIGVucm9sbCBhY2NvdW50IHdvcmtmbG93XG4gIGlmKHRva2VuRmlsdGVyWydzZXJ2aWNlcy5wYXNzd29yZC5lbnJvbGwucmVhc29uJ10pIHtcbiAgICBpc0Vucm9sbCA9IHRydWU7XG4gIH1cbiAgbGV0IHJlc2V0UmFuZ2VPciA9IHtcbiAgICAkb3I6IFtcbiAgICAgIHsgXCJzZXJ2aWNlcy5wYXNzd29yZC5yZXNldC53aGVuXCI6IHsgJGx0OiBvbGRlc3RWYWxpZERhdGUgfSB9LFxuICAgICAgeyBcInNlcnZpY2VzLnBhc3N3b3JkLnJlc2V0LndoZW5cIjogeyAkbHQ6ICtvbGRlc3RWYWxpZERhdGUgfSB9XG4gICAgXVxuICB9O1xuICBpZihpc0Vucm9sbCkge1xuICAgIHJlc2V0UmFuZ2VPciA9IHtcbiAgICAgICRvcjogW1xuICAgICAgICB7IFwic2VydmljZXMucGFzc3dvcmQuZW5yb2xsLndoZW5cIjogeyAkbHQ6IG9sZGVzdFZhbGlkRGF0ZSB9IH0sXG4gICAgICAgIHsgXCJzZXJ2aWNlcy5wYXNzd29yZC5lbnJvbGwud2hlblwiOiB7ICRsdDogK29sZGVzdFZhbGlkRGF0ZSB9IH1cbiAgICAgIF1cbiAgICB9O1xuICB9XG4gIGNvbnN0IGV4cGlyZUZpbHRlciA9IHsgJGFuZDogW3Rva2VuRmlsdGVyLCByZXNldFJhbmdlT3JdIH07XG4gIGlmKGlzRW5yb2xsKSB7XG4gICAgYWNjb3VudHMudXNlcnMudXBkYXRlKHsuLi51c2VyRmlsdGVyLCAuLi5leHBpcmVGaWx0ZXJ9LCB7XG4gICAgICAkdW5zZXQ6IHtcbiAgICAgICAgXCJzZXJ2aWNlcy5wYXNzd29yZC5lbnJvbGxcIjogXCJcIlxuICAgICAgfVxuICAgIH0sIHsgbXVsdGk6IHRydWUgfSk7XG4gIH0gZWxzZSB7XG4gICAgYWNjb3VudHMudXNlcnMudXBkYXRlKHsuLi51c2VyRmlsdGVyLCAuLi5leHBpcmVGaWx0ZXJ9LCB7XG4gICAgICAkdW5zZXQ6IHtcbiAgICAgICAgXCJzZXJ2aWNlcy5wYXNzd29yZC5yZXNldFwiOiBcIlwiXG4gICAgICB9XG4gICAgfSwgeyBtdWx0aTogdHJ1ZSB9KTtcbiAgfVxuXG59O1xuXG5jb25zdCBzZXRFeHBpcmVUb2tlbnNJbnRlcnZhbCA9IGFjY291bnRzID0+IHtcbiAgYWNjb3VudHMuZXhwaXJlVG9rZW5JbnRlcnZhbCA9IE1ldGVvci5zZXRJbnRlcnZhbCgoKSA9PiB7XG4gICAgYWNjb3VudHMuX2V4cGlyZVRva2VucygpO1xuICAgIGFjY291bnRzLl9leHBpcmVQYXNzd29yZFJlc2V0VG9rZW5zKCk7XG4gICAgYWNjb3VudHMuX2V4cGlyZVBhc3N3b3JkRW5yb2xsVG9rZW5zKCk7XG4gIH0sIEVYUElSRV9UT0tFTlNfSU5URVJWQUxfTVMpO1xufTtcblxuLy8vXG4vLy8gT0F1dGggRW5jcnlwdGlvbiBTdXBwb3J0XG4vLy9cblxuY29uc3QgT0F1dGhFbmNyeXB0aW9uID1cbiAgUGFja2FnZVtcIm9hdXRoLWVuY3J5cHRpb25cIl0gJiZcbiAgUGFja2FnZVtcIm9hdXRoLWVuY3J5cHRpb25cIl0uT0F1dGhFbmNyeXB0aW9uO1xuXG5jb25zdCB1c2luZ09BdXRoRW5jcnlwdGlvbiA9ICgpID0+IHtcbiAgcmV0dXJuIE9BdXRoRW5jcnlwdGlvbiAmJiBPQXV0aEVuY3J5cHRpb24ua2V5SXNMb2FkZWQoKTtcbn07XG5cbi8vIE9BdXRoIHNlcnZpY2UgZGF0YSBpcyB0ZW1wb3JhcmlseSBzdG9yZWQgaW4gdGhlIHBlbmRpbmcgY3JlZGVudGlhbHNcbi8vIGNvbGxlY3Rpb24gZHVyaW5nIHRoZSBvYXV0aCBhdXRoZW50aWNhdGlvbiBwcm9jZXNzLiAgU2Vuc2l0aXZlIGRhdGFcbi8vIHN1Y2ggYXMgYWNjZXNzIHRva2VucyBhcmUgZW5jcnlwdGVkIHdpdGhvdXQgdGhlIHVzZXIgaWQgYmVjYXVzZVxuLy8gd2UgZG9uJ3Qga25vdyB0aGUgdXNlciBpZCB5ZXQuICBXZSByZS1lbmNyeXB0IHRoZXNlIGZpZWxkcyB3aXRoIHRoZVxuLy8gdXNlciBpZCBpbmNsdWRlZCB3aGVuIHN0b3JpbmcgdGhlIHNlcnZpY2UgZGF0YSBwZXJtYW5lbnRseSBpblxuLy8gdGhlIHVzZXJzIGNvbGxlY3Rpb24uXG4vL1xuY29uc3QgcGluRW5jcnlwdGVkRmllbGRzVG9Vc2VyID0gKHNlcnZpY2VEYXRhLCB1c2VySWQpID0+IHtcbiAgT2JqZWN0LmtleXMoc2VydmljZURhdGEpLmZvckVhY2goa2V5ID0+IHtcbiAgICBsZXQgdmFsdWUgPSBzZXJ2aWNlRGF0YVtrZXldO1xuICAgIGlmIChPQXV0aEVuY3J5cHRpb24gJiYgT0F1dGhFbmNyeXB0aW9uLmlzU2VhbGVkKHZhbHVlKSlcbiAgICAgIHZhbHVlID0gT0F1dGhFbmNyeXB0aW9uLnNlYWwoT0F1dGhFbmNyeXB0aW9uLm9wZW4odmFsdWUpLCB1c2VySWQpO1xuICAgIHNlcnZpY2VEYXRhW2tleV0gPSB2YWx1ZTtcbiAgfSk7XG59O1xuXG5cbi8vIEVuY3J5cHQgdW5lbmNyeXB0ZWQgbG9naW4gc2VydmljZSBzZWNyZXRzIHdoZW4gb2F1dGgtZW5jcnlwdGlvbiBpc1xuLy8gYWRkZWQuXG4vL1xuLy8gWFhYIEZvciB0aGUgb2F1dGhTZWNyZXRLZXkgdG8gYmUgYXZhaWxhYmxlIGhlcmUgYXQgc3RhcnR1cCwgdGhlXG4vLyBkZXZlbG9wZXIgbXVzdCBjYWxsIEFjY291bnRzLmNvbmZpZyh7b2F1dGhTZWNyZXRLZXk6IC4uLn0pIGF0IGxvYWRcbi8vIHRpbWUsIGluc3RlYWQgb2YgaW4gYSBNZXRlb3Iuc3RhcnR1cCBibG9jaywgYmVjYXVzZSB0aGUgc3RhcnR1cFxuLy8gYmxvY2sgaW4gdGhlIGFwcCBjb2RlIHdpbGwgcnVuIGFmdGVyIHRoaXMgYWNjb3VudHMtYmFzZSBzdGFydHVwXG4vLyBibG9jay4gIFBlcmhhcHMgd2UgbmVlZCBhIHBvc3Qtc3RhcnR1cCBjYWxsYmFjaz9cblxuTWV0ZW9yLnN0YXJ0dXAoKCkgPT4ge1xuICBpZiAoISB1c2luZ09BdXRoRW5jcnlwdGlvbigpKSB7XG4gICAgcmV0dXJuO1xuICB9XG5cbiAgY29uc3QgeyBTZXJ2aWNlQ29uZmlndXJhdGlvbiB9ID0gUGFja2FnZVsnc2VydmljZS1jb25maWd1cmF0aW9uJ107XG5cbiAgU2VydmljZUNvbmZpZ3VyYXRpb24uY29uZmlndXJhdGlvbnMuZmluZCh7XG4gICAgJGFuZDogW3tcbiAgICAgIHNlY3JldDogeyAkZXhpc3RzOiB0cnVlIH1cbiAgICB9LCB7XG4gICAgICBcInNlY3JldC5hbGdvcml0aG1cIjogeyAkZXhpc3RzOiBmYWxzZSB9XG4gICAgfV1cbiAgfSkuZm9yRWFjaChjb25maWcgPT4ge1xuICAgIFNlcnZpY2VDb25maWd1cmF0aW9uLmNvbmZpZ3VyYXRpb25zLnVwZGF0ZShjb25maWcuX2lkLCB7XG4gICAgICAkc2V0OiB7XG4gICAgICAgIHNlY3JldDogT0F1dGhFbmNyeXB0aW9uLnNlYWwoY29uZmlnLnNlY3JldClcbiAgICAgIH1cbiAgICB9KTtcbiAgfSk7XG59KTtcblxuLy8gWFhYIHNlZSBjb21tZW50IG9uIEFjY291bnRzLmNyZWF0ZVVzZXIgaW4gcGFzc3dvcmRzX3NlcnZlciBhYm91dCBhZGRpbmcgYVxuLy8gc2Vjb25kIFwic2VydmVyIG9wdGlvbnNcIiBhcmd1bWVudC5cbmNvbnN0IGRlZmF1bHRDcmVhdGVVc2VySG9vayA9IChvcHRpb25zLCB1c2VyKSA9PiB7XG4gIGlmIChvcHRpb25zLnByb2ZpbGUpXG4gICAgdXNlci5wcm9maWxlID0gb3B0aW9ucy5wcm9maWxlO1xuICByZXR1cm4gdXNlcjtcbn07XG5cbi8vIFZhbGlkYXRlIG5ldyB1c2VyJ3MgZW1haWwgb3IgR29vZ2xlL0ZhY2Vib29rL0dpdEh1YiBhY2NvdW50J3MgZW1haWxcbmZ1bmN0aW9uIGRlZmF1bHRWYWxpZGF0ZU5ld1VzZXJIb29rKHVzZXIpIHtcbiAgY29uc3QgZG9tYWluID0gdGhpcy5fb3B0aW9ucy5yZXN0cmljdENyZWF0aW9uQnlFbWFpbERvbWFpbjtcbiAgaWYgKCFkb21haW4pIHtcbiAgICByZXR1cm4gdHJ1ZTtcbiAgfVxuXG4gIGxldCBlbWFpbElzR29vZCA9IGZhbHNlO1xuICBpZiAodXNlci5lbWFpbHMgJiYgdXNlci5lbWFpbHMubGVuZ3RoID4gMCkge1xuICAgIGVtYWlsSXNHb29kID0gdXNlci5lbWFpbHMucmVkdWNlKFxuICAgICAgKHByZXYsIGVtYWlsKSA9PiBwcmV2IHx8IHRoaXMuX3Rlc3RFbWFpbERvbWFpbihlbWFpbC5hZGRyZXNzKSwgZmFsc2VcbiAgICApO1xuICB9IGVsc2UgaWYgKHVzZXIuc2VydmljZXMgJiYgT2JqZWN0LnZhbHVlcyh1c2VyLnNlcnZpY2VzKS5sZW5ndGggPiAwKSB7XG4gICAgLy8gRmluZCBhbnkgZW1haWwgb2YgYW55IHNlcnZpY2UgYW5kIGNoZWNrIGl0XG4gICAgZW1haWxJc0dvb2QgPSBPYmplY3QudmFsdWVzKHVzZXIuc2VydmljZXMpLnJlZHVjZShcbiAgICAgIChwcmV2LCBzZXJ2aWNlKSA9PiBzZXJ2aWNlLmVtYWlsICYmIHRoaXMuX3Rlc3RFbWFpbERvbWFpbihzZXJ2aWNlLmVtYWlsKSxcbiAgICAgIGZhbHNlLFxuICAgICk7XG4gIH1cblxuICBpZiAoZW1haWxJc0dvb2QpIHtcbiAgICByZXR1cm4gdHJ1ZTtcbiAgfVxuXG4gIGlmICh0eXBlb2YgZG9tYWluID09PSAnc3RyaW5nJykge1xuICAgIHRocm93IG5ldyBNZXRlb3IuRXJyb3IoNDAzLCBgQCR7ZG9tYWlufSBlbWFpbCByZXF1aXJlZGApO1xuICB9IGVsc2Uge1xuICAgIHRocm93IG5ldyBNZXRlb3IuRXJyb3IoNDAzLCBcIkVtYWlsIGRvZXNuJ3QgbWF0Y2ggdGhlIGNyaXRlcmlhLlwiKTtcbiAgfVxufVxuXG5jb25zdCBzZXR1cFVzZXJzQ29sbGVjdGlvbiA9IHVzZXJzID0+IHtcbiAgLy8vXG4gIC8vLyBSRVNUUklDVElORyBXUklURVMgVE8gVVNFUiBPQkpFQ1RTXG4gIC8vL1xuICB1c2Vycy5hbGxvdyh7XG4gICAgLy8gY2xpZW50cyBjYW4gbW9kaWZ5IHRoZSBwcm9maWxlIGZpZWxkIG9mIHRoZWlyIG93biBkb2N1bWVudCwgYW5kXG4gICAgLy8gbm90aGluZyBlbHNlLlxuICAgIHVwZGF0ZTogKHVzZXJJZCwgdXNlciwgZmllbGRzLCBtb2RpZmllcikgPT4ge1xuICAgICAgLy8gbWFrZSBzdXJlIGl0IGlzIG91ciByZWNvcmRcbiAgICAgIGlmICh1c2VyLl9pZCAhPT0gdXNlcklkKSB7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH1cblxuICAgICAgLy8gdXNlciBjYW4gb25seSBtb2RpZnkgdGhlICdwcm9maWxlJyBmaWVsZC4gc2V0cyB0byBtdWx0aXBsZVxuICAgICAgLy8gc3ViLWtleXMgKGVnIHByb2ZpbGUuZm9vIGFuZCBwcm9maWxlLmJhcikgYXJlIG1lcmdlZCBpbnRvIGVudHJ5XG4gICAgICAvLyBpbiB0aGUgZmllbGRzIGxpc3QuXG4gICAgICBpZiAoZmllbGRzLmxlbmd0aCAhPT0gMSB8fCBmaWVsZHNbMF0gIT09ICdwcm9maWxlJykge1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH0sXG4gICAgZmV0Y2g6IFsnX2lkJ10gLy8gd2Ugb25seSBsb29rIGF0IF9pZC5cbiAgfSk7XG5cbiAgLy8vIERFRkFVTFQgSU5ERVhFUyBPTiBVU0VSU1xuICB1c2Vycy5jcmVhdGVJbmRleCgndXNlcm5hbWUnLCB7IHVuaXF1ZTogdHJ1ZSwgc3BhcnNlOiB0cnVlIH0pO1xuICB1c2Vycy5jcmVhdGVJbmRleCgnZW1haWxzLmFkZHJlc3MnLCB7IHVuaXF1ZTogdHJ1ZSwgc3BhcnNlOiB0cnVlIH0pO1xuICB1c2Vycy5jcmVhdGVJbmRleCgnc2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zLmhhc2hlZFRva2VuJyxcbiAgICB7IHVuaXF1ZTogdHJ1ZSwgc3BhcnNlOiB0cnVlIH0pO1xuICB1c2Vycy5jcmVhdGVJbmRleCgnc2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zLnRva2VuJyxcbiAgICB7IHVuaXF1ZTogdHJ1ZSwgc3BhcnNlOiB0cnVlIH0pO1xuICAvLyBGb3IgdGFraW5nIGNhcmUgb2YgbG9nb3V0T3RoZXJDbGllbnRzIGNhbGxzIHRoYXQgY3Jhc2hlZCBiZWZvcmUgdGhlXG4gIC8vIHRva2VucyB3ZXJlIGRlbGV0ZWQuXG4gIHVzZXJzLmNyZWF0ZUluZGV4KCdzZXJ2aWNlcy5yZXN1bWUuaGF2ZUxvZ2luVG9rZW5zVG9EZWxldGUnLFxuICAgIHsgc3BhcnNlOiB0cnVlIH0pO1xuICAvLyBGb3IgZXhwaXJpbmcgbG9naW4gdG9rZW5zXG4gIHVzZXJzLmNyZWF0ZUluZGV4KFwic2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zLndoZW5cIiwgeyBzcGFyc2U6IHRydWUgfSk7XG4gIC8vIEZvciBleHBpcmluZyBwYXNzd29yZCB0b2tlbnNcbiAgdXNlcnMuY3JlYXRlSW5kZXgoJ3NlcnZpY2VzLnBhc3N3b3JkLnJlc2V0LndoZW4nLCB7IHNwYXJzZTogdHJ1ZSB9KTtcbiAgdXNlcnMuY3JlYXRlSW5kZXgoJ3NlcnZpY2VzLnBhc3N3b3JkLmVucm9sbC53aGVuJywgeyBzcGFyc2U6IHRydWUgfSk7XG59O1xuXG5cbi8vIEdlbmVyYXRlcyBwZXJtdXRhdGlvbnMgb2YgYWxsIGNhc2UgdmFyaWF0aW9ucyBvZiBhIGdpdmVuIHN0cmluZy5cbmNvbnN0IGdlbmVyYXRlQ2FzZVBlcm11dGF0aW9uc0ZvclN0cmluZyA9IHN0cmluZyA9PiB7XG4gIGxldCBwZXJtdXRhdGlvbnMgPSBbJyddO1xuICBmb3IgKGxldCBpID0gMDsgaSA8IHN0cmluZy5sZW5ndGg7IGkrKykge1xuICAgIGNvbnN0IGNoID0gc3RyaW5nLmNoYXJBdChpKTtcbiAgICBwZXJtdXRhdGlvbnMgPSBbXS5jb25jYXQoLi4uKHBlcm11dGF0aW9ucy5tYXAocHJlZml4ID0+IHtcbiAgICAgIGNvbnN0IGxvd2VyQ2FzZUNoYXIgPSBjaC50b0xvd2VyQ2FzZSgpO1xuICAgICAgY29uc3QgdXBwZXJDYXNlQ2hhciA9IGNoLnRvVXBwZXJDYXNlKCk7XG4gICAgICAvLyBEb24ndCBhZGQgdW5uZWNlc3NhcnkgcGVybXV0YXRpb25zIHdoZW4gY2ggaXMgbm90IGEgbGV0dGVyXG4gICAgICBpZiAobG93ZXJDYXNlQ2hhciA9PT0gdXBwZXJDYXNlQ2hhcikge1xuICAgICAgICByZXR1cm4gW3ByZWZpeCArIGNoXTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJldHVybiBbcHJlZml4ICsgbG93ZXJDYXNlQ2hhciwgcHJlZml4ICsgdXBwZXJDYXNlQ2hhcl07XG4gICAgICB9XG4gICAgfSkpKTtcbiAgfVxuICByZXR1cm4gcGVybXV0YXRpb25zO1xufVxuXG4iXX0=
