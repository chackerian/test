(function () {

/* Imports */
var Meteor = Package.meteor.Meteor;
var global = Package.meteor.global;
var meteorEnv = Package.meteor.meteorEnv;
var ECMAScript = Package.ecmascript.ECMAScript;
var OAuth = Package.oauth.OAuth;
var HTTP = Package.http.HTTP;
var HTTPInternals = Package.http.HTTPInternals;
var ServiceConfiguration = Package['service-configuration'].ServiceConfiguration;
var meteorInstall = Package.modules.meteorInstall;
var Promise = Package.promise.Promise;

/* Package-scope variables */
var Facebook;

var require = meteorInstall({"node_modules":{"meteor":{"facebook-oauth":{"facebook_server.js":function module(require,exports,module){

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                   //
// packages/facebook-oauth/facebook_server.js                                                                        //
//                                                                                                                   //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                     //
var _Meteor$settings, _Meteor$settings$publ, _Meteor$settings$publ2, _Meteor$settings$publ3;

let _objectSpread;

module.link("@babel/runtime/helpers/objectSpread2", {
  default(v) {
    _objectSpread = v;
  }

}, 0);
let crypto;
module.link("crypto", {
  default(v) {
    crypto = v;
  }

}, 0);
let Accounts;
module.link("meteor/accounts-base", {
  Accounts(v) {
    Accounts = v;
  }

}, 1);
Facebook = {};
const API_VERSION = ((_Meteor$settings = Meteor.settings) === null || _Meteor$settings === void 0 ? void 0 : (_Meteor$settings$publ = _Meteor$settings.public) === null || _Meteor$settings$publ === void 0 ? void 0 : (_Meteor$settings$publ2 = _Meteor$settings$publ.packages) === null || _Meteor$settings$publ2 === void 0 ? void 0 : (_Meteor$settings$publ3 = _Meteor$settings$publ2['facebook-oauth']) === null || _Meteor$settings$publ3 === void 0 ? void 0 : _Meteor$settings$publ3.apiVersion) || '10.0';

Facebook.handleAuthFromAccessToken = (accessToken, expiresAt) => {
  // include basic fields from facebook
  // https://developers.facebook.com/docs/facebook-login/permissions/
  const whitelisted = ['id', 'email', 'name', 'first_name', 'last_name', 'middle_name', 'name_format', 'picture', 'short_name'];
  const identity = getIdentity(accessToken, whitelisted);
  const fields = {};
  whitelisted.forEach(field => fields[field] = identity[field]);

  const serviceData = _objectSpread({
    accessToken,
    expiresAt
  }, fields);

  return {
    serviceData,
    options: {
      profile: {
        name: identity.name
      }
    }
  };
};

Accounts.registerLoginHandler(request => {
  if (request.facebookSignIn !== true) {
    return;
  }

  const facebookData = Facebook.handleAuthFromAccessToken(request.accessToken, +new Date() + 1000 * request.expirationTime);
  return Accounts.updateOrCreateUserFromExternalService('facebook', facebookData.serviceData, facebookData.options);
});
OAuth.registerService('facebook', 2, null, query => {
  const response = getTokenResponse(query);
  const {
    accessToken
  } = response;
  const {
    expiresIn
  } = response;
  return Facebook.handleAuthFromAccessToken(accessToken, +new Date() + 1000 * expiresIn);
});

function getAbsoluteUrlOptions(query) {
  var _Meteor$settings2, _Meteor$settings2$pac, _Meteor$settings2$pac2;

  const overrideRootUrlFromStateRedirectUrl = (_Meteor$settings2 = Meteor.settings) === null || _Meteor$settings2 === void 0 ? void 0 : (_Meteor$settings2$pac = _Meteor$settings2.packages) === null || _Meteor$settings2$pac === void 0 ? void 0 : (_Meteor$settings2$pac2 = _Meteor$settings2$pac['facebook-oauth']) === null || _Meteor$settings2$pac2 === void 0 ? void 0 : _Meteor$settings2$pac2.overrideRootUrlFromStateRedirectUrl;

  if (!overrideRootUrlFromStateRedirectUrl) {
    return undefined;
  }

  try {
    const state = OAuth._stateFromQuery(query) || {};
    const redirectUrl = new URL(state.redirectUrl);
    return {
      rootUrl: redirectUrl.origin
    };
  } catch (e) {
    console.error("Failed to complete OAuth handshake with Facebook because it was not able to obtain the redirect url from the state and you are using overrideRootUrlFromStateRedirectUrl.", e);
    return undefined;
  }
} // returns an object containing:
// - accessToken
// - expiresIn: lifetime of token in seconds


const getTokenResponse = query => {
  const config = ServiceConfiguration.configurations.findOne({
    service: 'facebook'
  });
  if (!config) throw new ServiceConfiguration.ConfigError();
  let responseContent;

  try {
    const absoluteUrlOptions = getAbsoluteUrlOptions(query);

    const redirectUri = OAuth._redirectUri('facebook', config, undefined, absoluteUrlOptions); // Request an access token


    responseContent = HTTP.get("https://graph.facebook.com/v".concat(API_VERSION, "/oauth/access_token"), {
      params: {
        client_id: config.appId,
        redirect_uri: redirectUri,
        client_secret: OAuth.openSecret(config.secret),
        code: query.code
      }
    }).data;
  } catch (err) {
    throw Object.assign(new Error("Failed to complete OAuth handshake with Facebook. ".concat(err.message)), {
      response: err.response
    });
  }

  const fbAccessToken = responseContent.access_token;
  const fbExpires = responseContent.expires_in;

  if (!fbAccessToken) {
    throw new Error("Failed to complete OAuth handshake with facebook " + "-- can't find access token in HTTP response. ".concat(responseContent));
  }

  return {
    accessToken: fbAccessToken,
    expiresIn: fbExpires
  };
};

const getIdentity = (accessToken, fields) => {
  const config = ServiceConfiguration.configurations.findOne({
    service: 'facebook'
  });
  if (!config) throw new ServiceConfiguration.ConfigError(); // Generate app secret proof that is a sha256 hash of the app access token, with the app secret as the key
  // https://developers.facebook.com/docs/graph-api/securing-requests#appsecret_proof

  const hmac = crypto.createHmac('sha256', OAuth.openSecret(config.secret));
  hmac.update(accessToken);

  try {
    return HTTP.get("https://graph.facebook.com/v".concat(API_VERSION, "/me"), {
      params: {
        access_token: accessToken,
        appsecret_proof: hmac.digest('hex'),
        fields: fields.join(",")
      }
    }).data;
  } catch (err) {
    throw Object.assign(new Error("Failed to fetch identity from Facebook. ".concat(err.message)), {
      response: err.response
    });
  }
};

Facebook.retrieveCredential = (credentialToken, credentialSecret) => OAuth.retrieveCredential(credentialToken, credentialSecret);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}}}}},{
  "extensions": [
    ".js",
    ".json"
  ]
});

require("/node_modules/meteor/facebook-oauth/facebook_server.js");

/* Exports */
Package._define("facebook-oauth", {
  Facebook: Facebook
});

})();

//# sourceURL=meteor://💻app/packages/facebook-oauth.js
//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm1ldGVvcjovL/CfkrthcHAvcGFja2FnZXMvZmFjZWJvb2stb2F1dGgvZmFjZWJvb2tfc2VydmVyLmpzIl0sIm5hbWVzIjpbIl9vYmplY3RTcHJlYWQiLCJtb2R1bGUiLCJsaW5rIiwiZGVmYXVsdCIsInYiLCJjcnlwdG8iLCJBY2NvdW50cyIsIkZhY2Vib29rIiwiQVBJX1ZFUlNJT04iLCJNZXRlb3IiLCJzZXR0aW5ncyIsInB1YmxpYyIsInBhY2thZ2VzIiwiYXBpVmVyc2lvbiIsImhhbmRsZUF1dGhGcm9tQWNjZXNzVG9rZW4iLCJhY2Nlc3NUb2tlbiIsImV4cGlyZXNBdCIsIndoaXRlbGlzdGVkIiwiaWRlbnRpdHkiLCJnZXRJZGVudGl0eSIsImZpZWxkcyIsImZvckVhY2giLCJmaWVsZCIsInNlcnZpY2VEYXRhIiwib3B0aW9ucyIsInByb2ZpbGUiLCJuYW1lIiwicmVnaXN0ZXJMb2dpbkhhbmRsZXIiLCJyZXF1ZXN0IiwiZmFjZWJvb2tTaWduSW4iLCJmYWNlYm9va0RhdGEiLCJEYXRlIiwiZXhwaXJhdGlvblRpbWUiLCJ1cGRhdGVPckNyZWF0ZVVzZXJGcm9tRXh0ZXJuYWxTZXJ2aWNlIiwiT0F1dGgiLCJyZWdpc3RlclNlcnZpY2UiLCJxdWVyeSIsInJlc3BvbnNlIiwiZ2V0VG9rZW5SZXNwb25zZSIsImV4cGlyZXNJbiIsImdldEFic29sdXRlVXJsT3B0aW9ucyIsIm92ZXJyaWRlUm9vdFVybEZyb21TdGF0ZVJlZGlyZWN0VXJsIiwidW5kZWZpbmVkIiwic3RhdGUiLCJfc3RhdGVGcm9tUXVlcnkiLCJyZWRpcmVjdFVybCIsIlVSTCIsInJvb3RVcmwiLCJvcmlnaW4iLCJlIiwiY29uc29sZSIsImVycm9yIiwiY29uZmlnIiwiU2VydmljZUNvbmZpZ3VyYXRpb24iLCJjb25maWd1cmF0aW9ucyIsImZpbmRPbmUiLCJzZXJ2aWNlIiwiQ29uZmlnRXJyb3IiLCJyZXNwb25zZUNvbnRlbnQiLCJhYnNvbHV0ZVVybE9wdGlvbnMiLCJyZWRpcmVjdFVyaSIsIl9yZWRpcmVjdFVyaSIsIkhUVFAiLCJnZXQiLCJwYXJhbXMiLCJjbGllbnRfaWQiLCJhcHBJZCIsInJlZGlyZWN0X3VyaSIsImNsaWVudF9zZWNyZXQiLCJvcGVuU2VjcmV0Iiwic2VjcmV0IiwiY29kZSIsImRhdGEiLCJlcnIiLCJPYmplY3QiLCJhc3NpZ24iLCJFcnJvciIsIm1lc3NhZ2UiLCJmYkFjY2Vzc1Rva2VuIiwiYWNjZXNzX3Rva2VuIiwiZmJFeHBpcmVzIiwiZXhwaXJlc19pbiIsImhtYWMiLCJjcmVhdGVIbWFjIiwidXBkYXRlIiwiYXBwc2VjcmV0X3Byb29mIiwiZGlnZXN0Iiwiam9pbiIsInJldHJpZXZlQ3JlZGVudGlhbCIsImNyZWRlbnRpYWxUb2tlbiIsImNyZWRlbnRpYWxTZWNyZXQiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBLElBQUlBLGFBQUo7O0FBQWtCQyxNQUFNLENBQUNDLElBQVAsQ0FBWSxzQ0FBWixFQUFtRDtBQUFDQyxTQUFPLENBQUNDLENBQUQsRUFBRztBQUFDSixpQkFBYSxHQUFDSSxDQUFkO0FBQWdCOztBQUE1QixDQUFuRCxFQUFpRixDQUFqRjtBQUFsQixJQUFJQyxNQUFKO0FBQVdKLE1BQU0sQ0FBQ0MsSUFBUCxDQUFZLFFBQVosRUFBcUI7QUFBQ0MsU0FBTyxDQUFDQyxDQUFELEVBQUc7QUFBQ0MsVUFBTSxHQUFDRCxDQUFQO0FBQVM7O0FBQXJCLENBQXJCLEVBQTRDLENBQTVDO0FBQStDLElBQUlFLFFBQUo7QUFBYUwsTUFBTSxDQUFDQyxJQUFQLENBQVksc0JBQVosRUFBbUM7QUFBQ0ksVUFBUSxDQUFDRixDQUFELEVBQUc7QUFBQ0UsWUFBUSxHQUFDRixDQUFUO0FBQVc7O0FBQXhCLENBQW5DLEVBQTZELENBQTdEO0FBQXZFRyxRQUFRLEdBQUcsRUFBWDtBQUlBLE1BQU1DLFdBQVcsR0FBRyxxQkFBQUMsTUFBTSxDQUFDQyxRQUFQLCtGQUFpQkMsTUFBakIsMEdBQXlCQyxRQUF6Qiw0R0FBb0MsZ0JBQXBDLG1GQUF1REMsVUFBdkQsS0FBcUUsTUFBekY7O0FBRUFOLFFBQVEsQ0FBQ08seUJBQVQsR0FBcUMsQ0FBQ0MsV0FBRCxFQUFjQyxTQUFkLEtBQTRCO0FBQy9EO0FBQ0E7QUFDQSxRQUFNQyxXQUFXLEdBQUcsQ0FBQyxJQUFELEVBQU8sT0FBUCxFQUFnQixNQUFoQixFQUF3QixZQUF4QixFQUFzQyxXQUF0QyxFQUNsQixhQURrQixFQUNILGFBREcsRUFDWSxTQURaLEVBQ3VCLFlBRHZCLENBQXBCO0FBR0EsUUFBTUMsUUFBUSxHQUFHQyxXQUFXLENBQUNKLFdBQUQsRUFBY0UsV0FBZCxDQUE1QjtBQUVBLFFBQU1HLE1BQU0sR0FBRyxFQUFmO0FBQ0FILGFBQVcsQ0FBQ0ksT0FBWixDQUFvQkMsS0FBSyxJQUFJRixNQUFNLENBQUNFLEtBQUQsQ0FBTixHQUFnQkosUUFBUSxDQUFDSSxLQUFELENBQXJEOztBQUNBLFFBQU1DLFdBQVc7QUFDZlIsZUFEZTtBQUVmQztBQUZlLEtBR1pJLE1BSFksQ0FBakI7O0FBTUEsU0FBTztBQUNMRyxlQURLO0FBRUxDLFdBQU8sRUFBRTtBQUFDQyxhQUFPLEVBQUU7QUFBQ0MsWUFBSSxFQUFFUixRQUFRLENBQUNRO0FBQWhCO0FBQVY7QUFGSixHQUFQO0FBSUQsQ0FwQkQ7O0FBc0JBcEIsUUFBUSxDQUFDcUIsb0JBQVQsQ0FBOEJDLE9BQU8sSUFBSTtBQUN2QyxNQUFJQSxPQUFPLENBQUNDLGNBQVIsS0FBMkIsSUFBL0IsRUFBcUM7QUFDbkM7QUFDRDs7QUFDRCxRQUFNQyxZQUFZLEdBQUd2QixRQUFRLENBQUNPLHlCQUFULENBQW1DYyxPQUFPLENBQUNiLFdBQTNDLEVBQXlELENBQUMsSUFBSWdCLElBQUosRUFBRixHQUFlLE9BQU9ILE9BQU8sQ0FBQ0ksY0FBdEYsQ0FBckI7QUFDQSxTQUFPMUIsUUFBUSxDQUFDMkIscUNBQVQsQ0FBK0MsVUFBL0MsRUFBMkRILFlBQVksQ0FBQ1AsV0FBeEUsRUFBcUZPLFlBQVksQ0FBQ04sT0FBbEcsQ0FBUDtBQUNELENBTkQ7QUFRQVUsS0FBSyxDQUFDQyxlQUFOLENBQXNCLFVBQXRCLEVBQWtDLENBQWxDLEVBQXFDLElBQXJDLEVBQTJDQyxLQUFLLElBQUk7QUFDbEQsUUFBTUMsUUFBUSxHQUFHQyxnQkFBZ0IsQ0FBQ0YsS0FBRCxDQUFqQztBQUNBLFFBQU07QUFBRXJCO0FBQUYsTUFBa0JzQixRQUF4QjtBQUNBLFFBQU07QUFBRUU7QUFBRixNQUFnQkYsUUFBdEI7QUFFQSxTQUFPOUIsUUFBUSxDQUFDTyx5QkFBVCxDQUFtQ0MsV0FBbkMsRUFBaUQsQ0FBQyxJQUFJZ0IsSUFBSixFQUFGLEdBQWUsT0FBT1EsU0FBdEUsQ0FBUDtBQUNELENBTkQ7O0FBUUEsU0FBU0MscUJBQVQsQ0FBK0JKLEtBQS9CLEVBQXNDO0FBQUE7O0FBQ3BDLFFBQU1LLG1DQUFtQyx3QkFBR2hDLE1BQU0sQ0FBQ0MsUUFBViwrRUFBRyxrQkFBaUJFLFFBQXBCLG9GQUFHLHNCQUE0QixnQkFBNUIsQ0FBSCwyREFBRyx1QkFBK0M2QixtQ0FBM0Y7O0FBQ0EsTUFBSSxDQUFDQSxtQ0FBTCxFQUEwQztBQUN4QyxXQUFPQyxTQUFQO0FBQ0Q7O0FBQ0QsTUFBSTtBQUNGLFVBQU1DLEtBQUssR0FBR1QsS0FBSyxDQUFDVSxlQUFOLENBQXNCUixLQUF0QixLQUFnQyxFQUE5QztBQUNBLFVBQU1TLFdBQVcsR0FBRyxJQUFJQyxHQUFKLENBQVFILEtBQUssQ0FBQ0UsV0FBZCxDQUFwQjtBQUNBLFdBQU87QUFDTEUsYUFBTyxFQUFFRixXQUFXLENBQUNHO0FBRGhCLEtBQVA7QUFHRCxHQU5ELENBTUUsT0FBT0MsQ0FBUCxFQUFVO0FBQ1ZDLFdBQU8sQ0FBQ0MsS0FBUiw4S0FDK0tGLENBRC9LO0FBR0EsV0FBT1AsU0FBUDtBQUNEO0FBQ0YsQyxDQUVEO0FBQ0E7QUFDQTs7O0FBQ0EsTUFBTUosZ0JBQWdCLEdBQUdGLEtBQUssSUFBSTtBQUNoQyxRQUFNZ0IsTUFBTSxHQUFHQyxvQkFBb0IsQ0FBQ0MsY0FBckIsQ0FBb0NDLE9BQXBDLENBQTRDO0FBQUNDLFdBQU8sRUFBRTtBQUFWLEdBQTVDLENBQWY7QUFDQSxNQUFJLENBQUNKLE1BQUwsRUFDRSxNQUFNLElBQUlDLG9CQUFvQixDQUFDSSxXQUF6QixFQUFOO0FBRUYsTUFBSUMsZUFBSjs7QUFDQSxNQUFJO0FBRUYsVUFBTUMsa0JBQWtCLEdBQUduQixxQkFBcUIsQ0FBQ0osS0FBRCxDQUFoRDs7QUFDQSxVQUFNd0IsV0FBVyxHQUFHMUIsS0FBSyxDQUFDMkIsWUFBTixDQUFtQixVQUFuQixFQUErQlQsTUFBL0IsRUFBdUNWLFNBQXZDLEVBQWtEaUIsa0JBQWxELENBQXBCLENBSEUsQ0FJRjs7O0FBQ0FELG1CQUFlLEdBQUdJLElBQUksQ0FBQ0MsR0FBTCx1Q0FDZXZELFdBRGYsMEJBQ2lEO0FBQy9Ed0QsWUFBTSxFQUFFO0FBQ05DLGlCQUFTLEVBQUViLE1BQU0sQ0FBQ2MsS0FEWjtBQUVOQyxvQkFBWSxFQUFFUCxXQUZSO0FBR05RLHFCQUFhLEVBQUVsQyxLQUFLLENBQUNtQyxVQUFOLENBQWlCakIsTUFBTSxDQUFDa0IsTUFBeEIsQ0FIVDtBQUlOQyxZQUFJLEVBQUVuQyxLQUFLLENBQUNtQztBQUpOO0FBRHVELEtBRGpELEVBUWJDLElBUkw7QUFTRCxHQWRELENBY0UsT0FBT0MsR0FBUCxFQUFZO0FBQ1osVUFBTUMsTUFBTSxDQUFDQyxNQUFQLENBQ0osSUFBSUMsS0FBSiw2REFBK0RILEdBQUcsQ0FBQ0ksT0FBbkUsRUFESSxFQUVKO0FBQUV4QyxjQUFRLEVBQUVvQyxHQUFHLENBQUNwQztBQUFoQixLQUZJLENBQU47QUFJRDs7QUFFRCxRQUFNeUMsYUFBYSxHQUFHcEIsZUFBZSxDQUFDcUIsWUFBdEM7QUFDQSxRQUFNQyxTQUFTLEdBQUd0QixlQUFlLENBQUN1QixVQUFsQzs7QUFFQSxNQUFJLENBQUNILGFBQUwsRUFBb0I7QUFDbEIsVUFBTSxJQUFJRixLQUFKLENBQVUsNkdBQ2dEbEIsZUFEaEQsQ0FBVixDQUFOO0FBRUQ7O0FBQ0QsU0FBTztBQUNMM0MsZUFBVyxFQUFFK0QsYUFEUjtBQUVMdkMsYUFBUyxFQUFFeUM7QUFGTixHQUFQO0FBSUQsQ0F0Q0Q7O0FBd0NBLE1BQU03RCxXQUFXLEdBQUcsQ0FBQ0osV0FBRCxFQUFjSyxNQUFkLEtBQXlCO0FBQzNDLFFBQU1nQyxNQUFNLEdBQUdDLG9CQUFvQixDQUFDQyxjQUFyQixDQUFvQ0MsT0FBcEMsQ0FBNEM7QUFBQ0MsV0FBTyxFQUFFO0FBQVYsR0FBNUMsQ0FBZjtBQUNBLE1BQUksQ0FBQ0osTUFBTCxFQUNFLE1BQU0sSUFBSUMsb0JBQW9CLENBQUNJLFdBQXpCLEVBQU4sQ0FIeUMsQ0FLM0M7QUFDQTs7QUFDQSxRQUFNeUIsSUFBSSxHQUFHN0UsTUFBTSxDQUFDOEUsVUFBUCxDQUFrQixRQUFsQixFQUE0QmpELEtBQUssQ0FBQ21DLFVBQU4sQ0FBaUJqQixNQUFNLENBQUNrQixNQUF4QixDQUE1QixDQUFiO0FBQ0FZLE1BQUksQ0FBQ0UsTUFBTCxDQUFZckUsV0FBWjs7QUFFQSxNQUFJO0FBQ0YsV0FBTytDLElBQUksQ0FBQ0MsR0FBTCx1Q0FBd0N2RCxXQUF4QyxVQUEwRDtBQUMvRHdELFlBQU0sRUFBRTtBQUNOZSxvQkFBWSxFQUFFaEUsV0FEUjtBQUVOc0UsdUJBQWUsRUFBRUgsSUFBSSxDQUFDSSxNQUFMLENBQVksS0FBWixDQUZYO0FBR05sRSxjQUFNLEVBQUVBLE1BQU0sQ0FBQ21FLElBQVAsQ0FBWSxHQUFaO0FBSEY7QUFEdUQsS0FBMUQsRUFNSmYsSUFOSDtBQU9ELEdBUkQsQ0FRRSxPQUFPQyxHQUFQLEVBQVk7QUFDWixVQUFNQyxNQUFNLENBQUNDLE1BQVAsQ0FDSixJQUFJQyxLQUFKLG1EQUFxREgsR0FBRyxDQUFDSSxPQUF6RCxFQURJLEVBRUo7QUFBRXhDLGNBQVEsRUFBRW9DLEdBQUcsQ0FBQ3BDO0FBQWhCLEtBRkksQ0FBTjtBQUlEO0FBQ0YsQ0F4QkQ7O0FBMEJBOUIsUUFBUSxDQUFDaUYsa0JBQVQsR0FBOEIsQ0FBQ0MsZUFBRCxFQUFrQkMsZ0JBQWxCLEtBQzVCeEQsS0FBSyxDQUFDc0Qsa0JBQU4sQ0FBeUJDLGVBQXpCLEVBQTBDQyxnQkFBMUMsQ0FERixDIiwiZmlsZSI6Ii9wYWNrYWdlcy9mYWNlYm9vay1vYXV0aC5qcyIsInNvdXJjZXNDb250ZW50IjpbIkZhY2Vib29rID0ge307XG5pbXBvcnQgY3J5cHRvIGZyb20gJ2NyeXB0byc7XG5pbXBvcnQgeyBBY2NvdW50cyB9IGZyb20gJ21ldGVvci9hY2NvdW50cy1iYXNlJztcblxuY29uc3QgQVBJX1ZFUlNJT04gPSBNZXRlb3Iuc2V0dGluZ3M/LnB1YmxpYz8ucGFja2FnZXM/LlsnZmFjZWJvb2stb2F1dGgnXT8uYXBpVmVyc2lvbiB8fCAnMTAuMCc7XG5cbkZhY2Vib29rLmhhbmRsZUF1dGhGcm9tQWNjZXNzVG9rZW4gPSAoYWNjZXNzVG9rZW4sIGV4cGlyZXNBdCkgPT4ge1xuICAvLyBpbmNsdWRlIGJhc2ljIGZpZWxkcyBmcm9tIGZhY2Vib29rXG4gIC8vIGh0dHBzOi8vZGV2ZWxvcGVycy5mYWNlYm9vay5jb20vZG9jcy9mYWNlYm9vay1sb2dpbi9wZXJtaXNzaW9ucy9cbiAgY29uc3Qgd2hpdGVsaXN0ZWQgPSBbJ2lkJywgJ2VtYWlsJywgJ25hbWUnLCAnZmlyc3RfbmFtZScsICdsYXN0X25hbWUnLFxuICAgICdtaWRkbGVfbmFtZScsICduYW1lX2Zvcm1hdCcsICdwaWN0dXJlJywgJ3Nob3J0X25hbWUnXTtcblxuICBjb25zdCBpZGVudGl0eSA9IGdldElkZW50aXR5KGFjY2Vzc1Rva2VuLCB3aGl0ZWxpc3RlZCk7XG5cbiAgY29uc3QgZmllbGRzID0ge307XG4gIHdoaXRlbGlzdGVkLmZvckVhY2goZmllbGQgPT4gZmllbGRzW2ZpZWxkXSA9IGlkZW50aXR5W2ZpZWxkXSk7XG4gIGNvbnN0IHNlcnZpY2VEYXRhID0ge1xuICAgIGFjY2Vzc1Rva2VuLFxuICAgIGV4cGlyZXNBdCxcbiAgICAuLi5maWVsZHMsXG4gIH07XG5cbiAgcmV0dXJuIHtcbiAgICBzZXJ2aWNlRGF0YSxcbiAgICBvcHRpb25zOiB7cHJvZmlsZToge25hbWU6IGlkZW50aXR5Lm5hbWV9fVxuICB9O1xufTtcblxuQWNjb3VudHMucmVnaXN0ZXJMb2dpbkhhbmRsZXIocmVxdWVzdCA9PiB7XG4gIGlmIChyZXF1ZXN0LmZhY2Vib29rU2lnbkluICE9PSB0cnVlKSB7XG4gICAgcmV0dXJuO1xuICB9XG4gIGNvbnN0IGZhY2Vib29rRGF0YSA9IEZhY2Vib29rLmhhbmRsZUF1dGhGcm9tQWNjZXNzVG9rZW4ocmVxdWVzdC5hY2Nlc3NUb2tlbiwgKCtuZXcgRGF0ZSkgKyAoMTAwMCAqIHJlcXVlc3QuZXhwaXJhdGlvblRpbWUpKTtcbiAgcmV0dXJuIEFjY291bnRzLnVwZGF0ZU9yQ3JlYXRlVXNlckZyb21FeHRlcm5hbFNlcnZpY2UoJ2ZhY2Vib29rJywgZmFjZWJvb2tEYXRhLnNlcnZpY2VEYXRhLCBmYWNlYm9va0RhdGEub3B0aW9ucyk7XG59KTtcblxuT0F1dGgucmVnaXN0ZXJTZXJ2aWNlKCdmYWNlYm9vaycsIDIsIG51bGwsIHF1ZXJ5ID0+IHtcbiAgY29uc3QgcmVzcG9uc2UgPSBnZXRUb2tlblJlc3BvbnNlKHF1ZXJ5KTtcbiAgY29uc3QgeyBhY2Nlc3NUb2tlbiB9ID0gcmVzcG9uc2U7XG4gIGNvbnN0IHsgZXhwaXJlc0luIH0gPSByZXNwb25zZTtcblxuICByZXR1cm4gRmFjZWJvb2suaGFuZGxlQXV0aEZyb21BY2Nlc3NUb2tlbihhY2Nlc3NUb2tlbiwgKCtuZXcgRGF0ZSkgKyAoMTAwMCAqIGV4cGlyZXNJbikpO1xufSk7XG5cbmZ1bmN0aW9uIGdldEFic29sdXRlVXJsT3B0aW9ucyhxdWVyeSkge1xuICBjb25zdCBvdmVycmlkZVJvb3RVcmxGcm9tU3RhdGVSZWRpcmVjdFVybCA9IE1ldGVvci5zZXR0aW5ncz8ucGFja2FnZXM/LlsnZmFjZWJvb2stb2F1dGgnXT8ub3ZlcnJpZGVSb290VXJsRnJvbVN0YXRlUmVkaXJlY3RVcmw7XG4gIGlmICghb3ZlcnJpZGVSb290VXJsRnJvbVN0YXRlUmVkaXJlY3RVcmwpIHtcbiAgICByZXR1cm4gdW5kZWZpbmVkO1xuICB9XG4gIHRyeSB7XG4gICAgY29uc3Qgc3RhdGUgPSBPQXV0aC5fc3RhdGVGcm9tUXVlcnkocXVlcnkpIHx8IHt9O1xuICAgIGNvbnN0IHJlZGlyZWN0VXJsID0gbmV3IFVSTChzdGF0ZS5yZWRpcmVjdFVybCk7XG4gICAgcmV0dXJuIHtcbiAgICAgIHJvb3RVcmw6IHJlZGlyZWN0VXJsLm9yaWdpbixcbiAgICB9XG4gIH0gY2F0Y2ggKGUpIHtcbiAgICBjb25zb2xlLmVycm9yKFxuICAgICAgYEZhaWxlZCB0byBjb21wbGV0ZSBPQXV0aCBoYW5kc2hha2Ugd2l0aCBGYWNlYm9vayBiZWNhdXNlIGl0IHdhcyBub3QgYWJsZSB0byBvYnRhaW4gdGhlIHJlZGlyZWN0IHVybCBmcm9tIHRoZSBzdGF0ZSBhbmQgeW91IGFyZSB1c2luZyBvdmVycmlkZVJvb3RVcmxGcm9tU3RhdGVSZWRpcmVjdFVybC5gLCBlXG4gICAgKTtcbiAgICByZXR1cm4gdW5kZWZpbmVkO1xuICB9XG59XG5cbi8vIHJldHVybnMgYW4gb2JqZWN0IGNvbnRhaW5pbmc6XG4vLyAtIGFjY2Vzc1Rva2VuXG4vLyAtIGV4cGlyZXNJbjogbGlmZXRpbWUgb2YgdG9rZW4gaW4gc2Vjb25kc1xuY29uc3QgZ2V0VG9rZW5SZXNwb25zZSA9IHF1ZXJ5ID0+IHtcbiAgY29uc3QgY29uZmlnID0gU2VydmljZUNvbmZpZ3VyYXRpb24uY29uZmlndXJhdGlvbnMuZmluZE9uZSh7c2VydmljZTogJ2ZhY2Vib29rJ30pO1xuICBpZiAoIWNvbmZpZylcbiAgICB0aHJvdyBuZXcgU2VydmljZUNvbmZpZ3VyYXRpb24uQ29uZmlnRXJyb3IoKTtcblxuICBsZXQgcmVzcG9uc2VDb250ZW50O1xuICB0cnkge1xuXG4gICAgY29uc3QgYWJzb2x1dGVVcmxPcHRpb25zID0gZ2V0QWJzb2x1dGVVcmxPcHRpb25zKHF1ZXJ5KTtcbiAgICBjb25zdCByZWRpcmVjdFVyaSA9IE9BdXRoLl9yZWRpcmVjdFVyaSgnZmFjZWJvb2snLCBjb25maWcsIHVuZGVmaW5lZCwgYWJzb2x1dGVVcmxPcHRpb25zKTtcbiAgICAvLyBSZXF1ZXN0IGFuIGFjY2VzcyB0b2tlblxuICAgIHJlc3BvbnNlQ29udGVudCA9IEhUVFAuZ2V0KFxuICAgICAgYGh0dHBzOi8vZ3JhcGguZmFjZWJvb2suY29tL3Yke0FQSV9WRVJTSU9OfS9vYXV0aC9hY2Nlc3NfdG9rZW5gLCB7XG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGNsaWVudF9pZDogY29uZmlnLmFwcElkLFxuICAgICAgICAgIHJlZGlyZWN0X3VyaTogcmVkaXJlY3RVcmksXG4gICAgICAgICAgY2xpZW50X3NlY3JldDogT0F1dGgub3BlblNlY3JldChjb25maWcuc2VjcmV0KSxcbiAgICAgICAgICBjb2RlOiBxdWVyeS5jb2RlXG4gICAgICAgIH1cbiAgICAgIH0pLmRhdGE7XG4gIH0gY2F0Y2ggKGVycikge1xuICAgIHRocm93IE9iamVjdC5hc3NpZ24oXG4gICAgICBuZXcgRXJyb3IoYEZhaWxlZCB0byBjb21wbGV0ZSBPQXV0aCBoYW5kc2hha2Ugd2l0aCBGYWNlYm9vay4gJHtlcnIubWVzc2FnZX1gKSxcbiAgICAgIHsgcmVzcG9uc2U6IGVyci5yZXNwb25zZSB9LFxuICAgICk7XG4gIH1cblxuICBjb25zdCBmYkFjY2Vzc1Rva2VuID0gcmVzcG9uc2VDb250ZW50LmFjY2Vzc190b2tlbjtcbiAgY29uc3QgZmJFeHBpcmVzID0gcmVzcG9uc2VDb250ZW50LmV4cGlyZXNfaW47XG5cbiAgaWYgKCFmYkFjY2Vzc1Rva2VuKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKFwiRmFpbGVkIHRvIGNvbXBsZXRlIE9BdXRoIGhhbmRzaGFrZSB3aXRoIGZhY2Vib29rIFwiICtcbiAgICAgICAgICAgICAgICAgICAgYC0tIGNhbid0IGZpbmQgYWNjZXNzIHRva2VuIGluIEhUVFAgcmVzcG9uc2UuICR7cmVzcG9uc2VDb250ZW50fWApO1xuICB9XG4gIHJldHVybiB7XG4gICAgYWNjZXNzVG9rZW46IGZiQWNjZXNzVG9rZW4sXG4gICAgZXhwaXJlc0luOiBmYkV4cGlyZXNcbiAgfTtcbn07XG5cbmNvbnN0IGdldElkZW50aXR5ID0gKGFjY2Vzc1Rva2VuLCBmaWVsZHMpID0+IHtcbiAgY29uc3QgY29uZmlnID0gU2VydmljZUNvbmZpZ3VyYXRpb24uY29uZmlndXJhdGlvbnMuZmluZE9uZSh7c2VydmljZTogJ2ZhY2Vib29rJ30pO1xuICBpZiAoIWNvbmZpZylcbiAgICB0aHJvdyBuZXcgU2VydmljZUNvbmZpZ3VyYXRpb24uQ29uZmlnRXJyb3IoKTtcblxuICAvLyBHZW5lcmF0ZSBhcHAgc2VjcmV0IHByb29mIHRoYXQgaXMgYSBzaGEyNTYgaGFzaCBvZiB0aGUgYXBwIGFjY2VzcyB0b2tlbiwgd2l0aCB0aGUgYXBwIHNlY3JldCBhcyB0aGUga2V5XG4gIC8vIGh0dHBzOi8vZGV2ZWxvcGVycy5mYWNlYm9vay5jb20vZG9jcy9ncmFwaC1hcGkvc2VjdXJpbmctcmVxdWVzdHMjYXBwc2VjcmV0X3Byb29mXG4gIGNvbnN0IGhtYWMgPSBjcnlwdG8uY3JlYXRlSG1hYygnc2hhMjU2JywgT0F1dGgub3BlblNlY3JldChjb25maWcuc2VjcmV0KSk7XG4gIGhtYWMudXBkYXRlKGFjY2Vzc1Rva2VuKTtcblxuICB0cnkge1xuICAgIHJldHVybiBIVFRQLmdldChgaHR0cHM6Ly9ncmFwaC5mYWNlYm9vay5jb20vdiR7QVBJX1ZFUlNJT059L21lYCwge1xuICAgICAgcGFyYW1zOiB7XG4gICAgICAgIGFjY2Vzc190b2tlbjogYWNjZXNzVG9rZW4sXG4gICAgICAgIGFwcHNlY3JldF9wcm9vZjogaG1hYy5kaWdlc3QoJ2hleCcpLFxuICAgICAgICBmaWVsZHM6IGZpZWxkcy5qb2luKFwiLFwiKVxuICAgICAgfVxuICAgIH0pLmRhdGE7XG4gIH0gY2F0Y2ggKGVycikge1xuICAgIHRocm93IE9iamVjdC5hc3NpZ24oXG4gICAgICBuZXcgRXJyb3IoYEZhaWxlZCB0byBmZXRjaCBpZGVudGl0eSBmcm9tIEZhY2Vib29rLiAke2Vyci5tZXNzYWdlfWApLFxuICAgICAgeyByZXNwb25zZTogZXJyLnJlc3BvbnNlIH0sXG4gICAgKTtcbiAgfVxufTtcblxuRmFjZWJvb2sucmV0cmlldmVDcmVkZW50aWFsID0gKGNyZWRlbnRpYWxUb2tlbiwgY3JlZGVudGlhbFNlY3JldCkgPT5cbiAgT0F1dGgucmV0cmlldmVDcmVkZW50aWFsKGNyZWRlbnRpYWxUb2tlbiwgY3JlZGVudGlhbFNlY3JldCk7XG5cbiJdfQ==
