(function () {

/* Imports */
var Meteor = Package.meteor.Meteor;
var global = Package.meteor.global;
var meteorEnv = Package.meteor.meteorEnv;
var Random = Package.random.Random;
var OAuth = Package.oauth.OAuth;
var ServiceConfiguration = Package['service-configuration'].ServiceConfiguration;
var ECMAScript = Package.ecmascript.ECMAScript;
var meteorInstall = Package.modules.meteorInstall;
var Promise = Package.promise.Promise;

var require = meteorInstall({"node_modules":{"meteor":{"oauth2":{"oauth2_server.js":function module(){

///////////////////////////////////////////////////////////////////////
//                                                                   //
// packages/oauth2/oauth2_server.js                                  //
//                                                                   //
///////////////////////////////////////////////////////////////////////
                                                                     //
// connect middleware
OAuth._requestHandlers['2'] = (service, query, res) => {
  let credentialSecret; // check if user authorized access

  if (!query.error) {
    // Prepare the login results before returning.
    // Run service-specific handler.
    const oauthResult = service.handleOauthRequest(query);
    credentialSecret = Random.secret();

    const credentialToken = OAuth._credentialTokenFromQuery(query); // Store the login result so it can be retrieved in another
    // browser tab by the result handler


    OAuth._storePendingCredential(credentialToken, {
      serviceName: service.serviceName,
      serviceData: oauthResult.serviceData,
      options: oauthResult.options
    }, credentialSecret);
  } // Either close the window, redirect, or render nothing
  // if all else fails


  OAuth._renderOauthResults(res, query, credentialSecret);
};
///////////////////////////////////////////////////////////////////////

}}}}},{
  "extensions": [
    ".js",
    ".json"
  ]
});

require("/node_modules/meteor/oauth2/oauth2_server.js");

/* Exports */
Package._define("oauth2");

})();

//# sourceURL=meteor://💻app/packages/oauth2.js
//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm1ldGVvcjovL/CfkrthcHAvcGFja2FnZXMvb2F1dGgyL29hdXRoMl9zZXJ2ZXIuanMiXSwibmFtZXMiOlsiT0F1dGgiLCJfcmVxdWVzdEhhbmRsZXJzIiwic2VydmljZSIsInF1ZXJ5IiwicmVzIiwiY3JlZGVudGlhbFNlY3JldCIsImVycm9yIiwib2F1dGhSZXN1bHQiLCJoYW5kbGVPYXV0aFJlcXVlc3QiLCJSYW5kb20iLCJzZWNyZXQiLCJjcmVkZW50aWFsVG9rZW4iLCJfY3JlZGVudGlhbFRva2VuRnJvbVF1ZXJ5IiwiX3N0b3JlUGVuZGluZ0NyZWRlbnRpYWwiLCJzZXJ2aWNlTmFtZSIsInNlcnZpY2VEYXRhIiwib3B0aW9ucyIsIl9yZW5kZXJPYXV0aFJlc3VsdHMiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBO0FBQ0FBLEtBQUssQ0FBQ0MsZ0JBQU4sQ0FBdUIsR0FBdkIsSUFBOEIsQ0FBQ0MsT0FBRCxFQUFVQyxLQUFWLEVBQWlCQyxHQUFqQixLQUF5QjtBQUNyRCxNQUFJQyxnQkFBSixDQURxRCxDQUdyRDs7QUFDQSxNQUFJLENBQUNGLEtBQUssQ0FBQ0csS0FBWCxFQUFrQjtBQUNoQjtBQUVBO0FBQ0EsVUFBTUMsV0FBVyxHQUFHTCxPQUFPLENBQUNNLGtCQUFSLENBQTJCTCxLQUEzQixDQUFwQjtBQUNBRSxvQkFBZ0IsR0FBR0ksTUFBTSxDQUFDQyxNQUFQLEVBQW5COztBQUVBLFVBQU1DLGVBQWUsR0FBR1gsS0FBSyxDQUFDWSx5QkFBTixDQUFnQ1QsS0FBaEMsQ0FBeEIsQ0FQZ0IsQ0FTaEI7QUFDQTs7O0FBQ0FILFNBQUssQ0FBQ2EsdUJBQU4sQ0FBOEJGLGVBQTlCLEVBQStDO0FBQzdDRyxpQkFBVyxFQUFFWixPQUFPLENBQUNZLFdBRHdCO0FBRTdDQyxpQkFBVyxFQUFFUixXQUFXLENBQUNRLFdBRm9CO0FBRzdDQyxhQUFPLEVBQUVULFdBQVcsQ0FBQ1M7QUFId0IsS0FBL0MsRUFJR1gsZ0JBSkg7QUFLRCxHQXBCb0QsQ0FzQnJEO0FBQ0E7OztBQUNBTCxPQUFLLENBQUNpQixtQkFBTixDQUEwQmIsR0FBMUIsRUFBK0JELEtBQS9CLEVBQXNDRSxnQkFBdEM7QUFDRCxDQXpCRCxDIiwiZmlsZSI6Ii9wYWNrYWdlcy9vYXV0aDIuanMiLCJzb3VyY2VzQ29udGVudCI6WyIvLyBjb25uZWN0IG1pZGRsZXdhcmVcbk9BdXRoLl9yZXF1ZXN0SGFuZGxlcnNbJzInXSA9IChzZXJ2aWNlLCBxdWVyeSwgcmVzKSA9PiB7XG4gIGxldCBjcmVkZW50aWFsU2VjcmV0O1xuXG4gIC8vIGNoZWNrIGlmIHVzZXIgYXV0aG9yaXplZCBhY2Nlc3NcbiAgaWYgKCFxdWVyeS5lcnJvcikge1xuICAgIC8vIFByZXBhcmUgdGhlIGxvZ2luIHJlc3VsdHMgYmVmb3JlIHJldHVybmluZy5cblxuICAgIC8vIFJ1biBzZXJ2aWNlLXNwZWNpZmljIGhhbmRsZXIuXG4gICAgY29uc3Qgb2F1dGhSZXN1bHQgPSBzZXJ2aWNlLmhhbmRsZU9hdXRoUmVxdWVzdChxdWVyeSk7XG4gICAgY3JlZGVudGlhbFNlY3JldCA9IFJhbmRvbS5zZWNyZXQoKTtcblxuICAgIGNvbnN0IGNyZWRlbnRpYWxUb2tlbiA9IE9BdXRoLl9jcmVkZW50aWFsVG9rZW5Gcm9tUXVlcnkocXVlcnkpO1xuXG4gICAgLy8gU3RvcmUgdGhlIGxvZ2luIHJlc3VsdCBzbyBpdCBjYW4gYmUgcmV0cmlldmVkIGluIGFub3RoZXJcbiAgICAvLyBicm93c2VyIHRhYiBieSB0aGUgcmVzdWx0IGhhbmRsZXJcbiAgICBPQXV0aC5fc3RvcmVQZW5kaW5nQ3JlZGVudGlhbChjcmVkZW50aWFsVG9rZW4sIHtcbiAgICAgIHNlcnZpY2VOYW1lOiBzZXJ2aWNlLnNlcnZpY2VOYW1lLFxuICAgICAgc2VydmljZURhdGE6IG9hdXRoUmVzdWx0LnNlcnZpY2VEYXRhLFxuICAgICAgb3B0aW9uczogb2F1dGhSZXN1bHQub3B0aW9uc1xuICAgIH0sIGNyZWRlbnRpYWxTZWNyZXQpO1xuICB9XG5cbiAgLy8gRWl0aGVyIGNsb3NlIHRoZSB3aW5kb3csIHJlZGlyZWN0LCBvciByZW5kZXIgbm90aGluZ1xuICAvLyBpZiBhbGwgZWxzZSBmYWlsc1xuICBPQXV0aC5fcmVuZGVyT2F1dGhSZXN1bHRzKHJlcywgcXVlcnksIGNyZWRlbnRpYWxTZWNyZXQpO1xufTtcbiJdfQ==
