(function () {

/* Imports */
var Meteor = Package.meteor.Meteor;
var global = Package.meteor.global;
var meteorEnv = Package.meteor.meteorEnv;
var ECMAScript = Package.ecmascript.ECMAScript;
var Accounts = Package['accounts-base'].Accounts;
var Facebook = Package['facebook-oauth'].Facebook;
var meteorInstall = Package.modules.meteorInstall;
var Promise = Package.promise.Promise;

var require = meteorInstall({"node_modules":{"meteor":{"accounts-facebook":{"notice.js":function module(){

///////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                       //
// packages/accounts-facebook/notice.js                                                                  //
//                                                                                                       //
///////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                         //
if (Package['accounts-ui'] && !Package['service-configuration'] && !Object.prototype.hasOwnProperty.call(Package, 'facebook-config-ui')) {
  console.warn("Note: You're using accounts-ui and accounts-facebook,\n" + "but didn't install the configuration UI for the Facebook\n" + "OAuth. You can install it with:\n" + "\n" + "    meteor add facebook-config-ui" + "\n");
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////

},"facebook.js":function module(){

///////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                       //
// packages/accounts-facebook/facebook.js                                                                //
//                                                                                                       //
///////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                         //
Accounts.oauth.registerService('facebook');

if (Meteor.isClient) {
  const loginWithFacebook = (options, callback) => {
    // support a callback without options
    if (!callback && typeof options === "function") {
      callback = options;
      options = null;
    }

    const credentialRequestCompleteCallback = Accounts.oauth.credentialRequestCompleteHandler(callback);
    Facebook.requestCredential(options, credentialRequestCompleteCallback);
  };

  Accounts.registerClientLoginFunction('facebook', loginWithFacebook);

  Meteor.loginWithFacebook = function () {
    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    return Accounts.applyLoginFunction('facebook', args);
  };
} else {
  Accounts.addAutopublishFields({
    // publish all fields including access token, which can legitimately
    // be used from the client (if transmitted over ssl or on
    // localhost). https://developers.facebook.com/docs/concepts/login/access-tokens-and-types/,
    // "Sharing of Access Tokens"
    forLoggedInUser: ['services.facebook'],
    forOtherUsers: [// https://www.facebook.com/help/167709519956542
    'services.facebook.id', 'services.facebook.username', 'services.facebook.gender']
  });
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////

}}}}},{
  "extensions": [
    ".js",
    ".json"
  ]
});

require("/node_modules/meteor/accounts-facebook/notice.js");
require("/node_modules/meteor/accounts-facebook/facebook.js");

/* Exports */
Package._define("accounts-facebook");

})();

//# sourceURL=meteor://💻app/packages/accounts-facebook.js
//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm1ldGVvcjovL/CfkrthcHAvcGFja2FnZXMvYWNjb3VudHMtZmFjZWJvb2svbm90aWNlLmpzIiwibWV0ZW9yOi8v8J+Su2FwcC9wYWNrYWdlcy9hY2NvdW50cy1mYWNlYm9vay9mYWNlYm9vay5qcyJdLCJuYW1lcyI6WyJQYWNrYWdlIiwiT2JqZWN0IiwicHJvdG90eXBlIiwiaGFzT3duUHJvcGVydHkiLCJjYWxsIiwiY29uc29sZSIsIndhcm4iLCJBY2NvdW50cyIsIm9hdXRoIiwicmVnaXN0ZXJTZXJ2aWNlIiwiTWV0ZW9yIiwiaXNDbGllbnQiLCJsb2dpbldpdGhGYWNlYm9vayIsIm9wdGlvbnMiLCJjYWxsYmFjayIsImNyZWRlbnRpYWxSZXF1ZXN0Q29tcGxldGVDYWxsYmFjayIsImNyZWRlbnRpYWxSZXF1ZXN0Q29tcGxldGVIYW5kbGVyIiwiRmFjZWJvb2siLCJyZXF1ZXN0Q3JlZGVudGlhbCIsInJlZ2lzdGVyQ2xpZW50TG9naW5GdW5jdGlvbiIsImFyZ3MiLCJhcHBseUxvZ2luRnVuY3Rpb24iLCJhZGRBdXRvcHVibGlzaEZpZWxkcyIsImZvckxvZ2dlZEluVXNlciIsImZvck90aGVyVXNlcnMiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUEsSUFBSUEsT0FBTyxDQUFDLGFBQUQsQ0FBUCxJQUNHLENBQUNBLE9BQU8sQ0FBQyx1QkFBRCxDQURYLElBRUcsQ0FBQ0MsTUFBTSxDQUFDQyxTQUFQLENBQWlCQyxjQUFqQixDQUFnQ0MsSUFBaEMsQ0FBcUNKLE9BQXJDLEVBQThDLG9CQUE5QyxDQUZSLEVBRTZFO0FBQzNFSyxTQUFPLENBQUNDLElBQVIsQ0FDRSw0REFDQSw0REFEQSxHQUVBLG1DQUZBLEdBR0EsSUFIQSxHQUlBLG1DQUpBLEdBS0EsSUFORjtBQVFELEM7Ozs7Ozs7Ozs7O0FDWERDLFFBQVEsQ0FBQ0MsS0FBVCxDQUFlQyxlQUFmLENBQStCLFVBQS9COztBQUVBLElBQUlDLE1BQU0sQ0FBQ0MsUUFBWCxFQUFxQjtBQUNuQixRQUFNQyxpQkFBaUIsR0FBRyxDQUFDQyxPQUFELEVBQVVDLFFBQVYsS0FBdUI7QUFDL0M7QUFDQSxRQUFJLENBQUVBLFFBQUYsSUFBYyxPQUFPRCxPQUFQLEtBQW1CLFVBQXJDLEVBQWlEO0FBQy9DQyxjQUFRLEdBQUdELE9BQVg7QUFDQUEsYUFBTyxHQUFHLElBQVY7QUFDRDs7QUFFRCxVQUFNRSxpQ0FBaUMsR0FBR1IsUUFBUSxDQUFDQyxLQUFULENBQWVRLGdDQUFmLENBQWdERixRQUFoRCxDQUExQztBQUNBRyxZQUFRLENBQUNDLGlCQUFULENBQTJCTCxPQUEzQixFQUFvQ0UsaUNBQXBDO0FBQ0QsR0FURDs7QUFVQVIsVUFBUSxDQUFDWSwyQkFBVCxDQUFxQyxVQUFyQyxFQUFpRFAsaUJBQWpEOztBQUNBRixRQUFNLENBQUNFLGlCQUFQLEdBQ0U7QUFBQSxzQ0FBSVEsSUFBSjtBQUFJQSxVQUFKO0FBQUE7O0FBQUEsV0FBYWIsUUFBUSxDQUFDYyxrQkFBVCxDQUE0QixVQUE1QixFQUF3Q0QsSUFBeEMsQ0FBYjtBQUFBLEdBREY7QUFFRCxDQWRELE1BY087QUFDTGIsVUFBUSxDQUFDZSxvQkFBVCxDQUE4QjtBQUM1QjtBQUNBO0FBQ0E7QUFDQTtBQUNBQyxtQkFBZSxFQUFFLENBQUMsbUJBQUQsQ0FMVztBQU01QkMsaUJBQWEsRUFBRSxDQUNiO0FBQ0EsMEJBRmEsRUFFVyw0QkFGWCxFQUV5QywwQkFGekM7QUFOYSxHQUE5QjtBQVdELEMiLCJmaWxlIjoiL3BhY2thZ2VzL2FjY291bnRzLWZhY2Vib29rLmpzIiwic291cmNlc0NvbnRlbnQiOlsiaWYgKFBhY2thZ2VbJ2FjY291bnRzLXVpJ11cbiAgICAmJiAhUGFja2FnZVsnc2VydmljZS1jb25maWd1cmF0aW9uJ11cbiAgICAmJiAhT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKFBhY2thZ2UsICdmYWNlYm9vay1jb25maWctdWknKSkge1xuICBjb25zb2xlLndhcm4oXG4gICAgXCJOb3RlOiBZb3UncmUgdXNpbmcgYWNjb3VudHMtdWkgYW5kIGFjY291bnRzLWZhY2Vib29rLFxcblwiICtcbiAgICBcImJ1dCBkaWRuJ3QgaW5zdGFsbCB0aGUgY29uZmlndXJhdGlvbiBVSSBmb3IgdGhlIEZhY2Vib29rXFxuXCIgK1xuICAgIFwiT0F1dGguIFlvdSBjYW4gaW5zdGFsbCBpdCB3aXRoOlxcblwiICtcbiAgICBcIlxcblwiICtcbiAgICBcIiAgICBtZXRlb3IgYWRkIGZhY2Vib29rLWNvbmZpZy11aVwiICtcbiAgICBcIlxcblwiXG4gICk7XG59XG4iLCJBY2NvdW50cy5vYXV0aC5yZWdpc3RlclNlcnZpY2UoJ2ZhY2Vib29rJyk7XG5cbmlmIChNZXRlb3IuaXNDbGllbnQpIHtcbiAgY29uc3QgbG9naW5XaXRoRmFjZWJvb2sgPSAob3B0aW9ucywgY2FsbGJhY2spID0+IHtcbiAgICAvLyBzdXBwb3J0IGEgY2FsbGJhY2sgd2l0aG91dCBvcHRpb25zXG4gICAgaWYgKCEgY2FsbGJhY2sgJiYgdHlwZW9mIG9wdGlvbnMgPT09IFwiZnVuY3Rpb25cIikge1xuICAgICAgY2FsbGJhY2sgPSBvcHRpb25zO1xuICAgICAgb3B0aW9ucyA9IG51bGw7XG4gICAgfVxuXG4gICAgY29uc3QgY3JlZGVudGlhbFJlcXVlc3RDb21wbGV0ZUNhbGxiYWNrID0gQWNjb3VudHMub2F1dGguY3JlZGVudGlhbFJlcXVlc3RDb21wbGV0ZUhhbmRsZXIoY2FsbGJhY2spO1xuICAgIEZhY2Vib29rLnJlcXVlc3RDcmVkZW50aWFsKG9wdGlvbnMsIGNyZWRlbnRpYWxSZXF1ZXN0Q29tcGxldGVDYWxsYmFjayk7XG4gIH07XG4gIEFjY291bnRzLnJlZ2lzdGVyQ2xpZW50TG9naW5GdW5jdGlvbignZmFjZWJvb2snLCBsb2dpbldpdGhGYWNlYm9vayk7XG4gIE1ldGVvci5sb2dpbldpdGhGYWNlYm9vayA9IFxuICAgICguLi5hcmdzKSA9PiBBY2NvdW50cy5hcHBseUxvZ2luRnVuY3Rpb24oJ2ZhY2Vib29rJywgYXJncyk7XG59IGVsc2Uge1xuICBBY2NvdW50cy5hZGRBdXRvcHVibGlzaEZpZWxkcyh7XG4gICAgLy8gcHVibGlzaCBhbGwgZmllbGRzIGluY2x1ZGluZyBhY2Nlc3MgdG9rZW4sIHdoaWNoIGNhbiBsZWdpdGltYXRlbHlcbiAgICAvLyBiZSB1c2VkIGZyb20gdGhlIGNsaWVudCAoaWYgdHJhbnNtaXR0ZWQgb3ZlciBzc2wgb3Igb25cbiAgICAvLyBsb2NhbGhvc3QpLiBodHRwczovL2RldmVsb3BlcnMuZmFjZWJvb2suY29tL2RvY3MvY29uY2VwdHMvbG9naW4vYWNjZXNzLXRva2Vucy1hbmQtdHlwZXMvLFxuICAgIC8vIFwiU2hhcmluZyBvZiBBY2Nlc3MgVG9rZW5zXCJcbiAgICBmb3JMb2dnZWRJblVzZXI6IFsnc2VydmljZXMuZmFjZWJvb2snXSxcbiAgICBmb3JPdGhlclVzZXJzOiBbXG4gICAgICAvLyBodHRwczovL3d3dy5mYWNlYm9vay5jb20vaGVscC8xNjc3MDk1MTk5NTY1NDJcbiAgICAgICdzZXJ2aWNlcy5mYWNlYm9vay5pZCcsICdzZXJ2aWNlcy5mYWNlYm9vay51c2VybmFtZScsICdzZXJ2aWNlcy5mYWNlYm9vay5nZW5kZXInXG4gICAgXVxuICB9KTtcbn1cbiJdfQ==
