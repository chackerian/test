(function () {

/* Imports */
var Meteor = Package.meteor.Meteor;
var global = Package.meteor.global;
var meteorEnv = Package.meteor.meteorEnv;
var check = Package.check.check;
var Match = Package.check.Match;
var WebApp = Package.webapp.WebApp;
var WebAppInternals = Package.webapp.WebAppInternals;
var main = Package.webapp.main;
var Accounts = Package['accounts-base'].Accounts;
var ECMAScript = Package.ecmascript.ECMAScript;
var OAuth = Package.oauth.OAuth;
var meteorInstall = Package.modules.meteorInstall;
var Promise = Package.promise.Promise;

var require = meteorInstall({"node_modules":{"meteor":{"accounts-oauth":{"oauth_common.js":function module(){

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                 //
// packages/accounts-oauth/oauth_common.js                                                                         //
//                                                                                                                 //
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                   //
Accounts.oauth = {};
const services = {};
const hasOwn = Object.prototype.hasOwnProperty; // Helper for registering OAuth based accounts packages.
// On the server, adds an index to the user collection.

Accounts.oauth.registerService = name => {
  if (hasOwn.call(services, name)) throw new Error("Duplicate service: ".concat(name));
  services[name] = true;

  if (Meteor.server) {
    // Accounts.updateOrCreateUserFromExternalService does a lookup by this id,
    // so this should be a unique index. You might want to add indexes for other
    // fields returned by your service (eg services.github.login) but you can do
    // that in your app.
    Meteor.users.createIndex("services.".concat(name, ".id"), {
      unique: true,
      sparse: true
    });
  }
}; // Removes a previously registered service.
// This will disable logging in with this service, and serviceNames() will not
// contain it.
// It's worth noting that already logged in users will remain logged in unless
// you manually expire their sessions.


Accounts.oauth.unregisterService = name => {
  if (!hasOwn.call(services, name)) throw new Error("Service not found: ".concat(name));
  delete services[name];
};

Accounts.oauth.serviceNames = () => Object.keys(services);
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

},"oauth_server.js":function module(){

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                 //
// packages/accounts-oauth/oauth_server.js                                                                         //
//                                                                                                                 //
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                   //
// Listen to calls to `login` with an oauth option set. This is where
// users actually get logged in to meteor via oauth.
Accounts.registerLoginHandler(options => {
  if (!options.oauth) return undefined; // don't handle

  check(options.oauth, {
    credentialToken: String,
    // When an error occurs while retrieving the access token, we store
    // the error in the pending credentials table, with a secret of
    // null. The client can call the login method with a secret of null
    // to retrieve the error.
    credentialSecret: Match.OneOf(null, String)
  });
  const result = OAuth.retrieveCredential(options.oauth.credentialToken, options.oauth.credentialSecret);

  if (!result) {
    // OAuth credentialToken is not recognized, which could be either
    // because the popup was closed by the user before completion, or
    // some sort of error where the oauth provider didn't talk to our
    // server correctly and closed the popup somehow.
    //
    // We assume it was user canceled and report it as such, using a
    // numeric code that the client recognizes (XXX this will get
    // replaced by a symbolic error code at some point
    // https://trello.com/c/kMkw800Z/53-official-ddp-specification). This
    // will mask failures where things are misconfigured such that the
    // server doesn't see the request but does close the window. This
    // seems unlikely.
    //
    // XXX we want `type` to be the service name such as "facebook"
    return {
      type: "oauth",
      error: new Meteor.Error(Accounts.LoginCancelledError.numericError, "No matching login attempt found")
    };
  }

  if (result instanceof Error) // We tried to login, but there was a fatal error. Report it back
    // to the user.
    throw result;else {
    if (!Accounts.oauth.serviceNames().includes(result.serviceName)) {
      // serviceName was not found in the registered services list.
      // This could happen because the service never registered itself or
      // unregisterService was called on it.
      return {
        type: "oauth",
        error: new Meteor.Error(Accounts.LoginCancelledError.numericError, "No registered oauth service found for: ".concat(result.serviceName))
      };
    }

    return Accounts.updateOrCreateUserFromExternalService(result.serviceName, result.serviceData, result.options);
  }
});
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}}}}},{
  "extensions": [
    ".js",
    ".json"
  ]
});

require("/node_modules/meteor/accounts-oauth/oauth_common.js");
require("/node_modules/meteor/accounts-oauth/oauth_server.js");

/* Exports */
Package._define("accounts-oauth");

})();

//# sourceURL=meteor://💻app/packages/accounts-oauth.js
//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm1ldGVvcjovL/CfkrthcHAvcGFja2FnZXMvYWNjb3VudHMtb2F1dGgvb2F1dGhfY29tbW9uLmpzIiwibWV0ZW9yOi8v8J+Su2FwcC9wYWNrYWdlcy9hY2NvdW50cy1vYXV0aC9vYXV0aF9zZXJ2ZXIuanMiXSwibmFtZXMiOlsiQWNjb3VudHMiLCJvYXV0aCIsInNlcnZpY2VzIiwiaGFzT3duIiwiT2JqZWN0IiwicHJvdG90eXBlIiwiaGFzT3duUHJvcGVydHkiLCJyZWdpc3RlclNlcnZpY2UiLCJuYW1lIiwiY2FsbCIsIkVycm9yIiwiTWV0ZW9yIiwic2VydmVyIiwidXNlcnMiLCJjcmVhdGVJbmRleCIsInVuaXF1ZSIsInNwYXJzZSIsInVucmVnaXN0ZXJTZXJ2aWNlIiwic2VydmljZU5hbWVzIiwia2V5cyIsInJlZ2lzdGVyTG9naW5IYW5kbGVyIiwib3B0aW9ucyIsInVuZGVmaW5lZCIsImNoZWNrIiwiY3JlZGVudGlhbFRva2VuIiwiU3RyaW5nIiwiY3JlZGVudGlhbFNlY3JldCIsIk1hdGNoIiwiT25lT2YiLCJyZXN1bHQiLCJPQXV0aCIsInJldHJpZXZlQ3JlZGVudGlhbCIsInR5cGUiLCJlcnJvciIsIkxvZ2luQ2FuY2VsbGVkRXJyb3IiLCJudW1lcmljRXJyb3IiLCJpbmNsdWRlcyIsInNlcnZpY2VOYW1lIiwidXBkYXRlT3JDcmVhdGVVc2VyRnJvbUV4dGVybmFsU2VydmljZSIsInNlcnZpY2VEYXRhIl0sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUFBLFFBQVEsQ0FBQ0MsS0FBVCxHQUFpQixFQUFqQjtBQUVBLE1BQU1DLFFBQVEsR0FBRyxFQUFqQjtBQUNBLE1BQU1DLE1BQU0sR0FBR0MsTUFBTSxDQUFDQyxTQUFQLENBQWlCQyxjQUFoQyxDLENBRUE7QUFDQTs7QUFDQU4sUUFBUSxDQUFDQyxLQUFULENBQWVNLGVBQWYsR0FBaUNDLElBQUksSUFBSTtBQUN2QyxNQUFJTCxNQUFNLENBQUNNLElBQVAsQ0FBWVAsUUFBWixFQUFzQk0sSUFBdEIsQ0FBSixFQUNFLE1BQU0sSUFBSUUsS0FBSiw4QkFBZ0NGLElBQWhDLEVBQU47QUFDRk4sVUFBUSxDQUFDTSxJQUFELENBQVIsR0FBaUIsSUFBakI7O0FBRUEsTUFBSUcsTUFBTSxDQUFDQyxNQUFYLEVBQW1CO0FBQ2pCO0FBQ0E7QUFDQTtBQUNBO0FBQ0FELFVBQU0sQ0FBQ0UsS0FBUCxDQUFhQyxXQUFiLG9CQUFxQ04sSUFBckMsVUFBZ0Q7QUFBQ08sWUFBTSxFQUFFLElBQVQ7QUFBZUMsWUFBTSxFQUFFO0FBQXZCLEtBQWhEO0FBQ0Q7QUFDRixDQVpELEMsQ0FjQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7QUFDQWhCLFFBQVEsQ0FBQ0MsS0FBVCxDQUFlZ0IsaUJBQWYsR0FBbUNULElBQUksSUFBSTtBQUN6QyxNQUFJLENBQUNMLE1BQU0sQ0FBQ00sSUFBUCxDQUFZUCxRQUFaLEVBQXNCTSxJQUF0QixDQUFMLEVBQ0UsTUFBTSxJQUFJRSxLQUFKLDhCQUFnQ0YsSUFBaEMsRUFBTjtBQUNGLFNBQU9OLFFBQVEsQ0FBQ00sSUFBRCxDQUFmO0FBQ0QsQ0FKRDs7QUFNQVIsUUFBUSxDQUFDQyxLQUFULENBQWVpQixZQUFmLEdBQThCLE1BQU1kLE1BQU0sQ0FBQ2UsSUFBUCxDQUFZakIsUUFBWixDQUFwQyxDOzs7Ozs7Ozs7OztBQ2hDQTtBQUNBO0FBQ0FGLFFBQVEsQ0FBQ29CLG9CQUFULENBQThCQyxPQUFPLElBQUk7QUFDdkMsTUFBSSxDQUFDQSxPQUFPLENBQUNwQixLQUFiLEVBQ0UsT0FBT3FCLFNBQVAsQ0FGcUMsQ0FFbkI7O0FBRXBCQyxPQUFLLENBQUNGLE9BQU8sQ0FBQ3BCLEtBQVQsRUFBZ0I7QUFDbkJ1QixtQkFBZSxFQUFFQyxNQURFO0FBRW5CO0FBQ0E7QUFDQTtBQUNBO0FBQ0FDLG9CQUFnQixFQUFFQyxLQUFLLENBQUNDLEtBQU4sQ0FBWSxJQUFaLEVBQWtCSCxNQUFsQjtBQU5DLEdBQWhCLENBQUw7QUFTQSxRQUFNSSxNQUFNLEdBQUdDLEtBQUssQ0FBQ0Msa0JBQU4sQ0FBeUJWLE9BQU8sQ0FBQ3BCLEtBQVIsQ0FBY3VCLGVBQXZDLEVBQ3VCSCxPQUFPLENBQUNwQixLQUFSLENBQWN5QixnQkFEckMsQ0FBZjs7QUFHQSxNQUFJLENBQUNHLE1BQUwsRUFBYTtBQUNYO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxXQUFPO0FBQUVHLFVBQUksRUFBRSxPQUFSO0FBQ0VDLFdBQUssRUFBRSxJQUFJdEIsTUFBTSxDQUFDRCxLQUFYLENBQ0xWLFFBQVEsQ0FBQ2tDLG1CQUFULENBQTZCQyxZQUR4QixFQUVMLGlDQUZLO0FBRFQsS0FBUDtBQUlEOztBQUVELE1BQUlOLE1BQU0sWUFBWW5CLEtBQXRCLEVBQ0U7QUFDQTtBQUNBLFVBQU1tQixNQUFOLENBSEYsS0FJSztBQUNILFFBQUksQ0FBRTdCLFFBQVEsQ0FBQ0MsS0FBVCxDQUFlaUIsWUFBZixHQUE4QmtCLFFBQTlCLENBQXVDUCxNQUFNLENBQUNRLFdBQTlDLENBQU4sRUFBa0U7QUFDaEU7QUFDQTtBQUNBO0FBQ0EsYUFBTztBQUFFTCxZQUFJLEVBQUUsT0FBUjtBQUNFQyxhQUFLLEVBQUUsSUFBSXRCLE1BQU0sQ0FBQ0QsS0FBWCxDQUNMVixRQUFRLENBQUNrQyxtQkFBVCxDQUE2QkMsWUFEeEIsbURBRXFDTixNQUFNLENBQUNRLFdBRjVDO0FBRFQsT0FBUDtBQUtEOztBQUNELFdBQU9yQyxRQUFRLENBQUNzQyxxQ0FBVCxDQUErQ1QsTUFBTSxDQUFDUSxXQUF0RCxFQUFtRVIsTUFBTSxDQUFDVSxXQUExRSxFQUF1RlYsTUFBTSxDQUFDUixPQUE5RixDQUFQO0FBQ0Q7QUFDRixDQXRERCxFIiwiZmlsZSI6Ii9wYWNrYWdlcy9hY2NvdW50cy1vYXV0aC5qcyIsInNvdXJjZXNDb250ZW50IjpbIkFjY291bnRzLm9hdXRoID0ge307XG5cbmNvbnN0IHNlcnZpY2VzID0ge307XG5jb25zdCBoYXNPd24gPSBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5O1xuXG4vLyBIZWxwZXIgZm9yIHJlZ2lzdGVyaW5nIE9BdXRoIGJhc2VkIGFjY291bnRzIHBhY2thZ2VzLlxuLy8gT24gdGhlIHNlcnZlciwgYWRkcyBhbiBpbmRleCB0byB0aGUgdXNlciBjb2xsZWN0aW9uLlxuQWNjb3VudHMub2F1dGgucmVnaXN0ZXJTZXJ2aWNlID0gbmFtZSA9PiB7XG4gIGlmIChoYXNPd24uY2FsbChzZXJ2aWNlcywgbmFtZSkpXG4gICAgdGhyb3cgbmV3IEVycm9yKGBEdXBsaWNhdGUgc2VydmljZTogJHtuYW1lfWApO1xuICBzZXJ2aWNlc1tuYW1lXSA9IHRydWU7XG5cbiAgaWYgKE1ldGVvci5zZXJ2ZXIpIHtcbiAgICAvLyBBY2NvdW50cy51cGRhdGVPckNyZWF0ZVVzZXJGcm9tRXh0ZXJuYWxTZXJ2aWNlIGRvZXMgYSBsb29rdXAgYnkgdGhpcyBpZCxcbiAgICAvLyBzbyB0aGlzIHNob3VsZCBiZSBhIHVuaXF1ZSBpbmRleC4gWW91IG1pZ2h0IHdhbnQgdG8gYWRkIGluZGV4ZXMgZm9yIG90aGVyXG4gICAgLy8gZmllbGRzIHJldHVybmVkIGJ5IHlvdXIgc2VydmljZSAoZWcgc2VydmljZXMuZ2l0aHViLmxvZ2luKSBidXQgeW91IGNhbiBkb1xuICAgIC8vIHRoYXQgaW4geW91ciBhcHAuXG4gICAgTWV0ZW9yLnVzZXJzLmNyZWF0ZUluZGV4KGBzZXJ2aWNlcy4ke25hbWV9LmlkYCwge3VuaXF1ZTogdHJ1ZSwgc3BhcnNlOiB0cnVlfSk7XG4gIH1cbn07XG5cbi8vIFJlbW92ZXMgYSBwcmV2aW91c2x5IHJlZ2lzdGVyZWQgc2VydmljZS5cbi8vIFRoaXMgd2lsbCBkaXNhYmxlIGxvZ2dpbmcgaW4gd2l0aCB0aGlzIHNlcnZpY2UsIGFuZCBzZXJ2aWNlTmFtZXMoKSB3aWxsIG5vdFxuLy8gY29udGFpbiBpdC5cbi8vIEl0J3Mgd29ydGggbm90aW5nIHRoYXQgYWxyZWFkeSBsb2dnZWQgaW4gdXNlcnMgd2lsbCByZW1haW4gbG9nZ2VkIGluIHVubGVzc1xuLy8geW91IG1hbnVhbGx5IGV4cGlyZSB0aGVpciBzZXNzaW9ucy5cbkFjY291bnRzLm9hdXRoLnVucmVnaXN0ZXJTZXJ2aWNlID0gbmFtZSA9PiB7XG4gIGlmICghaGFzT3duLmNhbGwoc2VydmljZXMsIG5hbWUpKVxuICAgIHRocm93IG5ldyBFcnJvcihgU2VydmljZSBub3QgZm91bmQ6ICR7bmFtZX1gKTtcbiAgZGVsZXRlIHNlcnZpY2VzW25hbWVdO1xufTtcblxuQWNjb3VudHMub2F1dGguc2VydmljZU5hbWVzID0gKCkgPT4gT2JqZWN0LmtleXMoc2VydmljZXMpO1xuIiwiLy8gTGlzdGVuIHRvIGNhbGxzIHRvIGBsb2dpbmAgd2l0aCBhbiBvYXV0aCBvcHRpb24gc2V0LiBUaGlzIGlzIHdoZXJlXG4vLyB1c2VycyBhY3R1YWxseSBnZXQgbG9nZ2VkIGluIHRvIG1ldGVvciB2aWEgb2F1dGguXG5BY2NvdW50cy5yZWdpc3RlckxvZ2luSGFuZGxlcihvcHRpb25zID0+IHtcbiAgaWYgKCFvcHRpb25zLm9hdXRoKVxuICAgIHJldHVybiB1bmRlZmluZWQ7IC8vIGRvbid0IGhhbmRsZVxuXG4gIGNoZWNrKG9wdGlvbnMub2F1dGgsIHtcbiAgICBjcmVkZW50aWFsVG9rZW46IFN0cmluZyxcbiAgICAvLyBXaGVuIGFuIGVycm9yIG9jY3VycyB3aGlsZSByZXRyaWV2aW5nIHRoZSBhY2Nlc3MgdG9rZW4sIHdlIHN0b3JlXG4gICAgLy8gdGhlIGVycm9yIGluIHRoZSBwZW5kaW5nIGNyZWRlbnRpYWxzIHRhYmxlLCB3aXRoIGEgc2VjcmV0IG9mXG4gICAgLy8gbnVsbC4gVGhlIGNsaWVudCBjYW4gY2FsbCB0aGUgbG9naW4gbWV0aG9kIHdpdGggYSBzZWNyZXQgb2YgbnVsbFxuICAgIC8vIHRvIHJldHJpZXZlIHRoZSBlcnJvci5cbiAgICBjcmVkZW50aWFsU2VjcmV0OiBNYXRjaC5PbmVPZihudWxsLCBTdHJpbmcpXG4gIH0pO1xuXG4gIGNvbnN0IHJlc3VsdCA9IE9BdXRoLnJldHJpZXZlQ3JlZGVudGlhbChvcHRpb25zLm9hdXRoLmNyZWRlbnRpYWxUb2tlbixcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvcHRpb25zLm9hdXRoLmNyZWRlbnRpYWxTZWNyZXQpO1xuXG4gIGlmICghcmVzdWx0KSB7XG4gICAgLy8gT0F1dGggY3JlZGVudGlhbFRva2VuIGlzIG5vdCByZWNvZ25pemVkLCB3aGljaCBjb3VsZCBiZSBlaXRoZXJcbiAgICAvLyBiZWNhdXNlIHRoZSBwb3B1cCB3YXMgY2xvc2VkIGJ5IHRoZSB1c2VyIGJlZm9yZSBjb21wbGV0aW9uLCBvclxuICAgIC8vIHNvbWUgc29ydCBvZiBlcnJvciB3aGVyZSB0aGUgb2F1dGggcHJvdmlkZXIgZGlkbid0IHRhbGsgdG8gb3VyXG4gICAgLy8gc2VydmVyIGNvcnJlY3RseSBhbmQgY2xvc2VkIHRoZSBwb3B1cCBzb21laG93LlxuICAgIC8vXG4gICAgLy8gV2UgYXNzdW1lIGl0IHdhcyB1c2VyIGNhbmNlbGVkIGFuZCByZXBvcnQgaXQgYXMgc3VjaCwgdXNpbmcgYVxuICAgIC8vIG51bWVyaWMgY29kZSB0aGF0IHRoZSBjbGllbnQgcmVjb2duaXplcyAoWFhYIHRoaXMgd2lsbCBnZXRcbiAgICAvLyByZXBsYWNlZCBieSBhIHN5bWJvbGljIGVycm9yIGNvZGUgYXQgc29tZSBwb2ludFxuICAgIC8vIGh0dHBzOi8vdHJlbGxvLmNvbS9jL2tNa3c4MDBaLzUzLW9mZmljaWFsLWRkcC1zcGVjaWZpY2F0aW9uKS4gVGhpc1xuICAgIC8vIHdpbGwgbWFzayBmYWlsdXJlcyB3aGVyZSB0aGluZ3MgYXJlIG1pc2NvbmZpZ3VyZWQgc3VjaCB0aGF0IHRoZVxuICAgIC8vIHNlcnZlciBkb2Vzbid0IHNlZSB0aGUgcmVxdWVzdCBidXQgZG9lcyBjbG9zZSB0aGUgd2luZG93LiBUaGlzXG4gICAgLy8gc2VlbXMgdW5saWtlbHkuXG4gICAgLy9cbiAgICAvLyBYWFggd2Ugd2FudCBgdHlwZWAgdG8gYmUgdGhlIHNlcnZpY2UgbmFtZSBzdWNoIGFzIFwiZmFjZWJvb2tcIlxuICAgIHJldHVybiB7IHR5cGU6IFwib2F1dGhcIixcbiAgICAgICAgICAgICBlcnJvcjogbmV3IE1ldGVvci5FcnJvcihcbiAgICAgICAgICAgICAgIEFjY291bnRzLkxvZ2luQ2FuY2VsbGVkRXJyb3IubnVtZXJpY0Vycm9yLFxuICAgICAgICAgICAgICAgXCJObyBtYXRjaGluZyBsb2dpbiBhdHRlbXB0IGZvdW5kXCIpIH07XG4gIH1cblxuICBpZiAocmVzdWx0IGluc3RhbmNlb2YgRXJyb3IpXG4gICAgLy8gV2UgdHJpZWQgdG8gbG9naW4sIGJ1dCB0aGVyZSB3YXMgYSBmYXRhbCBlcnJvci4gUmVwb3J0IGl0IGJhY2tcbiAgICAvLyB0byB0aGUgdXNlci5cbiAgICB0aHJvdyByZXN1bHQ7XG4gIGVsc2Uge1xuICAgIGlmICghIEFjY291bnRzLm9hdXRoLnNlcnZpY2VOYW1lcygpLmluY2x1ZGVzKHJlc3VsdC5zZXJ2aWNlTmFtZSkpIHtcbiAgICAgIC8vIHNlcnZpY2VOYW1lIHdhcyBub3QgZm91bmQgaW4gdGhlIHJlZ2lzdGVyZWQgc2VydmljZXMgbGlzdC5cbiAgICAgIC8vIFRoaXMgY291bGQgaGFwcGVuIGJlY2F1c2UgdGhlIHNlcnZpY2UgbmV2ZXIgcmVnaXN0ZXJlZCBpdHNlbGYgb3JcbiAgICAgIC8vIHVucmVnaXN0ZXJTZXJ2aWNlIHdhcyBjYWxsZWQgb24gaXQuXG4gICAgICByZXR1cm4geyB0eXBlOiBcIm9hdXRoXCIsXG4gICAgICAgICAgICAgICBlcnJvcjogbmV3IE1ldGVvci5FcnJvcihcbiAgICAgICAgICAgICAgICAgQWNjb3VudHMuTG9naW5DYW5jZWxsZWRFcnJvci5udW1lcmljRXJyb3IsXG4gICAgICAgICAgICAgICAgIGBObyByZWdpc3RlcmVkIG9hdXRoIHNlcnZpY2UgZm91bmQgZm9yOiAke3Jlc3VsdC5zZXJ2aWNlTmFtZX1gKSB9O1xuXG4gICAgfVxuICAgIHJldHVybiBBY2NvdW50cy51cGRhdGVPckNyZWF0ZVVzZXJGcm9tRXh0ZXJuYWxTZXJ2aWNlKHJlc3VsdC5zZXJ2aWNlTmFtZSwgcmVzdWx0LnNlcnZpY2VEYXRhLCByZXN1bHQub3B0aW9ucyk7XG4gIH1cbn0pO1xuIl19
