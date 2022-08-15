var require = meteorInstall({"imports":{"api":{"links.js":function module(require,exports,module){

//////////////////////////////////////////////////////////////////////////////
//                                                                          //
// imports/api/links.js                                                     //
//                                                                          //
//////////////////////////////////////////////////////////////////////////////
                                                                            //
module.export({
  Listing: () => Listing,
  Message: () => Message,
  Notification: () => Notification,
  Feedback: () => Feedback,
  Report: () => Report,
  Saves: () => Saves
});
let Mongo;
module.link("meteor/mongo", {
  Mongo(v) {
    Mongo = v;
  }

}, 0);
const Listing = new Mongo.Collection('listing');
const Message = new Mongo.Collection('message');
const Notification = new Mongo.Collection('notifications');
const Feedback = new Mongo.Collection('feedback');
const Report = new Mongo.Collection('report');
const Saves = new Mongo.Collection('save');
//////////////////////////////////////////////////////////////////////////////

}}},"server":{"main.js":function module(require,exports,module){

//////////////////////////////////////////////////////////////////////////////
//                                                                          //
// server/main.js                                                           //
//                                                                          //
//////////////////////////////////////////////////////////////////////////////
                                                                            //
let Meteor;
module.link("meteor/meteor", {
  Meteor(v) {
    Meteor = v;
  }

}, 0);
let ServiceConfiguration;
module.link("meteor/service-configuration", {
  ServiceConfiguration(v) {
    ServiceConfiguration = v;
  }

}, 1);
let Listing, Notification, Message, Feedback, Report, Saves;
module.link("/imports/api/links", {
  Listing(v) {
    Listing = v;
  },

  Notification(v) {
    Notification = v;
  },

  Message(v) {
    Message = v;
  },

  Feedback(v) {
    Feedback = v;
  },

  Report(v) {
    Report = v;
  },

  Saves(v) {
    Saves = v;
  }

}, 2);

// import '/imports/api/methods.js';
if (Meteor.isServer) {
  Meteor.methods({
    updateUserCreation: function (options) {
      Meteor.users.update({
        _id: options.id
      }, {
        $set: {
          'profile.reviews_count': 0,
          'profile.amount_bought': 0,
          'profile.amount_sold': 0,
          'profile.meetups_count': 0,
          'profile.location': options.location,
          'profile.picturelrg': "http://graph.facebook.com/" + Meteor.user().services.facebook.id + "/picture/?type=large",
          'profile.picturesm': "http://graph.facebook.com/" + Meteor.user().services.facebook.id + "/picture/?type=small"
        }
      });
    },

    /*
     * @summary Send Email
     * @locus Server
     */
    sendEmail: function (to, from, subject, text) {
      this.unblock();
      Email.send({
        to: to,
        from: from,
        subject: subject,
        text: text
      });
    },

    /*
     * @summary Send Email
     * @locus Server
     *
     */
    sendFeedback: function (options) {
      Feedback.insert({
        listing_id: options.listingId,
        date: options.date,
        rater: options.rater,
        rater_id: options.rater_Id,
        rated: options.rated,
        friendly_rate: options.friendly_rate,
        efficiency_rate: options.efficiency_rate,
        negotiatiate_rate: options.negotiatiate_rate,
        comment_title: options.comment_title,
        comment: options.comment,
        // Diff
        payment_rate: options.payment_rate
      });
      Meteor.users.update({
        _id: options.rated_id
      }, {
        $inc: {
          'profile.reviewscount': 1,
          'profile.amountbought': 1
        },
        $set: {
          'profile.feedback_filed_seller': "Completed"
        },
        $push: {
          'profile.sell_friendlyratingArray': options.friendly_rate,
          'profile.sell_efficiencyratingArray': options.efficiency_rate,
          'profile.sell_negotiationratingArray': options.negotiatiate_rate,
          'profile.sell_describedratingArray': options.payment_rate
        }
      });
      Meteor.users.update({
        _id: options.rated_id
      }, {
        $set: {
          'profile.sell_friendlyrating': sumFriendly,
          'profile.sell_efficiencyrating': sumEfficiency,
          'profile.sell_negotiationrating': sumNegotiate,
          'profile.sell_describedrating': sumDescribed,
          // Totals
          'profile.sell_totalrating': sumSeller,
          'profile.totalrating': sumSeller
        }
      });
    },
    addListing: function (options) {
      if (!Meteor.userId()) {
        throw new Meteor.Error("Not Authorized");
      }

      Listing.insert({
        // User Information
        creator_id: options.creator_id,
        creator_image: options.creator_image,
        creator_facebook_id: options.creator_facebook_id,
        creator_username: Meteor.user().profile.name,
        creator_initials: options.creator_initials,
        listing_title: options.listing_title,
        urlKey: options.urlKey,
        // Category
        category: options.category,
        type: options.type,
        brand: options.brand,
        // Payment
        price: options.price,
        payment: options.payment,
        trade: options.trade,
        // Information
        condition: options.condition,
        description: options.description,
        // Location
        city: options.city,
        state: options.state,
        locationString: options.locationString,
        // Images
        images: options.images,
        // Status
        createdAt: new Date(),
        status: "Pending"
      });
    },

    /*
     * @summary Edit listing
     * @locus Server
     */
    updateListing: function (options) {
      Listing.update({
        _id: options.id
      }, {
        $set: {
          listing_title: options.listing_title,
          brand: options.brand,
          price: options.price,
          payment: options.payment,
          trade: options.trade,
          size: options.size,
          condition: options.condition,
          description: options.description
        }
      });
    },

    /*
     * @summary Transfer Listing to history
     * @locus Server
     */
    cacheListing: function (options) {
      Listing.update({
        _id: options.listingId
      }, {
        $set: {
          status: "Completed",
          feedback_filed_seller: "Pending",
          feedback_filed_buyer: "Pending"
        }
      });
    },

    /*
     * @summary Remove a listing
     * @locus Server
     */
    removeListing: function (options) {
      if (Meteor.userId() == options.creator_id) {
        Listing.remove({
          _id: options.id
        });
      } else {
        throw new Meteor.Error("Not Authorized");
      }
    },

    /*
     * @summary Save A Listing
     * @locus Server
     */
    saveListing: function (id) {
      Saves.insert({
        listing_id: id
      });
    },

    /*
     * @summary Unsave A Listing
     * @locus Server
     */
    unsaveListing: function (optionsA) {
      Saves.remove({
        _id: optionsA._id
      });
    },
    // Destination is set in options previously

    /*
     * @summary Send Notification
     * @locus Server
     */
    pulseNotify: function (options) {
      Notification.insert({
        createdAt: new Date(),
        action: options.action,
        notifyType: options.notifyType,
        listing_title: options.listing_title,
        offer_price: options.offerprice,
        creator_id: options.creator_id,
        creator_name: options.creator_name,
        listingId: options.listingId,
        destination: options.destination,
        link: options.link,
        listing_creator_id: options.listing_creator_id
      });
    },
    deleteAccount: function () {
      Meteor.users.remove({
        _id: Meteor.userId()
      });
    },

    /*
     * @summary Add a report (Listing and User)
     * @locus Server
     */
    addReport: function (options) {
      Report.insert({
        targetUser: options.targetUser,
        riskLevel: options.riskLevel,
        reasonBox: {
          prohibited_box: options.reasonBox.prohibited_box,
          offensive_box: options.reasonBox.offensive_box,
          irrelevant_box: options.reasonBox.irrelevant_box,
          false_box: options.reasonBox.false_box,
          compliance_box: options.reasonBox.compliance_box
        },
        description: options.description
      });
    },

    /*
     * @summary Send a User
     * @locus Server
     */
    sendMessage: function (options) {
      Message.insert({
        message: options.message,
        sender: options.sender,
        receiver: options.receiver,
        conversation: options.conversation,
        timestamp: options.timestamp,
        createdAt: new Date()
      });
    }
  });
  ServiceConfiguration.configurations.upsert({
    service: 'facebook'
  }, {
    $set: {
      loginStyle: "popup",
      appId: "1927827950722684",
      secret: "dbbb1dc68ca40f7dac91d412845b1fa3"
    }
  });
}
//////////////////////////////////////////////////////////////////////////////

}}},{
  "extensions": [
    ".js",
    ".json",
    ".ts",
    ".mjs",
    ".jsx"
  ]
});

require("/server/main.js");
//# sourceURL=meteor://💻app/app/app.js
//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm1ldGVvcjovL/CfkrthcHAvaW1wb3J0cy9hcGkvbGlua3MuanMiLCJtZXRlb3I6Ly/wn5K7YXBwL3NlcnZlci9tYWluLmpzIl0sIm5hbWVzIjpbIm1vZHVsZSIsImV4cG9ydCIsIkxpc3RpbmciLCJNZXNzYWdlIiwiTm90aWZpY2F0aW9uIiwiRmVlZGJhY2siLCJSZXBvcnQiLCJTYXZlcyIsIk1vbmdvIiwibGluayIsInYiLCJDb2xsZWN0aW9uIiwiTWV0ZW9yIiwiU2VydmljZUNvbmZpZ3VyYXRpb24iLCJpc1NlcnZlciIsIm1ldGhvZHMiLCJ1cGRhdGVVc2VyQ3JlYXRpb24iLCJvcHRpb25zIiwidXNlcnMiLCJ1cGRhdGUiLCJfaWQiLCJpZCIsIiRzZXQiLCJsb2NhdGlvbiIsInVzZXIiLCJzZXJ2aWNlcyIsImZhY2Vib29rIiwic2VuZEVtYWlsIiwidG8iLCJmcm9tIiwic3ViamVjdCIsInRleHQiLCJ1bmJsb2NrIiwiRW1haWwiLCJzZW5kIiwic2VuZEZlZWRiYWNrIiwiaW5zZXJ0IiwibGlzdGluZ19pZCIsImxpc3RpbmdJZCIsImRhdGUiLCJyYXRlciIsInJhdGVyX2lkIiwicmF0ZXJfSWQiLCJyYXRlZCIsImZyaWVuZGx5X3JhdGUiLCJlZmZpY2llbmN5X3JhdGUiLCJuZWdvdGlhdGlhdGVfcmF0ZSIsImNvbW1lbnRfdGl0bGUiLCJjb21tZW50IiwicGF5bWVudF9yYXRlIiwicmF0ZWRfaWQiLCIkaW5jIiwiJHB1c2giLCJzdW1GcmllbmRseSIsInN1bUVmZmljaWVuY3kiLCJzdW1OZWdvdGlhdGUiLCJzdW1EZXNjcmliZWQiLCJzdW1TZWxsZXIiLCJhZGRMaXN0aW5nIiwidXNlcklkIiwiRXJyb3IiLCJjcmVhdG9yX2lkIiwiY3JlYXRvcl9pbWFnZSIsImNyZWF0b3JfZmFjZWJvb2tfaWQiLCJjcmVhdG9yX3VzZXJuYW1lIiwicHJvZmlsZSIsIm5hbWUiLCJjcmVhdG9yX2luaXRpYWxzIiwibGlzdGluZ190aXRsZSIsInVybEtleSIsImNhdGVnb3J5IiwidHlwZSIsImJyYW5kIiwicHJpY2UiLCJwYXltZW50IiwidHJhZGUiLCJjb25kaXRpb24iLCJkZXNjcmlwdGlvbiIsImNpdHkiLCJzdGF0ZSIsImxvY2F0aW9uU3RyaW5nIiwiaW1hZ2VzIiwiY3JlYXRlZEF0IiwiRGF0ZSIsInN0YXR1cyIsInVwZGF0ZUxpc3RpbmciLCJzaXplIiwiY2FjaGVMaXN0aW5nIiwiZmVlZGJhY2tfZmlsZWRfc2VsbGVyIiwiZmVlZGJhY2tfZmlsZWRfYnV5ZXIiLCJyZW1vdmVMaXN0aW5nIiwicmVtb3ZlIiwic2F2ZUxpc3RpbmciLCJ1bnNhdmVMaXN0aW5nIiwib3B0aW9uc0EiLCJwdWxzZU5vdGlmeSIsImFjdGlvbiIsIm5vdGlmeVR5cGUiLCJvZmZlcl9wcmljZSIsIm9mZmVycHJpY2UiLCJjcmVhdG9yX25hbWUiLCJkZXN0aW5hdGlvbiIsImxpc3RpbmdfY3JlYXRvcl9pZCIsImRlbGV0ZUFjY291bnQiLCJhZGRSZXBvcnQiLCJ0YXJnZXRVc2VyIiwicmlza0xldmVsIiwicmVhc29uQm94IiwicHJvaGliaXRlZF9ib3giLCJvZmZlbnNpdmVfYm94IiwiaXJyZWxldmFudF9ib3giLCJmYWxzZV9ib3giLCJjb21wbGlhbmNlX2JveCIsInNlbmRNZXNzYWdlIiwibWVzc2FnZSIsInNlbmRlciIsInJlY2VpdmVyIiwiY29udmVyc2F0aW9uIiwidGltZXN0YW1wIiwiY29uZmlndXJhdGlvbnMiLCJ1cHNlcnQiLCJzZXJ2aWNlIiwibG9naW5TdHlsZSIsImFwcElkIiwic2VjcmV0Il0sIm1hcHBpbmdzIjoiOzs7Ozs7OztBQUFBQSxNQUFNLENBQUNDLE1BQVAsQ0FBYztBQUFDQyxTQUFPLEVBQUMsTUFBSUEsT0FBYjtBQUFxQkMsU0FBTyxFQUFDLE1BQUlBLE9BQWpDO0FBQXlDQyxjQUFZLEVBQUMsTUFBSUEsWUFBMUQ7QUFBdUVDLFVBQVEsRUFBQyxNQUFJQSxRQUFwRjtBQUE2RkMsUUFBTSxFQUFDLE1BQUlBLE1BQXhHO0FBQStHQyxPQUFLLEVBQUMsTUFBSUE7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QUFSLENBQWtCRyxjQUh6QjtBQUlUQyxtQkFBUyxFQUFFOUYsT0FBTyxDQUFDMEYsU0FBUixDQUFrQkksU0FKcEI7QUFLVEMsd0JBQWMsRUFBRS9GLE9BQU8sQ0FBQzBGLFNBQVIsQ0FBa0JLO0FBTHpCLFNBSEM7QUFVWm5DLG1CQUFXLEVBQUU1RCxPQUFPLENBQUM0RDtBQVZULE9BQWQ7QUFZRCxLQXZPYTs7QUF3T2Q7QUFDSjtBQUNBO0FBQ0E7QUFDS29DLGVBQVcsRUFBRSxVQUFTaEcsT0FBVCxFQUFrQjtBQUM5QmQsYUFBTyxDQUFDaUMsTUFBUixDQUFlO0FBQ2I4RSxlQUFPLEVBQUVqRyxPQUFPLENBQUNpRyxPQURKO0FBRWJDLGNBQU0sRUFBRWxHLE9BQU8sQ0FBQ2tHLE1BRkg7QUFHYkMsZ0JBQVEsRUFBRW5HLE9BQU8sQ0FBQ21HLFFBSEw7QUFJYkMsb0JBQVksRUFBRXBHLE9BQU8sQ0FBQ29HLFlBSlQ7QUFLYkMsaUJBQVMsRUFBRXJHLE9BQU8sQ0FBQ3FHLFNBTE47QUFNYnBDLGlCQUFTLEVBQUUsSUFBSUMsSUFBSjtBQU5FLE9BQWY7QUFRRDtBQXJQYSxHQUFmO0FBeVBEdEUsc0JBQW9CLENBQUMwRyxjQUFyQixDQUFvQ0MsTUFBcEMsQ0FDRTtBQUFFQyxXQUFPLEVBQUU7QUFBWCxHQURGLEVBRUU7QUFDRW5HLFFBQUksRUFBRTtBQUNKb0csZ0JBQVUsRUFBRSxPQURSO0FBRUpDLFdBQUssRUFBRSxrQkFGSDtBQUdKQyxZQUFNLEVBQUU7QUFISjtBQURSLEdBRkY7QUFXRCxDIiwiZmlsZSI6Ii9hcHAuanMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBNb25nbyB9IGZyb20gJ21ldGVvci9tb25nbyc7XG5cbi8vIExpc3RpbmdcbmV4cG9ydCBjb25zdCBMaXN0aW5nID0gbmV3IE1vbmdvLkNvbGxlY3Rpb24oJ2xpc3RpbmcnKTtcblxuLy8gTGlzdGluZ1xuZXhwb3J0IGNvbnN0IE1lc3NhZ2UgPSBuZXcgTW9uZ28uQ29sbGVjdGlvbignbWVzc2FnZScpO1xuXG4vLyBOb3RpZmljYXRpb25cbmV4cG9ydCBjb25zdCBOb3RpZmljYXRpb24gPSBuZXcgTW9uZ28uQ29sbGVjdGlvbignbm90aWZpY2F0aW9ucycpO1xuXG4vLyBGZWVkYmFja1xuZXhwb3J0IGNvbnN0IEZlZWRiYWNrID0gbmV3IE1vbmdvLkNvbGxlY3Rpb24oJ2ZlZWRiYWNrJyk7XG5cbi8vIFJlcG9ydFxuZXhwb3J0IGNvbnN0IFJlcG9ydCA9IG5ldyBNb25nby5Db2xsZWN0aW9uKCdyZXBvcnQnKTtcblxuLy8gU2F2ZXNcbmV4cG9ydCBjb25zdCBTYXZlcyA9IG5ldyBNb25nby5Db2xsZWN0aW9uKCdzYXZlJyk7XG4iLCJpbXBvcnQgeyBNZXRlb3IgfSBmcm9tICdtZXRlb3IvbWV0ZW9yJztcbmltcG9ydCB7IFNlcnZpY2VDb25maWd1cmF0aW9uIH0gZnJvbSAnbWV0ZW9yL3NlcnZpY2UtY29uZmlndXJhdGlvbic7XG5pbXBvcnQgeyBMaXN0aW5nLCBOb3RpZmljYXRpb24sIE1lc3NhZ2UsIEZlZWRiYWNrLCBSZXBvcnQsIFNhdmVzIH0gZnJvbSAnL2ltcG9ydHMvYXBpL2xpbmtzJztcbi8vIGltcG9ydCAnL2ltcG9ydHMvYXBpL21ldGhvZHMuanMnO1xuXG5pZiAoTWV0ZW9yLmlzU2VydmVyKSB7XG5cbiAgIE1ldGVvci5tZXRob2RzKHtcbiAgIHVwZGF0ZVVzZXJDcmVhdGlvbjogZnVuY3Rpb24ob3B0aW9ucykge1xuICAgICBNZXRlb3IudXNlcnMudXBkYXRlKHtcbiAgICAgICBfaWQ6IG9wdGlvbnMuaWRcbiAgICAgfSwge1xuICAgICAgICRzZXQ6IHtcbiAgICAgICAgICdwcm9maWxlLnJldmlld3NfY291bnQnOiAwLFxuICAgICAgICAgJ3Byb2ZpbGUuYW1vdW50X2JvdWdodCc6IDAsXG4gICAgICAgICAncHJvZmlsZS5hbW91bnRfc29sZCc6IDAsXG4gICAgICAgICAncHJvZmlsZS5tZWV0dXBzX2NvdW50JzogMCxcbiAgICAgICAgICdwcm9maWxlLmxvY2F0aW9uJzogb3B0aW9ucy5sb2NhdGlvbixcbiAgICAgICAgICdwcm9maWxlLnBpY3R1cmVscmcnOiBcImh0dHA6Ly9ncmFwaC5mYWNlYm9vay5jb20vXCIgKyBNZXRlb3IudXNlcigpLnNlcnZpY2VzLmZhY2Vib29rLmlkICsgXCIvcGljdHVyZS8/dHlwZT1sYXJnZVwiLFxuICAgICAgICAgJ3Byb2ZpbGUucGljdHVyZXNtJzogXCJodHRwOi8vZ3JhcGguZmFjZWJvb2suY29tL1wiICsgTWV0ZW9yLnVzZXIoKS5zZXJ2aWNlcy5mYWNlYm9vay5pZCArIFwiL3BpY3R1cmUvP3R5cGU9c21hbGxcIlxuICAgICAgIH1cbiAgICAgfSlcbiAgIH0sXG4gIC8qXG4gICAqIEBzdW1tYXJ5IFNlbmQgRW1haWxcbiAgICogQGxvY3VzIFNlcnZlclxuICAgKi9cbiAgICBzZW5kRW1haWw6IGZ1bmN0aW9uKHRvLCBmcm9tLCBzdWJqZWN0LCB0ZXh0KSB7XG4gICAgIHRoaXMudW5ibG9jaygpO1xuICAgICBFbWFpbC5zZW5kKHtcbiAgICAgICB0bzogdG8sXG4gICAgICAgZnJvbTogZnJvbSxcbiAgICAgICBzdWJqZWN0OiBzdWJqZWN0LFxuICAgICAgIHRleHQ6IHRleHRcbiAgICAgfSk7XG4gICAgfSxcbiAgICAvKlxuICAgICAqIEBzdW1tYXJ5IFNlbmQgRW1haWxcbiAgICAgKiBAbG9jdXMgU2VydmVyXG4gICAgICpcbiAgICAgKi9cbiAgICAgc2VuZEZlZWRiYWNrOiBmdW5jdGlvbihvcHRpb25zKSB7XG4gICAgICBGZWVkYmFjay5pbnNlcnQoe1xuICAgICAgICBsaXN0aW5nX2lkOiBvcHRpb25zLmxpc3RpbmdJZCxcbiAgICAgICAgZGF0ZTogb3B0aW9ucy5kYXRlLFxuICAgICAgICByYXRlcjogb3B0aW9ucy5yYXRlcixcbiAgICAgICAgcmF0ZXJfaWQ6IG9wdGlvbnMucmF0ZXJfSWQsXG4gICAgICAgIHJhdGVkOiBvcHRpb25zLnJhdGVkLFxuICAgICAgICBmcmllbmRseV9yYXRlOiBvcHRpb25zLmZyaWVuZGx5X3JhdGUsXG4gICAgICAgIGVmZmljaWVuY3lfcmF0ZTogb3B0aW9ucy5lZmZpY2llbmN5X3JhdGUsXG4gICAgICAgIG5lZ290aWF0aWF0ZV9yYXRlOiBvcHRpb25zLm5lZ290aWF0aWF0ZV9yYXRlLFxuICAgICAgICBjb21tZW50X3RpdGxlOiBvcHRpb25zLmNvbW1lbnRfdGl0bGUsXG4gICAgICAgIGNvbW1lbnQ6IG9wdGlvbnMuY29tbWVudCxcbiAgICAgICAgLy8gRGlmZlxuICAgICAgICBwYXltZW50X3JhdGU6IG9wdGlvbnMucGF5bWVudF9yYXRlXG4gICAgICB9KVxuXG4gICAgICBNZXRlb3IudXNlcnMudXBkYXRlKHtcbiAgICAgICAgX2lkOiBvcHRpb25zLnJhdGVkX2lkXG4gICAgICB9LCB7XG4gICAgICAgICRpbmM6IHtcbiAgICAgICAgICAncHJvZmlsZS5yZXZpZXdzY291bnQnOiAxLFxuICAgICAgICAgICdwcm9maWxlLmFtb3VudGJvdWdodCc6IDFcbiAgICAgICAgfSxcbiAgICAgICAgJHNldDoge1xuICAgICAgICAgICdwcm9maWxlLmZlZWRiYWNrX2ZpbGVkX3NlbGxlcic6IFwiQ29tcGxldGVkXCJcbiAgICAgICAgfSxcbiAgICAgICAgJHB1c2g6IHtcbiAgICAgICAgICAncHJvZmlsZS5zZWxsX2ZyaWVuZGx5cmF0aW5nQXJyYXknOiBvcHRpb25zLmZyaWVuZGx5X3JhdGUsXG4gICAgICAgICAgJ3Byb2ZpbGUuc2VsbF9lZmZpY2llbmN5cmF0aW5nQXJyYXknOiBvcHRpb25zLmVmZmljaWVuY3lfcmF0ZSxcbiAgICAgICAgICAncHJvZmlsZS5zZWxsX25lZ290aWF0aW9ucmF0aW5nQXJyYXknOiBvcHRpb25zLm5lZ290aWF0aWF0ZV9yYXRlLFxuICAgICAgICAgICdwcm9maWxlLnNlbGxfZGVzY3JpYmVkcmF0aW5nQXJyYXknOiBvcHRpb25zLnBheW1lbnRfcmF0ZSxcbiAgICAgICAgfVxuICAgICAgfSk7XG5cbiAgICAgIE1ldGVvci51c2Vycy51cGRhdGUoe1xuICAgICAgICBfaWQ6IG9wdGlvbnMucmF0ZWRfaWRcbiAgICAgIH0sIHtcbiAgICAgICAgJHNldDoge1xuICAgICAgICAgICdwcm9maWxlLnNlbGxfZnJpZW5kbHlyYXRpbmcnOiBzdW1GcmllbmRseSxcbiAgICAgICAgICAncHJvZmlsZS5zZWxsX2VmZmljaWVuY3lyYXRpbmcnOiBzdW1FZmZpY2llbmN5LFxuICAgICAgICAgICdwcm9maWxlLnNlbGxfbmVnb3RpYXRpb25yYXRpbmcnOiBzdW1OZWdvdGlhdGUsXG4gICAgICAgICAgJ3Byb2ZpbGUuc2VsbF9kZXNjcmliZWRyYXRpbmcnOiBzdW1EZXNjcmliZWQsXG4gICAgICAgICAgLy8gVG90YWxzXG4gICAgICAgICAgJ3Byb2ZpbGUuc2VsbF90b3RhbHJhdGluZyc6IHN1bVNlbGxlcixcbiAgICAgICAgICAncHJvZmlsZS50b3RhbHJhdGluZyc6IHN1bVNlbGxlclxuICAgICAgICB9XG4gICAgICB9KVxuXG4gICAgfSxcbiAgICBhZGRMaXN0aW5nOiBmdW5jdGlvbihvcHRpb25zKSB7XG4gICAgIGlmICghTWV0ZW9yLnVzZXJJZCgpKSB7XG4gICAgICAgdGhyb3cgbmV3IE1ldGVvci5FcnJvcihcIk5vdCBBdXRob3JpemVkXCIpO1xuICAgICB9XG5cbiAgICAgTGlzdGluZy5pbnNlcnQoe1xuICAgICAgICAgLy8gVXNlciBJbmZvcm1hdGlvblxuICAgICAgICAgY3JlYXRvcl9pZDogb3B0aW9ucy5jcmVhdG9yX2lkLFxuICAgICAgICAgY3JlYXRvcl9pbWFnZTogb3B0aW9ucy5jcmVhdG9yX2ltYWdlLFxuICAgICAgICAgY3JlYXRvcl9mYWNlYm9va19pZDogb3B0aW9ucy5jcmVhdG9yX2ZhY2Vib29rX2lkLFxuICAgICAgICAgY3JlYXRvcl91c2VybmFtZTogTWV0ZW9yLnVzZXIoKS5wcm9maWxlLm5hbWUsXG4gICAgICAgICBjcmVhdG9yX2luaXRpYWxzOiBvcHRpb25zLmNyZWF0b3JfaW5pdGlhbHMsXG4gICAgICAgICBsaXN0aW5nX3RpdGxlOiBvcHRpb25zLmxpc3RpbmdfdGl0bGUsXG4gICAgICAgICB1cmxLZXk6IG9wdGlvbnMudXJsS2V5LFxuICAgICAgICAgLy8gQ2F0ZWdvcnlcbiAgICAgICAgIGNhdGVnb3J5OiBvcHRpb25zLmNhdGVnb3J5LFxuICAgICAgICAgdHlwZTogb3B0aW9ucy50eXBlLFxuICAgICAgICAgYnJhbmQ6IG9wdGlvbnMuYnJhbmQsXG4gICAgICAgICAvLyBQYXltZW50XG4gICAgICAgICBwcmljZTogb3B0aW9ucy5wcmljZSxcbiAgICAgICAgIHBheW1lbnQ6IG9wdGlvbnMucGF5bWVudCxcbiAgICAgICAgIHRyYWRlOiBvcHRpb25zLnRyYWRlLFxuICAgICAgICAgLy8gSW5mb3JtYXRpb25cbiAgICAgICAgIGNvbmRpdGlvbjogb3B0aW9ucy5jb25kaXRpb24sXG4gICAgICAgICBkZXNjcmlwdGlvbjogb3B0aW9ucy5kZXNjcmlwdGlvbixcbiAgICAgICAgIC8vIExvY2F0aW9uXG4gICAgICAgICBjaXR5OiBvcHRpb25zLmNpdHksXG4gICAgICAgICBzdGF0ZTogb3B0aW9ucy5zdGF0ZSxcbiAgICAgICAgIGxvY2F0aW9uU3RyaW5nOiBvcHRpb25zLmxvY2F0aW9uU3RyaW5nLFxuICAgICAgICAgLy8gSW1hZ2VzXG4gICAgICAgICBpbWFnZXM6IG9wdGlvbnMuaW1hZ2VzLFxuICAgICAgICAgLy8gU3RhdHVzXG4gICAgICAgICBjcmVhdGVkQXQ6IG5ldyBEYXRlKCksXG4gICAgICAgICBzdGF0dXM6IFwiUGVuZGluZ1wiLFxuICAgICAgIH0pO1xuICAgfSxcbiAgIC8qXG4gICAgKiBAc3VtbWFyeSBFZGl0IGxpc3RpbmdcbiAgICAqIEBsb2N1cyBTZXJ2ZXJcbiAgICAqL1xuICAgIHVwZGF0ZUxpc3Rpbmc6IGZ1bmN0aW9uKG9wdGlvbnMpIHtcbiAgICAgTGlzdGluZy51cGRhdGUoe1xuICAgICAgIF9pZDogb3B0aW9ucy5pZFxuICAgICB9LCB7XG4gICAgICAgJHNldDoge1xuICAgICAgICAgbGlzdGluZ190aXRsZTogb3B0aW9ucy5saXN0aW5nX3RpdGxlLFxuICAgICAgICAgYnJhbmQ6IG9wdGlvbnMuYnJhbmQsXG4gICAgICAgICBwcmljZTogb3B0aW9ucy5wcmljZSxcbiAgICAgICAgIHBheW1lbnQ6IG9wdGlvbnMucGF5bWVudCxcbiAgICAgICAgIHRyYWRlOiBvcHRpb25zLnRyYWRlLFxuICAgICAgICAgc2l6ZTogb3B0aW9ucy5zaXplLFxuICAgICAgICAgY29uZGl0aW9uOiBvcHRpb25zLmNvbmRpdGlvbixcbiAgICAgICAgIGRlc2NyaXB0aW9uOiBvcHRpb25zLmRlc2NyaXB0aW9uXG4gICAgICAgfVxuICAgICB9KTtcbiAgIH0sXG4gICAgLypcbiAgICAgKiBAc3VtbWFyeSBUcmFuc2ZlciBMaXN0aW5nIHRvIGhpc3RvcnlcbiAgICAgKiBAbG9jdXMgU2VydmVyXG4gICAgICovXG4gICAgIGNhY2hlTGlzdGluZzogZnVuY3Rpb24ob3B0aW9ucykge1xuICAgICAgTGlzdGluZy51cGRhdGUoe1xuICAgICAgICBfaWQ6IG9wdGlvbnMubGlzdGluZ0lkXG4gICAgICB9LCB7XG4gICAgICAgICRzZXQ6IHtcbiAgICAgICAgICBzdGF0dXM6IFwiQ29tcGxldGVkXCIsXG4gICAgICAgICAgZmVlZGJhY2tfZmlsZWRfc2VsbGVyOiBcIlBlbmRpbmdcIixcbiAgICAgICAgICBmZWVkYmFja19maWxlZF9idXllcjogXCJQZW5kaW5nXCJcbiAgICAgICAgfVxuICAgICAgfSk7XG5cbiAgICB9LFxuXG4gICAgLypcbiAgICAgKiBAc3VtbWFyeSBSZW1vdmUgYSBsaXN0aW5nXG4gICAgICogQGxvY3VzIFNlcnZlclxuICAgICAqL1xuICAgICByZW1vdmVMaXN0aW5nOiBmdW5jdGlvbihvcHRpb25zKSB7XG4gICAgICBpZiAoTWV0ZW9yLnVzZXJJZCgpID09IG9wdGlvbnMuY3JlYXRvcl9pZCkge1xuICAgICAgICBMaXN0aW5nLnJlbW92ZSh7XG4gICAgICAgICAgX2lkOiBvcHRpb25zLmlkXG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhyb3cgbmV3IE1ldGVvci5FcnJvcihcIk5vdCBBdXRob3JpemVkXCIpO1xuICAgICAgfVxuXG4gICAgfSxcbiAgICAvKlxuICAgICAqIEBzdW1tYXJ5IFNhdmUgQSBMaXN0aW5nXG4gICAgICogQGxvY3VzIFNlcnZlclxuICAgICAqL1xuICAgICBzYXZlTGlzdGluZzogZnVuY3Rpb24oaWQpIHtcbiAgICAgIFNhdmVzLmluc2VydCh7XG4gICAgICAgIGxpc3RpbmdfaWQ6IGlkXG4gICAgICB9KVxuICAgIH0sXG4gICAgLypcbiAgICAgKiBAc3VtbWFyeSBVbnNhdmUgQSBMaXN0aW5nXG4gICAgICogQGxvY3VzIFNlcnZlclxuICAgICAqL1xuICAgICB1bnNhdmVMaXN0aW5nOiBmdW5jdGlvbihvcHRpb25zQSkge1xuICAgICAgU2F2ZXMucmVtb3ZlKHtcbiAgICAgICAgX2lkOiBvcHRpb25zQS5faWRcbiAgICAgIH0pXG4gICAgfSxcbiAgICAvLyBEZXN0aW5hdGlvbiBpcyBzZXQgaW4gb3B0aW9ucyBwcmV2aW91c2x5XG4gICAgLypcbiAgICAgKiBAc3VtbWFyeSBTZW5kIE5vdGlmaWNhdGlvblxuICAgICAqIEBsb2N1cyBTZXJ2ZXJcbiAgICAgKi9cbiAgICAgcHVsc2VOb3RpZnk6IGZ1bmN0aW9uKG9wdGlvbnMpIHtcbiAgICAgIE5vdGlmaWNhdGlvbi5pbnNlcnQoe1xuICAgICAgICBjcmVhdGVkQXQ6IG5ldyBEYXRlKCksXG4gICAgICAgIGFjdGlvbjogb3B0aW9ucy5hY3Rpb24sXG4gICAgICAgIG5vdGlmeVR5cGU6IG9wdGlvbnMubm90aWZ5VHlwZSxcbiAgICAgICAgbGlzdGluZ190aXRsZTogb3B0aW9ucy5saXN0aW5nX3RpdGxlLFxuICAgICAgICBvZmZlcl9wcmljZTogb3B0aW9ucy5vZmZlcnByaWNlLFxuICAgICAgICBjcmVhdG9yX2lkOiBvcHRpb25zLmNyZWF0b3JfaWQsXG4gICAgICAgIGNyZWF0b3JfbmFtZTogb3B0aW9ucy5jcmVhdG9yX25hbWUsXG4gICAgICAgIGxpc3RpbmdJZDogb3B0aW9ucy5saXN0aW5nSWQsXG4gICAgICAgIGRlc3RpbmF0aW9uOiBvcHRpb25zLmRlc3RpbmF0aW9uLFxuICAgICAgICBsaW5rOiBvcHRpb25zLmxpbmssXG4gICAgICAgIGxpc3RpbmdfY3JlYXRvcl9pZDogb3B0aW9ucy5saXN0aW5nX2NyZWF0b3JfaWRcbiAgICAgIH0pO1xuICAgIH0sXG5cbiAgICBkZWxldGVBY2NvdW50OiBmdW5jdGlvbigpIHtcbiAgICAgIE1ldGVvci51c2Vycy5yZW1vdmUoe1xuICAgICAgICBfaWQ6IE1ldGVvci51c2VySWQoKVxuICAgICAgfSk7XG4gICAgfSxcbiAgICAvKlxuICAgICAqIEBzdW1tYXJ5IEFkZCBhIHJlcG9ydCAoTGlzdGluZyBhbmQgVXNlcilcbiAgICAgKiBAbG9jdXMgU2VydmVyXG4gICAgICovXG4gICAgIGFkZFJlcG9ydDogZnVuY3Rpb24ob3B0aW9ucykge1xuICAgICAgUmVwb3J0Lmluc2VydCh7XG4gICAgICAgIHRhcmdldFVzZXI6IG9wdGlvbnMudGFyZ2V0VXNlcixcbiAgICAgICAgcmlza0xldmVsOiBvcHRpb25zLnJpc2tMZXZlbCxcbiAgICAgICAgcmVhc29uQm94OiB7XG4gICAgICAgICAgcHJvaGliaXRlZF9ib3g6IG9wdGlvbnMucmVhc29uQm94LnByb2hpYml0ZWRfYm94LFxuICAgICAgICAgIG9mZmVuc2l2ZV9ib3g6IG9wdGlvbnMucmVhc29uQm94Lm9mZmVuc2l2ZV9ib3gsXG4gICAgICAgICAgaXJyZWxldmFudF9ib3g6IG9wdGlvbnMucmVhc29uQm94LmlycmVsZXZhbnRfYm94LFxuICAgICAgICAgIGZhbHNlX2JveDogb3B0aW9ucy5yZWFzb25Cb3guZmFsc2VfYm94LFxuICAgICAgICAgIGNvbXBsaWFuY2VfYm94OiBvcHRpb25zLnJlYXNvbkJveC5jb21wbGlhbmNlX2JveFxuICAgICAgICB9LFxuICAgICAgICBkZXNjcmlwdGlvbjogb3B0aW9ucy5kZXNjcmlwdGlvblxuICAgICAgfSk7XG4gICAgfSxcbiAgICAvKlxuICAgICAqIEBzdW1tYXJ5IFNlbmQgYSBVc2VyXG4gICAgICogQGxvY3VzIFNlcnZlclxuICAgICAqL1xuICAgICBzZW5kTWVzc2FnZTogZnVuY3Rpb24ob3B0aW9ucykge1xuICAgICAgTWVzc2FnZS5pbnNlcnQoe1xuICAgICAgICBtZXNzYWdlOiBvcHRpb25zLm1lc3NhZ2UsXG4gICAgICAgIHNlbmRlcjogb3B0aW9ucy5zZW5kZXIsXG4gICAgICAgIHJlY2VpdmVyOiBvcHRpb25zLnJlY2VpdmVyLFxuICAgICAgICBjb252ZXJzYXRpb246IG9wdGlvbnMuY29udmVyc2F0aW9uLFxuICAgICAgICB0aW1lc3RhbXA6IG9wdGlvbnMudGltZXN0YW1wLFxuICAgICAgICBjcmVhdGVkQXQ6IG5ldyBEYXRlKClcbiAgICAgIH0pO1xuICAgIH1cblxuICB9KTtcblxuICBTZXJ2aWNlQ29uZmlndXJhdGlvbi5jb25maWd1cmF0aW9ucy51cHNlcnQoXG4gICAgeyBzZXJ2aWNlOiAnZmFjZWJvb2snIH0sXG4gICAge1xuICAgICAgJHNldDoge1xuICAgICAgICBsb2dpblN0eWxlOiBcInBvcHVwXCIsXG4gICAgICAgIGFwcElkOiBcIjE5Mjc4Mjc5NTA3MjI2ODRcIixcbiAgICAgICAgc2VjcmV0OiBcImRiYmIxZGM2OGNhNDBmN2RhYzkxZDQxMjg0NWIxZmEzXCJcbiAgICAgIH1cbiAgICB9XG4gICk7XG5cbn1cbiJdfQ==
