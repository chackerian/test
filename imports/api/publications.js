import { Meteor } from 'meteor/meteor';
import { Listing, Notification, Message, Feedback, Report, Saves } from '../db.js';

if (Meteor.isServer) {

	Meteor.publish('listingShow', function() {
		return Listing.find({ status: "Pending" }, { limit: 100 });
		this.ready();
	});

	Meteor.publish('userShow', function() {
		return Meteor.users.find({}, { limit: 100 });
		this.ready();
	});

}
