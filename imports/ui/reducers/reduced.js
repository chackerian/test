import { Meteor } from 'meteor/meteor';
import React from 'react';

export default function(state=[], action) {

  switch(action.type) {
    case "JOIN":
      return {
        modal: "join",
        status: "on"
      }
    case "ADD":
      return {
        modal: "add",
        status: "on"
      }
    case "EDIT_LISTING":
      return {
        modal: "editListing",
        status: "on"
      }
    case "EDIT_PROFILE":
      return {
        modal: "editProfile",
        status: "on"
      }
    case "REPORT_USER":
      return {
        modal: "reportUser",
        status: "on"
      }
    case "REPORT_LISTING":
      return {
        modal: "reportListing",
        status: "on"
      }
    case "IMAGE":
      return {
        modal: "image",
        status: "on"
      }
    case "CLOSE_MODAL":
      return {
        modal: "add",
        status: "off"
      }
    case "NOTIFY":
      return {
        alert: "add",
      }
    case "CLOSE_NOTIFY":
      return {
        alert: "add",
        status: "off"
      }
    default:
      return "app";
  }
}
