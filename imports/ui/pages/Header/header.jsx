import React, { Component } from 'react';
import { Users, Notifications } from '/imports/api/links.js';
import { Meteor } from 'meteor/meteor';

import Homepre from './homepre.jsx';
import Homepost from './homepost.jsx';

export default class Header extends Component {

  constructor(props) {
    super(props)
  }

  render() {
    if(Meteor.user()) {
      return <Homepost />
    }
    return <Homepre />
  }
}
