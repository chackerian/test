import React from 'react';
import { Meteor } from 'meteor/meteor';
import { render } from 'react-dom';
import '../stylesheets/main.scss';
import { App } from '/imports/ui/App';
import '../imports/api/methods.js'

Meteor.startup(() => {
  render(<App/>, document.getElementById('react-target'));
});
