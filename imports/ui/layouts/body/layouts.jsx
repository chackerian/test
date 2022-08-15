import React, { Component } from 'react';
import { Meteor } from 'meteor/meteor';

import { Listing } from '/imports/api/links.js';

import { withTracker } from 'meteor/react-meteor-data';
import { Provider } from 'react-redux';
import { createStore } from 'redux';
import reducer from '../../reducers/reduced.js';

import Alert from '../../pages/Solo/alert.jsx';
import Header from '../../pages/Header/header.jsx';
import Modal from '../../pages/Modal/modal.jsx';
import Popper from '../../pages/Solo/popper.jsx';

export const store = createStore(reducer);

HeaderContainer = withTracker(({ urlKey }) => {
  const list = Meteor.user();
  return {
    list
  };
})(Header);

export default class MainLayout extends Component {

  constructor(props) {
    super(props);
    this.state = {
      modal: "",
      status: ""
    }
  }

  render() {
    return (
      <Provider store={store}>
        <div>
          <Alert />
          <Modal />
          <Popper />
          <HeaderContainer />
          {this.props.content}
        </div>
      </Provider>
    )
  }
}
