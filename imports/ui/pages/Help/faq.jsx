import React, { Component } from 'react';
import HelpNav from './nav.jsx';

export default class AboutHelp extends Component {

  render() {
    return(
      <div className="oneDiv">
        <HelpNav />
        <h1>SpaceTrades helps people organize meetups for buying and selling items locally.</h1>
        <h2>How Does It Work?</h2>
        Create a listing, wait for messages from other users, organize a meetup.
      </div>
    )
  }
}
