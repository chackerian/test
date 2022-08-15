import React, { Component } from 'react';
import HelpNav from './nav.jsx';

export default class Safety extends Component {

  render() {
    return(
      <div className="oneDiv">
        <HelpNav />
        <h2>Don't Reveal Sensitive Personal Information</h2>

        Never reveal information that is unrelated to the meetup that the other party doesn't need to know.

        <h2>Only Meet During the Day</h2>

        It's a good idea to meet only in the daytime when more people are outside.

        <h2>Always Meet in a Public Place</h2>

        Never agree to meet in a secluded place where there are not any other people present.

        <h2>Be Especially Mindful When Trading High Value Items</h2>

        The higher the price of things, the greater the risk of something going wrong.

        <h2>Consider Having a Friend Accompany You</h2>

        It's a good idea to have a friend or trusted person accompany you to your meetup.
      </div>
      )
    }
  }
