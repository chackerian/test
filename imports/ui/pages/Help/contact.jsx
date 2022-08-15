import React, { Component } from 'react';
import { Meteor } from 'meteor/meteor';
import HelpNav from './nav.jsx';

export default class Help extends Component {

  render() {
    return(
      <div className="oneDiv">
        <HelpNav />
        <div className='email'>
          <h3>Email</h3>
          <form className="contactform">
            <p className="contactsubject">
              <input type="text" id="contactSubject" placeholder="Subject" />
            </p>
            <p className="contacttext">
              <textarea placeholder="Message" className="message"></textarea>
            </p>
            <ul className="blackon">
                <li><a href="#" onClick={this.edit}>Send</a></li>
            </ul>
          </form>
        </div>
        <div className='phone'>
          <h3>Phone</h3>
          <div className="phoneNumber">
              Call <a href="tel:7182859432" className="phone">718-285-9432</a>
          </div>
        </div>
      </div>
    )
  }
}
