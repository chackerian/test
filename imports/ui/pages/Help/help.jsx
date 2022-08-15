import React, { Component } from 'react';
import { Meteor } from 'meteor/meteor';
import HelpNav from './nav.jsx';

export default class Help extends Component {

  constructor(props) {
    super(props)
  }

  render() {
    return (
      <div className="oneDiv">
          <HelpNav />
          <h2 className="helpShow">Welcome to the Help Center</h2>

          <div className="helpCenterThree">
              <ul className="helpThree">
                  <li>
                      <ul>
                          <li><h3>Get Answers</h3></li>
                          <li>If you have any questions, look over the <a className='link' href="/help/faq">FAQ</a>.</li>
                      </ul>
                  </li>
                  <li>
                      <ul>
                          <li><h3>Contact us</h3></li>
                          <li>If you would like to <a className='link' href="/help/contact">get in touch</a> with us for any reason.</li>
                      </ul>
                  </li>
                  <li>
                      <ul>
                          <li><h3>Review Safety Tips</h3></li>
                          <li>Take a look at the <a className='link' href="/help/safety">Safety Tips</a>.</li>
                      </ul>
                  </li>
                  <li>
                      <ul>
                          <li><h3>Review Terms and Conditions</h3></li>
                          <li>By using this site, you agree to certain <a className='link' href="/help/terms">Terms &amp; Conditions</a>.</li>
                      </ul>
                  </li>
              </ul>
          </div>
      </div>
    )
  }

}
