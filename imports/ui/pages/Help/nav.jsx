import React, { Component } from 'react';

export default class HelpNav extends Component {

  render() {
    return(
      <div className="helpcenternav">
        <nav className="helpnav">
          <ul className="helpiteml">
              <li><a href="/help" className="helpitem">Home</a></li>
              <li><a href="/help/faq" className="helpitem">FAQ</a></li>
              <li><a href="/help/safety" className="helpitem">Safety</a></li>
              <li><a href="/help/prohibited" className="helpitem">Prohibited</a></li>
              <li><a href="/help/terms" className="helpitem">Terms &amp; Privacy</a></li>
              <li><a href="/help/contact" className="helpitem">Contact</a></li>
          </ul>
        </nav>
      </div>
    )
  }

}
