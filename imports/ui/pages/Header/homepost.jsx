import React, { Component } from 'react';
import { currentUsername } from '../helpers.js';
import { connect } from 'react-redux';
import 'jquery';
 
class Homepost extends Component {

  logout = () => {
    Meteor.logout();
  }

  clearToggle() {
    if ($(".navNotifications > .headerDropDownNav").is(":visible")) {
      $(".navNotifications > .headerDropDownNav").toggle();
    }
    if ($(".navGeneral > .headerDropDownNav").is(":visible")) {
      $(".navGeneral > .headerDropDownNav").toggle();
    }
  }

  navGeneral() {
    if ($(".navNotifications > .headerDropDownNav").is(":visible")) {
      $(".navNotifications > .headerDropDownNav").toggle();
    }
    $(".navGeneral > .headerDropDownNav").toggle();
  }

  navNotifications() {
    if ($(".navGeneral > .headerDropDownNav").is(":visible")) {
      $(".navGeneral > .headerDropDownNav").toggle();
    }
    $(".fa-globe").removeClass('notificationHighlight');
    $(".navNotifications > .headerDropDownNav").toggle()
  }

  componentDidMount() {
    this.clearToggle();
    $(".search").keypress(function(e) {
      if (e.key == "Enter") {
        var search = $(".search").val();
        FlowRouter.go("/search?q="+search);
      }
    });
  }

  render() {
    let profile = Meteor.user()._id;
    this.clearToggle();
    return (
      <nav className="headerNav">
        <div className="wholeNav">
          <div className="leftNav">
            <div className="iconLogo">
              <a href="/" className="radiusLogo">
              </a>
            </div>
            <div className="searchBox">
              <input type="text" className="search" placeholder="Search" autoFocus="True" />
            </div>
          </div>
          <div className="rightNav">
            <ul>
              <li>
                <a className='blackon' href={`/profile/${profile}`}>
                  <span>{currentUsername()}</span>
                </a>
              </li>
            </ul>
            <ul className="headerAuth">
                <li><a href="#" className="btn" data-toggle="modal" data-target="#myModal" onClick={this.props.add}>Add Listing</a></li>
            </ul>
            <ul className="clickDropper">
              <li className="navNotifications">
                <a onClick={this.navNotifications}><i className="material-icons matdrop">notifications</i><span className='notify'></span></a>

                <ul className="headerDropDownNav">
                  <a href='/chat'><li>You received a message</li></a>
                </ul>
              </li>
              <li className="navGeneral">
                <a onClick={this.navGeneral}><i className="material-icons matdrop">more_vert</i></a>
                <ul className="headerDropDownNav">
                  <a href={`/profile/${profile}`}><li>Profile</li></a>
                  <a href="/listings"><li>Listings</li></a>
                  <a href="/saved"><li>Saved</li></a>
                  <a href="/help"><li>Help Center</li></a>
                  <a href="#" onClick={this.logout}><li>Log out</li></a>
                </ul>
              </li>
            </ul>
          </div>
        </div>
      </nav>
    )
  }

}

const mapDispatchToProps = dispatch => {
  return {
      add: () => dispatch({ type: 'ADD'})
  };
};

export default connect(null, mapDispatchToProps)(Homepost)
