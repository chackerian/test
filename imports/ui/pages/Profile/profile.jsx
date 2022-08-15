import React, { Component } from 'react';
import { Meteor } from 'meteor/meteor';
import { Listing } from '/imports/api/links.js';
import { connect } from 'react-redux';
import { FlowRouter } from 'meteor/kadira:flow-router';

class Profile extends Component {

  constructor(props) {
    super(props)
  }

  message = () => {
    FlowRouter.go('/chat')
  }

  settings = () => {
    $(".prof_settings > .headerDropDownNav").toggle();
  }

  edit = () => {
    if (Meteor.userId() == FlowRouter.current().params.id) {
      return (
        <ul className="editButton">
          <li><a className='blackon' onClick={this.props.edit}>Edit</a></li>
          <li className='prof_settings'>
            <a onClick={this.settings}><i className="material-icons">more_horiz</i></a>
            <ul className="headerDropDownNav">
              <a><li>Edit</li></a>
            </ul>
          </li>
        </ul>
      )
    } else if (Meteor.user()) {
      return (
        <ul className="editButton">
          <li><a className='blackon' onClick={this.message}>Message</a></li>
          <li className='prof_settings'>
            <a onClick={this.settings}><i className="material-icons">more_horiz</i></a>
            <ul className="headerDropDownNav">
              <a><li>Edit</li></a>
            </ul>
          </li>
        </ul>
      )
    }
    else {
      return (
        <ul className="editButton">
          <li><a className='blackon' onClick={this.props.join}>Message</a></li>
          <li className='prof_settings'>
            <a data-toggle="tooltip" onClick={this.settings}><i className="material-icons">more_horiz</i></a>
            <ul className="headerDropDownNav">
              <a><li>Edit</li></a>
            </ul>
          </li>
        </ul>
      )
    }
  }

  render() {
    var profile = Meteor.users.find({_id: FlowRouter.current().params.id}).fetch()
    if (profile.length > 0) {

      var prof = profile[0];
      console.log(prof)
      var name = prof.profile.name;
      var img = prof.services.facebook.picture.data.url

      try {
        var city = JSON.parse(prof.profile.location).city || "";
        var state = JSON.parse(prof.profile.location).region || "";
      } catch(err) {
        var city = ""
        var state = ""
      }

        return(
          <div className="oneDiv">
            <div className="topStrip">
              <div className="profileUserLeft">
                  <div className="profileUserImage"><img className='profilePic' src={img} /><a onClick={this.props.image}>
                  <div className='overflower'><div className="overflow">Edit Photo</div></div></a></div>
              </div>
              <div className='name'>{name}</div>
              { this.edit() }
            </div>
            <div className='bottom'>
              <div className='desc location'>
                <i class="fa fa-map-marker" aria-hidden="true"></i>{city}, {state}
              </div>
              <div className='desc'>
                <a href=""> <i class="fa fa-facebook-square fbconnect" aria-hidden="true"></i></a>
              </div>
            </div>
          </div>
        )
    } else {
        return(
          <div className="oneDiv">
            User doesn't exist
          </div>
        )
    }
  }

}

const mapDispatchToProps = dispatch => {
  return {
      edit: () => dispatch({ type: 'EDIT_PROFILE'}),
      image: () => dispatch({ type: 'IMAGE'}),
      join: () => dispatch({type: 'JOIN'})
  };
};

export default connect(null, mapDispatchToProps)(Profile)
