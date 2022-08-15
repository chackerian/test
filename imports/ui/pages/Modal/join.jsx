import React, { Component } from 'react';
import { Listing } from '/imports/api/links.js';
import { Meteor } from 'meteor/meteor';
import { connect } from 'react-redux';

class JoinModal extends Component {

  login = () => {
    this.props.close();
    Meteor.loginWithFacebook({
      requestPermissions: ['user_friends', 'public_profile', 'email']
    }, function(err, result) {
        setTimeout(function(){
          $.getJSON('//json.geoiplookup.io/api', function(data) {
            var options = {
              id: Meteor.user()._id,
              location: JSON.stringify(data, null, 2)
            }
            Meteor.call('updateUserCreation', options)
          });
        }, 5000);
    })
    this.props.alert();
    $('.modal-backdrop').remove();
  }

  render() {
    return(
      <div className="modal fade" id="myModal" role="dialog">
        <div className="modal-dialog">
          <div className="modal-content">
            <div className="modal-body">
                <button type="button" className="close" data-dismiss="modal">&times;</button>
                <h1>Join SpaceTrades</h1>
                <ul>
                  <li className="modJoinMessage">SpaceTrades helps people buy and sell items locally.</li>
                </ul>
                <p className="joinAgreeSmall">By signing up you agree to our <a className="link" target="_blank" href="/help/terms">Terms and Conditions</a></p>
                <div className="join-button facebook" onClick={this.login}>
                  <i className="fa fa-facebook-square"></i>
                  <span>Continue with Facebook</span>
                </div>
                <div className="join-button google" onClick={this.login}>
                  <i className="fa fa-google"></i>
                  <span>Continue with Google</span>
                </div>
            </div>
          </div>
        </div>
      </div>
    )
  }

}

const mapDispatchToProps = dispatch => {
  return {
      close: () => dispatch({type: 'CLOSE'}),
      alert: () => dispatch({type: 'NOTIFY'})
  };
};

export default connect(null, mapDispatchToProps)(JoinModal)
