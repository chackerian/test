import React, { Component } from 'react';
import { connect } from 'react-redux';
import { Meteor } from 'meteor/meteor';

class SettingsModal extends Component {

  constructor(props) {
    super(props)
    this.state = {
      locay: ''
    }
  }

  remove = () => {
    Meteor.call('deleteAccount');
  }

  componentDidMount() {
      var mape = new google.maps.places.SearchBox(document.getElementById('pac-input'));
      mape.getPlaces();
  }

  render() {
    var image = Meteor.user().profile.picturelrg;
    var email = Meteor.user().services.facebook.email;
    var city = JSON.parse(Meteor.user().profile.location).city;
    var state = JSON.parse(Meteor.user().profile.location).region;
    var loca = city + " " + state;
    this.setState({locay: loca})
    return (
      <div className="modal-dialog">
        <div className="modal-content">
          <div className='modal-head'>
            <div className='modal-header'>Edit Profile</div>
            <div className="modal-close"><a className="close" onClick={this.props.close}><i className="material-icons">close</i></a></div>
          </div>
          <div className="modal-body">
            <li className="profileSettingsLi">
              <ul className="profileSettingsEmail">
                <li><h4>Email</h4></li>
                <li><input type="text" placeholder="Email" data-key="listing_title" value={this.state.listing_title} onChange={(event) => this.handleChange(event)} /></li>
              </ul>
            </li>
            <li className="profileSettingsLi">
              <ul className="profileSettingsBlock">
                <li><h4>Location</h4></li>
                <li><input id="pac-input" className="controls" type="text" placeholder="Choose Location" data-key="listing_title" value={this.state.locay} onChange={(event) => this.handleChange(event)} /></li>
              </ul>
            </li>
            <a className=''>Change Background color</a>
            <a className='blackon' onClick={this.remove}>Delete Account</a>
          </div>
          <div className='modal-foot'>
              <div className="modMultiBtn">
                <button type="button" className="modalNext" onClick={this.edit}>Update</button>
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
      image: () => dispatch({type: 'IMAGE'})
  };
};

export default connect(null, mapDispatchToProps)(SettingsModal)
