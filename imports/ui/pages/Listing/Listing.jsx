import React, { Component } from 'react';
import { Meteor } from 'meteor/meteor';
import { Listing } from '/imports/api/links.js';
import { connect } from 'react-redux';
import Carousel from './carousel.jsx';
import { FlowRouter } from 'meteor/kadira:flow-router';

class ListingItem extends Component {

  constructor(props) {
    super(props)
  }

  settings() {
    $(".settings > .headerDropDownNav").toggle();
  }

  save() {
    if(Meteor.user()){
      Meteor.call('saveListing', FlowRouter.current().params.id);
    }
  }

  manage = () => {
    var listing = Listing.find({urlKey: FlowRouter.current().params.id}).fetch()


  if (Meteor.user()){
      if (listing[0].creator_id == Meteor.user()._id) {
      return (
        <ul className="clickDropper">
          <li className="settings">
            <a onClick={this.settings}><i className="material-icons">more_horiz</i></a>
            <ul className="headerDropDownNav">
              <a data-toggle="modal" data-target="#myModal" onClick={this.props.edit}><li>Edit</li></a>
            </ul>
          </li>
        </ul>
      )
    }
  } else {
      return (
        <ul className="clickDropper">
          <li className="settings">
            <a onClick={this.settings}><i className="material-icons">more_horiz</i></a>
            <ul className="headerDropDownNav">
              <a data-toggle="modal" data-target="#myModal" onClick={this.props.report}><li>Report Listing</li></a>
              <a onClick={this.save}><li>Save</li></a>
            </ul>
          </li>
        </ul>
      )
    } 
  }

  render() {
    let listing = Listing.find({ urlKey: FlowRouter.current().params.id }).fetch()
    if (listing && listing.length > 0) {
      var listed = listing[0]
      var createdAt = moment(listed.createdAt).format("dddd, MMMM D");
      return (
        <div className="listingItemDiv">
          <div className="listingItemLeft">

            <div className="titleBox">
              <h1 className="listingItemTitle">{listed.listing_title}</h1>
            </div>

            <div className="row">
              <div className="dateDiv">
                <p className="listingItemCreated">
                  {createdAt}
                </p>
              </div>
              <div className="listingPrice">
                <ul className="listingItemPrice">
                    <li className="money itemMoney">${listed.price}</li>
                </ul>
              </div>
            </div>

            <div className='topPage'>
              <div className='leftPage'>
                <Carousel />
              </div>
              <div className='rightPage'>
                <img className='placeLocation' src="https://maps.googleapis.com/maps/api/staticmap?center=40.714728,-73.998672&zoom=15&size=800x300&key=AIzaSyDELJ-BZK9f7IXUrNMF3d0knY5N8INNqiM" />
                <div className="guardian">
                  <div className="listingItemUser">
                    <ul className="listingItemUserImg">
                        <li><a href={`/profile/${listed.creator_id}`}><img src={listed.creator_image}/></a></li>
                    </ul>
                    <ul className="listingItemUserInfo">
                        <li className="listingItemUserName"><a href={`/profile/${listed.creator_id}`}>{listed.creator_username}</a></li>
                        { this.manage() }
                    </ul>
                  </div>
                  <Social listing={listed} />
                </div>
              </div>
            </div>

          <div className='bottomPage'>
              <div className="desc-box">
                <h4 className="box-title">Description</h4>
                <p className="desc-full description">{listed.description}</p>
              </div>
          </div>
        </div>
      </div>
      )
    } else {
        return "<div> <h1>AD</h1> </div>"
      }
    }
}

const mapDispatchToProps = dispatch => {
  return {
      edit: () => dispatch({type: 'EDIT_LISTING'}),
      report: () => dispatch({ type: 'REPORT_LISTING'}),
      join: () => dispatch({type: 'JOIN'})
  };
};

export default connect(null, mapDispatchToProps)(ListingItem)

var Social = ({listing}) => (
  <div className="listingItemShare">
  <h2>Share</h2>
      <a href={`http://twitter.com/share?url=spacetrades.io/listing/${listing._id}&text=${listing.listing_title} at spacetrades.io/listing/${listing._id}`} target="_blank" className="share-btn twitter">
          <i className="fa fa-twitter"></i>
      </a>
      <a href={`https://plus.google.com/share?url=spacetrades.io/listing/${listing._id}`} target="_blank" className="share-btn google-plus">
          <i className="fa fa-google-plus"></i>
      </a>
      <a href={`http://www.facebook.com/sharer/sharer.php?u=spacetrades.io/listing/${listing._id}`} target="_blank" className="share-btn facebook">
          <i className="fa fa-facebook"></i>
      </a>
      <a href={`http://reddit.com/submit?url=spacetrades.io/listing/${listing._id}&title=SpaceTrades`} target="_blank" className="share-btn reddit">
          <i className="fa fa-reddit"></i>
      </a>
  </div>
)
