import React, { Component } from 'react';
import { connect } from 'react-redux';
import { Meteor } from 'meteor/meteor';
import { Listing } from '/imports/api/links.js';

var HomeCard = ({item}) => (
  <div className="grid-item">
    <li className="homeCardLi">
      <ul className="homeCardItem">
        <li><a className='imglink' href={`/listing/${item.urlKey}`}><img src="https://static.nike.com/a/images/t_PDP_1280_v1/f_auto,q_auto:eco/78e78695-74ab-4162-b052-67f004aad13b/air-max-270-g-golf-shoe-GVHWZK.png" className="homeCardImg"/></a></li>
      </ul>
      <ul className="homeCardDetails">
        <li className='homeTitle'><a href={`/listing/${item.urlKey}`}><h4>{item.listing_title}</h4></a></li>
        <li className="homeCardLeft">
            <ul>
              <li className="money homePrice">${item.price}</li>
            </ul>
        </li>
        <li className="homeCardRight">
            <ul>
              <li className="homeCardUser" popshow='true'>
                <a href={`/profile/${item.creator_id}`} className="profile-link">{item.creator_initials}</a>
              </li>
            </ul>
        </li>
      </ul>
    </li>
  </div>
)

class Home extends Component {

  constructor(props) {
    super(props)
  }

  cards() {
    let listings = Listing.find({ status: "Pending" }).fetch();
    return(
      listings.map((item, index) => {
        return (
          <HomeCard index={index} item={item} key={index} />
        )
      })
    )
  }

  // componentDidMount() {
  //   $("[popshow='true']").hover(() => {
  //     var pos = $(this).getBoundingClientRect();
  //     var left = pos.left;
  //     var top = pos.top+30;
  //     console.log(top, left);
  //     $('.popover').css({
  //       'left': left,
  //       'top': top 
  //     });
  //     $('popover').toggle();
  //   })
  // }

  render() {
    return (
      <div className="homeCard">
        <ul className="homeCardUl">
          <div className="grid" data-isotope='{ "itemSelector": ".grid-item", "masonry": { "columnWidth": 200 } }'>
            { this.cards() }
          </div>
        </ul>
      </div>
    )
  }

}

export default Home
