import React, { Component } from 'react';
import { Listing } from '/imports/api/links.js';

export default class Carousel extends Component {

  componentDidMount() {
    $('.carousel').flickity({
      freeScroll: true,
      lazyLoad: true,
      wrapAround: true
    });
    var left = (475-$(".carousel-cell-image").width())/2
    $(".carousel-cell-image").css('left', left)

  }

  render() {
    var listing = Listing.find({urlKey: FlowRouter.current().params.id}).fetch()[0];
    var img = listing.images;

    return (
      <div className="carousel carousel-main" data-flickity>
        <div className="carousel-cell"><img className="carousel-cell-image" data-flickity-lazyload={img[0]} /></div>
        <div className="carousel-cell"><img className="carousel-cell-image" data-flickity-lazyload={img[0]} /></div>
        <div className="carousel-cell"><img className="carousel-cell-image" data-flickity-lazyload={img[0]} /></div>
        <div className="carousel-cell"><img className="carousel-cell-image" data-flickity-lazyload={img[0]} /></div>
      </div>
    )
  }

}
