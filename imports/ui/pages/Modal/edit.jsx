import React, { Component } from 'react';
import { Meteor } from 'meteor/meteor';
import { connect } from 'react-redux';
import { Listing } from '/imports/api/links.js';

class EditListingModal extends Component {

  constructor(props) {
    super(props)
    this.state = {
      price:"",
      listing_title:""
    }
  }

  update() {
    Meteor.call('updateListing', options);
  }

  remove = (listing) => {
    var options = {
      id: listing._id,
      creator_id: listing.creator_id
    }
    Meteor.call('removeListing', options);
    this.props.close()
    $('.modal-backdrop').remove();
    FlowRouter.go("/")
  }

  setTitle(event) {
    this.setState({
      title: event.target.value
    })
  }

  setDescription(event) {
    this.setState({
      description: event.target.innerText
    })
  }

  setPrice(event) {
    this.setState({
      price: event.target.value
    })
  }

  render() {
    let listing = Listing.find({ urlKey: FlowRouter.current().params.id }).fetch()[0]
    console.log("LISTING EDIT", listing)
    return(
      <div className="modal fade" id="myModal" role="dialog">
        <div className="modal-dialog">
          <div className="modal-content">
            <div className='modal-header'>
              <button type="button" className="close" data-dismiss="modal">&times;</button>
              <div className='modal-title'>Edit Listing</div>
            </div>
            <div className="modal-body">
              <div classname='mod-top'>
                <input type="text" className="listtitle" placeholder="Title" maxLength="30" value={listing.listing_title} onChange={(event) => this.handleChange(event)} />
                <input type="text" className="money price" placeholder="Price" maxLength="5" value={listing.price} onChange={(event) => this.handleChange(event)} />
              </div>
              <div className="addBitExterior">
                <div className="toolbar">
                  <ul className="tools">
                    <li><a onMouseDown={(event) => event.preventDefault()} onClick={this.actionBold}><i className="material-icons tool">format_bold</i></a></li>
                    <li><a onMouseDown={(event) => event.preventDefault()} onClick={this.actionItalic}><i className="material-icons tool">format_italic</i></a></li>
                    <li><a onMouseDown={(event) => event.preventDefault()} onClick={this.actionLink}><i className="material-icons tool">link</i></a></li>
                  </ul>
                </div>
                <div contentEditable="true" data-text="Enter description" value={listing.description} className="contentsBit"></div>
              </div>
            </div>
            <div className='modal-foot'>
              <div className="modMultiBtn">
                  <button type="button" onClick={() => this.remove(listing)}>Delete Listing</button>
              </div>
              <div className="modMultiBtn">
                  <button type="button" onClick={this.update}>Update</button>
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
      close: () => dispatch({type: 'CLOSE'})
  };
};

export default connect(null, mapDispatchToProps)(EditListingModal)