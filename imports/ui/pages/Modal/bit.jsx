import React, { Component } from 'react';
import { Meteor } from 'meteor/meteor';
import { connect } from 'react-redux';

class AddBitModal extends Component {

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

  remove = () => {
    Meteor.call('cacheListing', options);
  }

  handleChange(event) {
    var key = event.target.getAttribute('data-key');
    this.setState({
      [key]: event.target.value
    })
  }

  render() {
    return(
        <div className="modal-dialog">
          <div className="modal-content">
            <div className='modal-head'>
              <div className='modal-header'>Add Bit</div>
              <div className="modal-close"><a className="close" onClick={this.props.close}><i className="material-icons">close</i></a></div>
            </div>
            <div className="modal-body">
              <div classname='mod-top'>
                <input type="text" className="listtitle" placeholder="Title" maxLength="30" value={this.state.listing_title} onChange={(event) => this.handleChange(event)} />
                <input type="text" className="money price" placeholder="Price" maxLength="5" value={this.state.price} onChange={(event) => this.handleChange(event)} />
              </div>
              <div className="addBitExterior">
                <div className="toolbar">
                  <ul className="tools">
                    <li><a onMouseDown={(event) => event.preventDefault()} onClick={this.actionBold}><i className="material-icons tool">format_bold</i></a></li>
                    <li><a onMouseDown={(event) => event.preventDefault()} onClick={this.actionItalic}><i className="material-icons tool">format_italic</i></a></li>
                    <li><a onMouseDown={(event) => event.preventDefault()} onClick={this.actionLink}><i className="material-icons tool">link</i></a></li>
                  </ul>
                </div>
                <div contentEditable="true" data-text="Enter description" className="contentsBit"></div>
                <a onClick={this.remove}>Delete Listing</a>
              </div>
            </div>
            <div className='modal-foot'>
              <div className="modMultiBtn">
                  <button type="button" className="modalNext" onClick={this.update}>Update</button>
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