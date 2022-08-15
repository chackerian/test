import React, { Component } from 'react';
import { Meteor } from 'meteor/meteor';
import { connect } from 'react-redux';
import Dropzone from '../Solo/drop.jsx';

class ImageModal extends Component {
          
  render() {
    return(
      <div className="modal-dialog">
        <div className="modal-content">
          <div className='modal-head'>
            <div className='modal-header'>Edit Photo</div>
            <div className="modal-close"><a className="close" onClick={this.props.close}><i className="material-icons">close</i></a></div>
          </div>
          <div className="modal-body step">
            <div className="modAddListingPage">
              <ul className="addListImg">
                <Dropzone></Dropzone>
              </ul>
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

export default connect(null, mapDispatchToProps)(ImageModal)