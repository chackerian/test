import React, { Component } from 'react';

import JoinModal from './join.jsx';
import AddModal from './add.jsx';
import EditListingModal from './edit.jsx';
import SettingsModal from './settings.jsx';
import ReportUserModal from './reportUser.jsx';
import ReportListingModal from './reportListing.jsx';
import ImageModal from './image.jsx';

import { connect } from 'react-redux';

class Modal extends Component {

  constructor(props) {
    super(props)
  }

  render() {
    if (this.props.status == "on") {
      // $(".modal-backdrop").remove()
      // $("body").append("<div class='modal-backdrop'></div>");
      // $("body").css("overflow", "hidden")
      if (this.props.modal == "add") {
        return <AddModal />
      }
      if (this.props.modal == "join") {
        return <JoinModal />
      }
      if (this.props.modal == "editListing") {
        return <EditListingModal />
      }
      if (this.props.modal == "editProfile") {
        return <SettingsModal />
      }
      if (this.props.modal == "reportListing") {
        return <ReportListingModal />
      }
      if (this.props.modal == "reportUser") {
        return <ReportUserModal />
      }
      if (this.props.modal == "image") {
        return <ImageModal />
      }
    } else {
      // $(".modal-backdrop").remove();
      // $("body").css("overflow", "visible");
      return null
    }
  }

}

const mapStateToProps = state => {
  return {
    modal: state.modal,
    status: state.status
  };
}

export default connect(mapStateToProps, null)(Modal)
