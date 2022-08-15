import React, { Component } from 'react';
import { Listing } from '/imports/api/links.js';
import { Meteor } from 'meteor/meteor';
import { connect } from 'react-redux';

class reportUser extends Component {

    constructor(props) {
      super(props)
    }

    render() {
      return(
        <div className="modal-dialog">
          <div className="modal-content">
            <div className='modal-head'>
              <div className='modal-header'>Report User</div>
              <div className="modal-close"><a className="close" onClick={this.props.close}><i className="material-icons">close</i></a></div>
            </div>
            <div className="modal-body">
              <div className="modReportPageOne">
                <h2>Select All That Apply</h2>
                  <ul>
                  	<li><input type="checkbox" />Using a Fake Name</li>
                  	<li><input type="checkbox" />User is a Scammer</li>
                  	<li><input type="checkbox" />User is Racist/Offensive</li>
                  	<li><input type="checkbox" />User is Posting Spam</li>
                  </ul>
                    </div>
                    <div className="modReportPageThree">
                      <h2>Tell Us More</h2>
                      <div placeholder="Explain briefly" contentEditable="true"></div>
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

export default connect(null, mapDispatchToProps)(reportUser)
