import React, { Component } from 'react';
import { connect } from 'react-redux';

class Alert extends Component {

  render() {
    if (this.props.alert == "add") {
      setTimeout(function(){
        return (
          <div className="fall">
            <span>Welcome</span>
          </div>
        )
      }, 2000)
    } 

    if (this.props.alert == "login") {
      setTimeout(function(){
        return (
          <div className="fall">
            <span>Welcome</span>
          </div>
        )
      }, 2000)
    } 

    else {
      return null
    }
  }

}

const mapStateToProps = state => {
  return {
    alert: state.alert
  };
}

export default connect(mapStateToProps, null)(Alert)
