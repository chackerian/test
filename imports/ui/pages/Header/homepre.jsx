import React, { Component } from 'react';
import { connect } from 'react-redux';

class Homepre extends Component {

  componentDidMount() {
    // $(".search").keypress(function(e) {
    //   if (e.key == "Enter") {
    //     var search = $(".search").val();
    //     FlowRouter.go("/search?q="+search);
    //   }
    // });
  }

  render() {
    return (
        <nav className="headerNav">
          <div className="wholeNav">
            <div className="leftNav">
              <div className="iconLogo">
                <a href="/" className="radiusLogo"></a>
              </div>
              <div className="searchBox">
                <input type="text" className="search" placeholder="Search" autoFocus="True" />
              </div>
            </div>
            <div className="rightNav">
              <ul className="headerAuth">
                  <li><a href="#" data-toggle="modal" data-target="#myModal" onClick={this.props.join}>Login</a></li>
              </ul>
              <ul className="headerAuth">
                  <li><a href="#" data-toggle="modal" data-target="#myModal" onClick={this.props.join}>Sign Up</a></li>
              </ul>
            </div>
          </div>
        </nav>
      )
    }
}

const mapDispatchToProps = dispatch => {
  return {
      join: () => dispatch({type: 'JOIN'})
  };
};

export default connect(null, mapDispatchToProps)(Homepre)
