import React, { Component } from 'react';
import { Meteor } from 'meteor/meteor';
import { connect } from 'react-redux';
import Dropzone from '../Solo/drop.jsx';
import { TextField } from '@mui/material'
import { getStorage, ref, uploadBytes, getDownloadURL } from "firebase/storage";

String.prototype.shorten = function(n) {
  return (this.length > n) ? this.substr(0, n-1) + '...' : this.substr(0,n);
};


    // var image = acceptedFiles[0]

    //   const uploadImage = async (image) => {
    //       const response = await fetch(image.path);

    //        var file = acceptedFiles[0].path

    //        var filename = "images/" + "IMG" + Math.round(Math.random()*10000)
    //        var refs = store.ref().child(filename);

    //         // 'file' comes from the Blob or File API
    //         uploadBytes(refs, image).then((snapshot) => {
    //           console.log('Uploaded a blob or file!', snapshot);

    //           getDownloadURL(snapshot.ref).then((downloadURL) => {
    //             console.log('File available at', downloadURL);
    //             setImageURL(downloadURL)
    //           });
    //         });
    //   }
      

class AddModal extends Component {

  constructor(props) {
    super(props);
    this.state = {
      modaltab: 1,
      types: []
    }
  }

  nextPage(event) {
    var next = parseInt(event.target.getAttribute('data-step'))+1
    this.setState({
      modaltab: next
    })
  }

  backPage(event) {
    var past = parseInt(event.target.getAttribute('data-step'))-1
    this.setState({
      modaltab: past
    })
  }

  selectChange(event) {
    let catvalue = event.target.value;

    const categories = {
      'Apparel': ['Shirt', 'Hoodie', 'Sweater', 'Pants', 'Jacket', 'Socks', 'Hat', 'Backpack'],
      'Electronics': ['Phone', 'Tablet', 'Laptop', 'Game', 'Game Console'],
      'Shoes': ['Basketball', 'Boots', 'Running', 'Casual', 'Sandals', 'Training', 'Skateboarding'],
      'Other': ['Other']
    }

    const brands = {
      'Apparel': ['Bape', 'Supreme', 'Other'],
      'Electronics': ['Apple', 'Asus', 'Beats by Dr Dre', 'Blackberry', 'Bose', 'Cannon', 'Dell', 'Go Pro', 'Google', 'HP', 'Lenovo', 'Logitech', 'Microsoft', 'Nikon', 'Nintendo', 'Panasonic', 'Samsung', 'Sandisk', 'Sharp', 'Sony', 'Turtle Beach', 'Vizio', 'Other'],
      'Shoes': ['Asics', 'Jordans', 'Converse', 'Ewing Athletics', 'Fila', 'Li Ning', 'New Balance', 'Nike', 'Puma', 'Radii', 'Reebok', 'Saucony', 'Sperry', 'Supra', 'Timberland', 'Toms', 'Vans', 'Under Armour', 'Other'],
      'Other': ['Other']
    }

    this.setState({
      category: catvalue,
      types: categories[catvalue],
    })

  }

  selectTypeChange(event) {
    this.setState({
      type: event.target.value
    })
  }

  actionBold = () => {
    document.execCommand('bold');
  }

  actionItalic = () => {
    document.execCommand('italic');
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

  createListing = (props) => {

    var titled = this.state.title.charAt(0).toUpperCase() + this.state.title.slice(1)

    var splite = Meteor.user().profile.name.split(" ")
    var last = splite[1].charAt();
    var initials = splite[0] + " " + last;

    var key = this.state.title.replace(/ /g, '-')+Math.random().toString(36).slice(2, 7)

    var options = {
      creator_id: Meteor.userId(),
      creator_facebook_id: Meteor.user().services.facebook.id,
      creator_image: Meteor.user().services.facebook.picture.data.url,
      creator_username: Meteor.user().profile.name,
      creator_initials: initials,
      listing_title: this.state.title,
      urlKey: this.state.title.replace(/ /g, '-')+"-"+Math.random().toString(36).slice(2, 9),
      images: [],
      category: this.state.category,
      type: this.state.type,
      price: this.state.price,
      description: this.state.description,
    }

    function addListingValidate() {
      for (var x in options) {
        if (options[x].length > 0) {
          return true
        }
      }
    }

    if (addListingValidate()) {
      console.log("Listing Options", options)
      Meteor.call('addListing', options);
      this.props.close()
      $('.modal-backdrop').remove();
    }

  }

  componentDidMount() {
    $(".listtitle").focus()
  }

  render() {
    if (this.state.modaltab == 1) {
      return(
        <div className="modal fade" id="myModal" role="dialog">
          <div className="modal-dialog">
            <div className="modal-content">
              <div className="modal-header">
                <button type="button" className="close" data-dismiss="modal">&times;</button>
                <h4 className="modal-title">Add Listing</h4>
              </div>
              <div className="modal-body">
                <div className="modAddListingPage">
                  <ul className="modAddListingPageOneUl">
                    <li>
                      <h3 className="listing_title">What Are You Selling?</h3>
                      <TextField id="filled-basic" className="addPrice" label="Title" variant="filled" maxLength="30" data-key="title" value={this.state.title} onChange={(event) => this.setTitle(event)}/>
                    </li>
                    <li>
                      <h3>At What Price?</h3>
                      <TextField id="filled-basic" label="Price" variant="filled" maxLength="5" data-key="price" value={this.state.price} onChange={(event) => this.setPrice(event)}/>
                    </li>
                  </ul>
                </div>
              </div>
              <div class="modal-footer">
                  <button type="button" className="btn btn-default modalNext" data-step="1" onClick={(event) => this.nextPage(event)}>Next</button>
              </div>
            </div>
          </div>
        </div>
      )
    }

    if (this.state.modaltab == 2) {
      return(
        <div className="modal fade" id="myModal" role="dialog">
          <div className="modal-dialog">
            <div className="modal-content">
              <div className="modal-header">
                <button type="button" className="close" data-dismiss="modal">&times;</button>
                <h4 className="modal-title">Add Listing</h4>
              </div>
              <div className="modal-body">
                  <div className="modAddListingPage">
                    <ul className="modAddListingPageOneUl">
                        <li className="modOfferRequestOfferWrap">
                            <h3 className="category">What is its Category?</h3>
                            <div className="styled-select">
                                <select className="listcategory" value={this.state.category} onChange={(event) => this.selectChange(event)}>
                                    <option defaultValue>Select Category</option>
                                    <option value="Apparel">Apparel</option>
                                    <option value="Electronics">Electronics</option>
                                    <option value="Shoes">Shoes</option>
                                    <option value="Other">Other</option>
                                </select>
                            </div>
                        </li>
                          <li className="modOfferRequestOfferWrap">
                            <h3 className="typed">What is its Type?</h3>
                            <select className="listtype" value={this.state.type} onChange={(event) => this.selectTypeChange(event)}>
                              <option defaultValue>Select Type</option>
                              {
                                this.state.types.map(type => {
                                  return <option value={type}>{type}</option>
                                })
                              }
                            </select>
                          </li>
                      </ul>
                </div>
              </div>
              <div class="modal-footer">
                <button type="button" class="btn btn-default modalBack" data-step="2" onClick={(event) => this.backPage(event)}>Back</button>
                <button type="button" className="btn btn-default modalNext" data-step="2" onClick={(event) => this.nextPage(event)}>Next</button>
            </div>
            </div>
          </div>
          </div>
        )
      }

  if (this.state.modaltab == 3) {

    return(
      <div className="modal fade" id="myModal" role="dialog">
          <div className="modal-dialog">
            <div className="modal-content">
              <div className="modal-header">
                <button type="button" className="close" data-dismiss="modal">&times;</button>
                <h4 className="modal-title">Add Listing</h4>
              </div>
              <div className="modal-body">
                <div className="modAddListingPage imageUploadPage">
                  <ul className="addListImg">
                    <Dropzone></Dropzone>
                  </ul>
                </div>
              </div>
              <div class="modal-footer">
                <button type="button" class="btn btn-default modalBack" data-step="3" onClick={(event) => this.backPage(event)}>Back</button>
                <button type="button" className="btn btn-default modalNext" data-step="3" onClick={(event) => this.nextPage(event)}>Next</button>
            </div>
            </div>
          </div>
        </div>
      )
  }

    if (this.state.modaltab == 4) {
      return(
        <div className="modal fade" id="myModal" role="dialog">
          <div className="modal-dialog">
            <div className="modal-content">
             <div className="modal-header">
                <button type="button" className="close" data-dismiss="modal">&times;</button>
                <h4 className="modal-title">Add Listing</h4>
              </div>
              <div className="modal-body">
                <div className="addBitExterior">
                  <div className="toolbar">
                    <ul className="tools">
                      <li><a onMouseDown={(event) => event.preventDefault()} onClick={this.actionBold}><i className="material-icons tool">format_bold</i></a></li>
                      <li><a onMouseDown={(event) => event.preventDefault()} onClick={this.actionItalic}><i className="material-icons tool">format_italic</i></a></li>
                      <li><a onMouseDown={(event) => event.preventDefault()} onClick={this.actionLink}><i className="material-icons tool">link</i></a></li>
                    </ul>
                  </div>
                  <div contentEditable="true" data-text="Enter description" className="contentsBit" value={this.state.description} onInput={(event) => this.setDescription(event)}></div>
                </div>
              </div>
              <div class="modal-footer">
                  <button type="button" class="btn btn-default modalBack" data-step="4" onClick={(event) => this.backPage(event)}>Back</button>
                  <button type="button" className="btn btn-default modalNext" data-step="4" onClick={this.createListing}>Create</button>
              </div>
            </div>
          </div>
        </div>
      )
    }
  }

}

const mapDispatchToProps = dispatch => {
  return {
      close: () => dispatch({type: 'CLOSE'}),
      alert: () => dispatch({type: 'NOTIFY'})
  };
};

export default connect(null, mapDispatchToProps)(AddModal)
