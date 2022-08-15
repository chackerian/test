export function currentUsername() {
  if(Meteor.user()) {
    var split = Meteor.user().profile.name.split(" ");
    var last = split[1].charAt();
    var merge = split[0] + " " + last;
    return merge;
  }
}

export function getLocation() {
  if (navigator.geolocation) {
    navigator.geolocation.getCurrentPosition();
  }
}
