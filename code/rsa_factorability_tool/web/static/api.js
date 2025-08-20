// Wraps the API calls behind JavaScript functions

// get_key_resuable tells us if a key is factorizable
function get_key_reusable(key) {
  var f = function (data) {
    try {
      if (data.factorizable) {
        $("#result").html('<p><span style="font-weight: bold; color: red">Key is factorable!</span>');
      } else {
        $("#result").html('<p><span style="color: green">Key is NOT factorable!</span>');
      }
    } catch {
      return $("#result").html('Error during API reponse parsing.');
    }
  }
  query_endpoint_get("/rsa_cert?" + $.param({ find: key.val() }), f, "#result");
}

// adds an rsa key to the database
function add_rsa_key(key) {
  var f = function (data) {
    try {
      $("#result").html('<p><span style="font-weight: bold; color: green">' + data.information + '</span>');
    } catch {
      return $("#result").html('Error during API reponse parsing.');
    }
  }
  query_endpoint_post("/add_rsa_cert", {add : key.val()}, f, "#result");
}

// stats tells us basic database stats
function get_stats() {
  var f = function (data) {
    try {
      $("#nav-stats").html("Database contains<br><ul><li>... " + data.keys + " keys</li><li>... " + data.certificates + " certificates</li><li>... found in " + data.occurrences + " occurrences</li></ul>");
    } catch {
      $("#nav-stats").html("Error during API reponse parsing.");
    }
  }
  query_endpoint_get("/stats", f, "#nav-stats");
}

// I'm not a webdev, I'm sure there are cleaner solutions for this
function query_endpoint_get(api_endpoint, api_handler, field_name) {
  $.get(api_endpoint, function (api_response) {
    // inform about errors
    if (is_error(api_response)) {
      $(field_name).html(get_error(api_response));
    } else {
      // let handler handle our response
      api_handler(api_response.data);
    }
  }).fail(function () {
    $(field_name).html("404: API not reachable");
  })
}

// I'm not a webdev, I'm sure there are cleaner solutions for this
function query_endpoint_post(api_endpoint, post_params, api_handler, field_name) {
  $.post(api_endpoint, post_params, function (api_response) {
    // inform about errors
    if (is_error(api_response)) {
      $(field_name).html(get_error(api_response));
    } else {
      // let handler handle our response
      api_handler(api_response.data);
    }
  }).fail(function () {
    $(field_name).html("404: API not reachable");
  })
}

function is_error(api_response) {
  try {
    code = api_response.status
    if (code == '200') {
      return false;
    } else {
      return true;
    }
  } catch {
    return true;
  }
}

function get_error(api_response) {
  try {
    return api_response.status + ": " + api_response.description;
  } catch {
    return "Could not read error from API.";
  }
}
