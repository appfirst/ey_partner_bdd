var http   = require('http'),
    url    = require('url'),
    fs     = require('fs'),
    qstr   = require('querystring'),
    crypto = require('crypto'),
    util   = require('util'),
    moment = require('moment');

var DASHBOARD_PATH = "/dashboard",
    BASE_PATH      = "/appharbor/resources",
    SSO_PATH       = "/appharbor/sso",
    EY_ACC_PATH    = "/ey/resources",
    EY_CFG_PATH    = "/ey/sso",
    EY_PVS_PATH    = "/ey/provision",
    SSO_SALT       = "JjEqmttYOKcbbeJy",
    CREDENTIAL     = "appfirst:Jm8Poyu3CbRts3ZH",
    EY_AUTH_ID     = "68c2104b53521752",
    EY_AUTH_KEY    = "fde420642d8c1a83940d71ae651388946a94818df49991d0341d83dd273626ae0cf52d2ea9938ff1",
    LISTEN_ADDR    = "localhost",
    LISTEN_PORT    = 8080,
    EXPIRE_TIME    = 2 * 60;

var ey_registration_url = "http://localhost:8088/api/1/partners/48/services";


var service_url,
    service_account_url,
    service_account_messages_url,
    service_account_invoices_url,
    provisioned_service_url,
    provisioned_service_messages_url;

var RED     = '\033[31m',
    GREEN   = '\033[32m',
    YELLOW  = '\033[33m',
    BLUE    = '\033[34m',
    MAGENTA = '\033[35m',
    CYAN    = '\033[36m',
    RESET   = '\033[0m';

var indexhtml = fs.readFileSync('./index.html');

var sendResponse = function(response, errcode, header, msg){
  if (header["Content-Type"] == "text/html"){
    console.log("%s<= response%s %s, %s, %s", MAGENTA, RESET, errcode, JSON.stringify(header), "[HTML Content]");
  } else {
    console.log("%s<= response%s %s, %s, %s", MAGENTA, RESET, errcode, JSON.stringify(header), msg);
  }
  response.writeHead(errcode, header);
  response.write(msg);
  response.end();
}

var sendRequest = function(method, dest_url, jsonData, handleResponse){
  var parsed_url = url.parse(dest_url)
  var contentType = "application/json";
  var strData = JSON.stringify(jsonData);
  var now = new Date();

  var hmac = getAPIAuth(method, parsed_url.path, contentType, strData, now);
  var headers = {
    "Content-Type":   "application/json",
    "Accept":         "application/json",
    "Date":           now,
    "User-agenet":    "EY-ServiceAPI/0.0.1",
    "Host":           "services.engineyard.com",
    "Authentication": hmac
  };

  var options = {
    host: parsed_url.hostname,
    port: parseInt(parsed_url.port),
    path: parsed_url.path,
    method: method,
    headers: headers
  };
  var request = http.request(options, function(response){
    var postData = "";
    response.on("data", function(postDataChunk){
      postData += postDataChunk;
    });
    response.on("end", function(){
      handleResponse(request, response, postData);
    });
  })

  request.write(strData);
  request.end();
}

var authenticate = function(request){
  console.log("%s[~]%s headers%s | %s", BLUE, CYAN, RESET, request.headers);
  var header=request.headers['authorization']||'',    // get the header
      token=header.split(/\s+/).pop()||'',            // and the encoded auth token
      auth=new Buffer(token, 'base64').toString();    // convert from base64
  console.log("%s[~]%s auth%s | %s", BLUE, CYAN, RESET, auth);
  if (auth==CREDENTIAL){
    console.log("%s[/]%s - auth success!", GREEN, RESET);
    return true;
  } else {
    console.log("%s[x]%s - auth failed!", RED, RESET);
    return false;
  }
}

var sso = function(request, data){
  var seed = data.id + ':' + SSO_SALT + ':' + data.timestamp;
  var shasum = crypto.createHash('sha1');
  shasum.update(seed);
  var token = shasum.digest('hex');
  var nowts = Math.floor(new Date().getTime() / 1000);
  var ts = parseInt(data.timestamp);
  if (token!=data.token) {
    console.log("%s[x]%s - invalid sso token", RED, RESET);
    return 403;
  } else if (nowts-ts > EXPIRE_TIME) {
    console.log("%s[x]%s - request expired", RED, RESET);
    return 403;
  } else if (false) { // tenant not found
    return 404;
  } else {
    console.log("%s[/]%s - sso success", GREEN, RESET);
    return 302;
  }
}

var provision = function(response, pathname, data) {
  console.log("%s[/]%s - provision a tenant", GREEN, RESET);
  var tenant_id = Math.floor(Math.random() * 1000),
      jsonmsg = { id:tenant_id, config:{"APPFIRST_URL":"http://dev.appfirst.com/?tenant=" + tenant_id} };
  sendResponse(response, 200, {'Content-Type': 'text/json'}, JSON.stringify(jsonmsg));
}

var changePlan = function(response, pathname, data) {
  var paths = pathname.split("/");
  var tenant_id = paths[paths.length-1];
  console.log("%s[/]%s - change plan of tenant %s to plan %s", GREEN, RESET, tenant_id, data.plan);
  var jsonmsg = { config:{"APPFIRST_URL":"http://dev.appfirst.com/?tenant=" + tenant_id},
                  message:"welcome to plan " + data.plan };
  sendResponse(response, 200, {'Content-Type': 'text/json'}, JSON.stringify(jsonmsg));
}

var deprovision = function(response, pathname, data) {
  var tenant_id = pathname.substring(pathname.lastIndexOf("/")+1, pathname.length);
  console.log("%s[/]%s - deprovision tenant %s", GREEN, RESET, tenant_id);
  sendResponse(response, 200, {'Content-Type': 'text/plain'}, "ok");
}

var getAPIAuth = function(method, path, contentType, strData, date){
  var isoFormat = "yyyy-mm-dd hh:MM:ss o";
  var contentMD5 = crypto.createHash("md5").update(strData).digest('hex');
  var canonical_string = util.format("%s\n%s\n%s\n%s\n%s",
          method, contentType, contentMD5, moment(date).format(), path);
  return getHmac(EY_AUTH_ID, EY_AUTH_KEY, canonical_string);
}

var getSSOUrl = function(dest_url){
  return getHmac(EY_AUTH_ID, EY_AUTH_KEY, dest_url);
}

var getHmac = function(auth_id, auth_key, message){
  var signing = crypto.createHmac("sha1", auth_key)
                   .update(message)
                   .digest("base64");
  return util.format("AuthHMAC %s:%s", auth_id, signing);
}

var ey_authenticate = function(request, postData){
  var method = request.method;
  var urlObj = url.parse(request.url),
      path = urlObj.path,
      auth = request.headers['authentication']||'',
      contentType = request.headers["content-type"],
      date = Date.parse(request.headers['Date']);
  console.log("%s[~]%s auth%s | %s", BLUE, CYAN, RESET, auth);
  var calc_auth = getAPIAuth(method, path, contentType, postData, date)
  if (auth = calc_auth){
    console.log("%s[/]%s - auth success!", GREEN, RESET);
    return true;
  } else {
    console.log("%s[x]%s - auth failed!", RED, RESET);
    return false;
  }  
}

var ey_sso = function(request, postData) {
  var method   = request.method;
  var urlObj   = url.parse(request.url),
      path     = urlObj.path,
      query    = qstr.parse(urlObj.query)
      org_url  = request.url.substring(0, request.url.indexOf("&signature="))
      token    = getSSOUrl(org_url);
  if (token!=query["signature"]) {
    console.log("%s[x]%s - invalid sso token", RED, RESET);
    return 403;
  } else if (false) { // tenant not found
    return 404;
  } else {
    console.log("%s[/]%s - sso success", GREEN, RESET);
    return 302;
  }
}

var ey_register_partner = function(response, pathname, data){
  sendResponse(response, 200, {}, "Will send Registration request");
  var reqJson = {
    "service": {
      "name":                      "AppFirst",
      "description":               "We post friendly messages to your dashboard daily.  Sign-up is free!",
      "vars":     [
        "api_key", 
        "daily_supplement_path"
      ],
      "home_url"                : util.format("http://%s:%s",   LISTEN_ADDR, LISTEN_PORT),
      "terms_and_conditions_url": util.format("http://%s:%s%s", LISTEN_ADDR, LISTEN_PORT, "/terms"),
      "service_accounts_url"    : util.format("http://%s:%s%s", LISTEN_ADDR, LISTEN_PORT, EY_ACC_PATH),
    }
  };
  sendRequest("POST", ey_registration_url, reqJson, function (request, response, postData){
    console.log("%s[/]%s - service registered", GREEN, RESET);
  });
}

var ey_create_account = function(response, pathname, data) {
  var tenant_id = Math.floor(Math.random() * 1000);
  var respJson = {
    "service_account": {
      "url"                     : util.format("http://%s:%s%s/4331", LISTEN_ADDR, LISTEN_PORT, EY_ACC_PATH),
      "configuration_required"  : true,
      "configuration_url"       : util.format("http://%s:%s%s/4331", LISTEN_ADDR, LISTEN_PORT, EY_CFG_PATH),
      "provisioned_services_url": util.format("http://%s:%s%s/4331", LISTEN_ADDR, LISTEN_PORT, EY_PVS_PATH),
    },"message":                  {}
  };
  console.log("%s[/]%s - create a tenant", GREEN, RESET);
  sendResponse(response, 200, {'Content-Type': 'application/json'}, JSON.stringify(respJson));
}

var ey_cancel_account = function(response, pathname, data) {
  var tenant_id = pathname.substring(pathname.lastIndexOf("/")+1, pathname.length);
  console.log("%s[/]%s - delete tenant %s", GREEN, RESET, tenant_id);
  sendResponse(response, 200, {'Content-Type': 'application/json'}, "OK");
}

var ey_provision = function(response, pathname, data) {
  console.log("%s[/]%s - provision a tenant", GREEN, RESET);
  var tenant_id = Math.floor(Math.random() * 1000),
      respJson = {
    "provisioned_service": {
      "url"                     : util.format("http://%s:%s%s/%s/23", LISTEN_ADDR, LISTEN_PORT, EY_PVS_PATH, tenant_id),
      "configuration_url"       : util.format("http://%s:%s%s/%s/23", LISTEN_ADDR, LISTEN_PORT, EY_PVS_PATH, tenant_id),
      "vars": {
        "api_key"               : "987698AFB0987EFBB983",
        "daily_supplement_path" : "/etc/"
      }
    },
    "message"                   : {}
  }
  sendResponse(response, 200, {'Content-Type': 'application/json'}, JSON.stringify(respJson));
}

var ey_deprovision = function(response, pathname, data) {
  var tenant_id = pathname.substring(pathname.lastIndexOf("/")+1, pathname.length);
  console.log("%s[/]%s - deprovision tenant %s", GREEN, RESET, tenant_id);
  sendResponse(response, 200, {'Content-Type': 'application/json'}, "OK");
}

var ey_account_msg = function(response, pathname, data){
  sendResponse(response, 200, {}, "Will send Registration request");
  var reqJson = {
    "message": {
      "message_type": "notification",
      "subject":      "That's a nice looking app deployment you've got there",
      "body":         "And a db_slave, spiffy!",
                      // Optional, will show as collapsed until user clicks 'read more'
    }
  };
  sendRequest("POST", ey_registration_url, reqJson, function (request, response, postData){
    console.log("%s[/]%s - account msg sent", GREEN, RESET);
  });
}

var ey_provisioned_service_msg = function(response, pathname, data){
  sendResponse(response, 200, {}, "Will send Registration request");
  var reqJson = {
    "message": {
      "message_type": "notification",
      "subject":      "That's a nice looking app deployment you've got there",
      "body":         "And a db_slave, spiffy!",
                      // Optional, will show as collapsed until user clicks 'read more'
    }
  }
  sendRequest("POST", ey_registration_url, reqJson, function (request, response, postData){
    console.log("%s[/]%s - provisioned service msg sent", GREEN, RESET);
  });
}

var ey_billing = function(response, pathname, data){
  sendResponse(response, 200, {}, "Will send Registration request");
  var reqJson = {
    "invoice":
    {
      "total_amount_cents":     "3050", //USD amount in cents ($30.50)
      "line_item_description":  "Invoice ID: 122. For service from Jan 1 to Feb 1 of 2012, rendered in a complimentary fashion.",
    }
}
  sendRequest("POST", ey_registration_url, reqJson, function (request, response, postData){
    console.log("%s[/]%s - invoices sent", GREEN, RESET);
  });
}

function isEmpty(map) {
  for (var name in map) {
    if (map.hasOwnProperty(name)) {
      return false;
    }
  }
  return true;
}

var logRequest = function(request, postData){
  var method = request.method;
  var urlObj = url.parse(request.url),
      pathname = urlObj.pathname,
      query = qstr.parse(urlObj.query);
  console.log("%s[~]%s meth%s | %s", BLUE, CYAN, RESET, method);
  console.log("%s[~]%s path%s | %s", BLUE, CYAN, RESET, pathname);
  if (!isEmpty(request.headers)){
    console.log("%s[~]%s head%s | %s", BLUE, CYAN, RESET, JSON.stringify(request.headers));
  }
  if (!isEmpty(query)){
    console.log("%s[~]%s qstr%s | %s", BLUE, CYAN, RESET, JSON.stringify(query));
  }
  if (typeof postData == "object" && !isEmpty(postData)) {
    console.log("%s[~]%s data%s | %s", BLUE, CYAN, RESET, JSON.stringify(postData));
  } else if (typeof postData == "string" && postData.length == 0) {
    console.log("%s[~]%s data%s | %s", BLUE, CYAN, RESET, postData);
  }
}

var handleRequest = function(request, response, postData){
  var pathname = url.parse(request.url).pathname;
  var method = request.method;
  if (pathname.search(BASE_PATH) >= 0 && pathname.search(SSO_PATH) == -1){
    if (authenticate(request)) {
      logRequest(request, postData);
      if (method == "DELETE"){
        deprovision(response, pathname, postData);
      } else if (method == "PUT") {
        changePlan(response, pathname, postData);
      } else {
        provision(response, pathname, postData);
      }
    } else {
      sendResponse(response, 401, {'Content-Type': 'text/plain'}, "Authentication Failed");
    }
  } else if (pathname == SSO_PATH && method == "POST"){
    postData = qstr.parse(postData);
    var errcode = sso(request, postData);
    if (errcode == 302) {
      logRequest(request, postData);
      response.setHeader("Set-Cookie", ["heroku-nav-data="+postData['nav-data']]);
      console.log("%s[/]%s - set cookie heroku-nav-data=%s", GREEN, RESET, postData['nav-data']);
      sendResponse(response, 302, {"Location": "/dashboard"}, "Single Sign-On Success");
    } else if (errcode == 404) {
      sendResponse(response, 404, {'Content-Type': 'text/plain'}, "User Not Found");
    } else {
      sendResponse(response, 403, {'Content-Type': 'text/plain'}, "Access Denied");
    }
  } else if (pathname == DASHBOARD_PATH && method == "GET") {
    logRequest(request, postData);
    sendResponse(response, 200, {'Content-Type': 'text/html'}, indexhtml);
  } else if (pathname.search(EY_ACC_PATH) >= 0){
    if (ey_authenticate(request, postData)){
      logRequest(request, postData);
      if (method == "DELETE"){
        ey_cancel_account(response, pathname, postData);
      } else if (pathname == EY_ACC_PATH && method == "POST"){
        ey_create_account(response, pathname, postData);
      } else {
        sendResponse(response, 404, {'Content-Type': 'text/plain'}, "Page Not Found");
      }
    } else {
      sendResponse(response, 401, {'Content-Type': 'text/plain'}, "Authentication Failed");
    }
  } else if (pathname.search(EY_PVS_PATH) >= 0) {
    if (ey_authenticate(request, postData)){
      logRequest(request, postData);
      if (method == "POST"){
        ey_provision(response, pathname, postData);
      } else if (method == "DELETE"){
        ey_deprovision(response, pathname, postData);
      } else {
        sendResponse(response, 404, {'Content-Type': 'text/plain'}, "Page Not Found");
      }
    } else {
      sendResponse(response, 401, {'Content-Type': 'text/plain'}, "Authentication Failed");
    }
  } else if (pathname.search(EY_CFG_PATH) >= 0){
    var errcode = ey_sso(request, postData);
    if (errcode == 302) {
      logRequest(request, postData);
      sendResponse(response, 302, {'Location': '/dashboard'}, "Single Sign-On Success");
    } else if (errcode == 404) {
      sendResponse(response, 404, {'Content-Type': 'text/plain'}, "User Not Found");
    } else {
      sendResponse(response, 403, {'Content-Type': 'text/plain'}, "Access Denied");
    }    
  } else if (pathname.search("/ey/test/registration") >= 0 && method == "PUT") {
    ey_register_partner(response, pathname, postData);
  } else if (pathname.search("/ey/test/account_message") >= 0 && method == "PUT") {
    ey_register_partner(response, pathname, postData);
  } else if (pathname.search("/ey/test/provision_message") >= 0 && method == "PUT") {
    ey_register_partner(response, pathname, postData);
  } else if (pathname.search("/ey/test/invoices") >= 0 && method == "PUT") {
    ey_billing(response, pathname, postData);
  } else {
    logRequest(request, postData);
    sendResponse(response, 404, {'Content-Type': 'text/plain'}, "Page Not Found");
  }
}

http.createServer(function (request, response) {
  var postData = "";
  console.log("\n%s=> request%s from %s", MAGENTA, RESET, request.connection.remoteAddress);
  request.setEncoding("utf8");
  request.addListener("data", function(postDataChunk) {
    postData += postDataChunk;
  });

  request.addListener("end", function() {
    handleRequest(request, response, postData);
  });

  request.addListener("error", function(err) {
    console.log("\n%sERROR%s socket hanging up from %s", RED, RESET, request.connection.remoteAddress);
  });
}).listen(LISTEN_PORT, LISTEN_ADDR);

console.log('Server running at http://%s:%s/', LISTEN_ADDR, LISTEN_PORT);
