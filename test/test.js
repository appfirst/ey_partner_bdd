/**
  * @author Yangming
 */

var fs     = require("fs")
  , url    = require("url")
  , util   = require("util")
  , qstr   = require("querystring")
  , http   = require("http")
  , crypto = require("crypto")
  , moment = require("moment")
  , should = require("should")
  , events = require("events")
  //, chai   = require("chai")
  //, expect = chai.expect;
  //, should = chai.should()
  ;

var EY_LISTEN_ADDR = "localhost"
  , EY_LISTEN_PORT = 8088
  , URL_PATTERN = /https?:\/\/([\w\-])+(\.([\w\-])+)*(:\d+)?.*/;

var Dispatcher = function() {};
Dispatcher.prototype = new events.EventEmitter();
var dispatcher = new Dispatcher();

// ---------- config ----------
var configPath = './ey_test.json';

config = eval('config = ' + fs.readFileSync(configPath));

var getAPIAuth = function(method, path, contentType, strData, date){
  var isoFormat = "yyyy-mm-dd hh:MM:ss o";
  var contentMD5 = crypto.createHash("md5").update(strData).digest('hex');
  var canonical_string = util.format("%s\n%s\n%s\n%s\n%s",
          method, contentType, contentMD5, moment(date).format(), path);
  return getHmac(config.auth_id, config.auth_key, canonical_string);
}

var getSSOUrl = function(dest_url){
  return getHmac(config.auth_id, config.auth_key, dest_url);
}

var getHmac = function(auth_id, auth_key, message){
  var signing = crypto.createHmac("sha1", auth_key)
                   .update(message)
                   .digest("base64");
  return util.format("AuthHMAC %s:%s", auth_id, signing);
}

var authRequest = function(request, postData){
  var method = request.method;
  var urlObj = url.parse(request.url),
      path = urlObj.path;
      auth = request.headers['authentication']||'',
      contentType = request.headers["content-type"],
      date = Date.parse(request.headers['Date']);
  console.log("[~] auth | %s", auth);
  var calc_auth = getAPIAuth(method, path, contentType, postData, date)
  if (auth = calc_auth){
    console.log("[/] - auth success!");
    return true;
  } else {
    console.log("[x] - auth failed!");
    return false;
  }  
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

var sendResponse = function(response, errcode, header, msg){
  response.writeHead(errcode, header);
  response.write(msg);
  response.end();
}

http.createServer(function (request, response) {
  var postData = "";
  request.setEncoding("utf8");
  request.addListener("data", function(postDataChunk) {
    postData += postDataChunk;
  });

  request.addListener("end", function() {
    var path = url.parse(request.url).path;
    if (path == config["service_registration_url"] && request.method == "POST"){
      dispatcher.emit("registration", request, response, postData);
      dispatcher.emit("account_msg", request, response, postData);
      dispatcher.emit("provisioned_service_msg", request, response, postData);
      dispatcher.emit("invoices", request, response, postData);
    }
  });
}).listen(EY_LISTEN_PORT, EY_LISTEN_ADDR);

describe('Engine Yard Add-on Test', function(){

  // * * * * * * * * * * * * * * * * * * * * * * * * * * *
  // *                                                   *
  // *          1) Partner Service Registration          *
  // *                                                   *
  // * * * * * * * * * * * * * * * * * * * * * * * * * * *

  // saved values
  var create_account_url = ""; //= config["registration"]["create_account_url"];
  var vars = [];

  describe('1) Partner Service Registration', function(){
    // ==========================================
    // ========== REGISTER PARTNERSHIP ==========
    // ==========================================
    describe("When register a partner service || POST to <service_registration_url>", function(){
      var jsonData = {};
      it("should send a request", function(done){
        // POST to the <service_registration_url> provided on partner sign-up
        dispatcher.once("registration", function(request, response, postData){
          jsonData = JSON.parse(postData);
          var headers = {"Content-Type" : "application/json", 
                         "Location"     : util.format("http://%s:%s/api/1/partners/48/services/1232", EY_LISTEN_ADDR, EY_LISTEN_PORT)};
          sendResponse(response, 201, headers, "Created");
          done();
        })

        sendRequest("PUT", config["test"]["register_service_url"], "", function(req, resp, postData){
        });
      });
      describe("HTTP Request", function(){
        it("should contain valid json post data", function(){
          jsonData.should.be.a("object");
          jsonData.should.have.keys("service");
          jsonData["service"].should.have.property("name").and.be.a('string');
          jsonData["service"].should.have.property("description").and.be.a('string');
          jsonData["service"].should.have.property("vars").and.be.an.instanceOf(Array);
          vars = jsonData["service"]["vars"];
          jsonData["service"].should.have.property("home_url").and.match(URL_PATTERN);
          if (jsonData["service"]["terms_and_conditions_url"] != null){
            jsonData["service"]["terms_and_conditions_url"].should.match(URL_PATTERN);
          }
          jsonData.service.should.have.property("service_accounts_url").and.match(URL_PATTERN);
          create_account_url = jsonData["service"]["service_accounts_url"];
        });
      })
    });
    // ========================================
    // ========== UPDATE PARTNERSHIP ==========
    // ========================================
    describe("When send a update request || PUT to <engineyard.url>", function(){
      var postData = JSON.stringify({
        "service": {
          "description":       "We post friendly messages to your dashboard daily.  Only $1/month."
        }
      });
      describe("HTTP Request", function(){
        it("should contain valid json post data", function(done){
          // signal for a request
          // TODO

          // receive a request
          // method should be "POST"
          // pathname should be blah blah
          postData = JSON.parse(postData);
          var service = postData.should.have.keys("service");
          // send back a response
          // TODO
          //  sendResponse(response, "201", {"Content-Type":"application/json"}, "Created");
          done();
        });
      })
    });
  })

//------------------------------------------------------------------------------------------------
  
  // * * * * * * * * * * * * * * * * * * * * * *
  // *                                         *
  // *          2) Service Enablement          *
  // *                                         *
  // * * * * * * * * * * * * * * * * * * * * * *

  // saved values
  var service_account_url = "";
  var configuration_required = false;
  var configuration_url = "";
  var provision_url = "";

  describe('2) Service Enablement for User Account', function(){
    // ====================================
    // ========== CREATE ACCOUNT ==========
    // ====================================
    describe("When create partner account || POST to <service.service_accounts_url>", function(){
      describe('HTTP Response', function(){
        var reqJson =  {
          "url":          util.format("http://%s:%s/api/1/partners/48/services/1232/service_accounts/333", EY_LISTEN_ADDR, EY_LISTEN_PORT),
          "name":         "appfirst",
          "messages_url": util.format("http://%s:%s/api/1/partners/48/services/1232/service_accounts/333/messages", EY_LISTEN_ADDR, EY_LISTEN_PORT),
          "invoices_url": util.format("http://%s:%s/api/1/partners/48/services/1232/service_accounts/333/invoices", EY_LISTEN_ADDR, EY_LISTEN_PORT),
        };
        var respJson = {};

        it('should response 200 OK if json post data is valid', function(done){
          sendRequest("POST", create_account_url, reqJson, function(req, resp, postData){
            resp.statusCode.should.equal(200);
            if (postData != ""){
              respJson = JSON.parse(postData);
            }
            done();
          });
        });

        describe('API Authentication', function(){
          it('should response 401 Authentication Failed if AuthHMAC is not matching', function(){
            // client.basicAuth('appfirst', 'Jm8Poyu3CbRts3ZH');
            // client.put('/appharbor/resources', data, function(err, req, res, obj){
              // console.log('res: %s' + util.inspect(res.statusCode));
            // });
            // TODO
          });
        });

        describe('JSON in response || <service_account, message>', function(){
          it('should have the valid structure', function(){
            respJson.should.have.property("service_account");

            respJson["service_account"].should.have.property("url").and.match(URL_PATTERN);
            service_account_url = respJson["service_account"]["url"];

            respJson["service_account"].should.have.property("configuration_required").and.be.a('boolean');
            configuration_required = respJson["service_account"]["configuration_required"];

            if (configuration_required){
              respJson["service_account"].should.have.property("configuration_url").and.match(URL_PATTERN);
              configuration_url = respJson["service_account"]["configuration_url"];
            }

            respJson["service_account"].should.have.property("provisioned_services_url").and.match(URL_PATTERN);
            provision_url = respJson["service_account"]["provisioned_services_url"];

            if (respJson["message"] != null){
              respJson["message"].should.be.a('object');
            }
          });

          describe("Account Configuration", function(){
            if (configuration_required){
              describe("When <configuration_required> is True || GET to <service_account.configuration_url>", function(){
                it('', function(){
                  configuration_url += getHmac();
                  sendRequest("GET", configuration_url, "", function(req, resp, postData){
                    resp.statusCode.should.equal(200);
                    resp.should.be.html;
                    done();
                  });
                  // TODO
                  /*
                    Service is not yet considered active (can’t be provisioned or billed)
                    User is redirected to configuration_url via SSO
                    When configuration is completed:
                    The partner should redirect the user (or provide a link) to ey_return_to_url
                    The partner should make an API call to Engine Yard to note that config is complete
                  */
                });
              })
            }
          });
        });
      });
    });

    describe("When cancel partner account || DELETE to <service_account.url>", function(){
      describe('HTTP Response', function(){
        it('should response 200 OK', function(done){
          sendRequest("DELETE", service_account_url, "", function(req, resp, postData){
            resp.statusCode.should.equal(200);
            done();
          });
        });
      });
    });
  });

//------------------------------------------------------------------------------------------------
  
  // * * * * * * * * * * * * * * * * * * * * * * *
  // *                                           *
  // *          3) Service Provisioning          *
  // *                                           *
  // * * * * * * * * * * * * * * * * * * * * * * *

  // saved values
  var deprovision_url = "";

  describe('3) Service Provisioning', function(){
    describe("When call provision API || POST to <service_account.provisioned_services_url>", function(){
      describe('HTTP Response', function(){
        var reqJson = {
          "url":          util.format("http://%s:%s/api/1/partners/8/services/1232/service_accounts/333/provisioned_services/32", EY_LISTEN_ADDR, EY_LISTEN_PORT),
          "messages_url": util.format("http://%s:%s/api/1/partners/8/services/1232/service_accounts/333/provisioned_services/32/messages", EY_LISTEN_ADDR, EY_LISTEN_PORT),
          "environment": {
            "name":          "foo_production",
            "framework_env": "production",
            "id":            "123"
          },
          "app":         {
            "name": "foo",
            "id":   "456"
          }
        };
        var respJson = {};
        it('should response 200 OK when receive valid json request', function(done){
          sendRequest("POST", provision_url, reqJson, function(req, resp, postData){
            resp.statusCode.should.equal(200);
            if (postData != ""){
              respJson = JSON.parse(postData);
            }
            done();
          });
        });

        describe('JSON in response || <provisioned_service, message>', function(){
          it('should have the same structure as defined', function(){
            respJson.should.have.property("provisioned_service");

            respJson["provisioned_service"].should.have.property("url").and.match(URL_PATTERN);
            deprovision_url = respJson["provisioned_service"]["url"];

            respJson["provisioned_service"].should.have.property("configuration_url").and.match(URL_PATTERN);
            configuration_url = respJson["provisioned_service"]["configuration_url"];

            respJson["provisioned_service"].should.have.property("vars").and.have.keys(vars);

            if (respJson["message"] != null){
              respJson["message"].should.be.a('object');
            }
          });
        });
      });
    });

    describe("When call de-provision API || DELETE to <provisioned_service.url>", function(){
      describe('HTTP Response', function(){
        it('should response 200 OK', function(){
          sendRequest("DELETE", deprovision_url, "", function(req, resp, postData){
            resp.statusCode.should.equal(200);
          });
        });
      });
    });

    describe("When Configuration on user instances", function(){
      it("should", function(){
        
      });
    });
  });

  describe("4) User FeedBack", function(){
    var jsonData = {};
    describe("When partner send service message || POST to <service_account.messages_url>", function(){
      it("should send a request", function(done){
        // POST to the <service_account.messages_url> create a service_account message
        dispatcher.once("account_msg", function(request, response, postData){
          // TODO for tenant
          jsonData = JSON.parse(postData);
          sendResponse(response, 201, {"Content-Type" : "application/json"}, "Created");
          done();
        })

        sendRequest("PUT", config["test"]["account_message_url"], "", function(req, resp, postData){
        });
      });
      it("should with json having the same structure as defined", function(){
        // TODO
      });
    });
    describe("When partner send provision message || POST to <provisioned_service.messages_url>", function(){
      it("should send a request", function(done){
        // POST to the <service_account.messages_url> create a service_account message
        dispatcher.once("provisioned_service_msg", function(request, response, postData){
          // TODO for tenant
          jsonData = JSON.parse(postData);
          sendResponse(response, 201, {"Content-Type" : "application/json"}, "Created");
          done();
        })

        sendRequest("PUT", config["test"]["provision_message_url"], "", function(req, resp, postData){
        });

      });
      it("should with json having the same structure as defined", function(){
        // TODO
      });
    });
  });

  describe("5) Billing", function(){
    var jsonData = {};
    describe("When partner send invoice || POST to <service_account.invoices_url>", function(){
      it("should send a request", function(done){
        // POST to the <service_account.messages_url> create a service_account message
        dispatcher.once("invoices", function(request, response, postData){
          // TODO for tenant
          jsonData = JSON.parse(postData);
          sendResponse(response, 201, {"Content-Type" : "application/json"}, "Created");
          done();
        })

        sendRequest("PUT", config["test"]["invoices_url"], "", function(req, resp, postData){
        });

      });
      it("should with json having the same structure as defined", function(){
        // TODO
        // engine yard returns 201 created
      });
    });
  });
});
