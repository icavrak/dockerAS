from flask import Flask
from flask import request
from flask import make_response

import requests
import re

import json
import os 

#
# application-specific modules
#
import log
import utils
import auth
import tokens

#
# DEBUG MODE ON/OFF
#
utils.setDebugMode(True)
log.setLogLevel(log.LOG_DEBUG)

#
#
# CONSTANTS 
#
#
SELF_NAME = "dockerAS"

USERNAME = "$"
USERNAME_REGEX = "[A-Za-z0-9_]+"




#
#
# DEFAULT VALUES FOR ENVIRONMENT VARIABLES
#
#


AUTHORIZATION_ISSUER_DEFAULT = "dockertest.fairuse.org"
AUTHORIZATION_PERIOD_DEFAULT = 300

GK_SECURITY_CERT_PATH_DEFAULT = "/var/dauth/auth/cert.crt"
GK_SECURITY_PKEY_PATH_DEFAULT = "/var/dauth/auth/pkey.key"

AUTHENTICATION_HTPASSWD_PATH_DEFAULT = "/var/dauth/auth/htpasswd"
AUTHENTICATION_EXTERNAL_URI_DEFAULT =  ""

AUTHORIZATION_ACL_PATH_DEFAULT = "/var/dauth/auth/acl.json" 

DOCKER_REGISTRY_URI_DEFAULT = "https://127.0.0.1"

#get filename for htpasswd-based authentication 
auth_htpasswd_path = os.getenv("GK_AUTHENTICATION_HTPASSWD_PATH", AUTHENTICATION_HTPASSWD_PATH_DEFAULT)
auth.loadHTPASSWDData(auth_htpasswd_path)

#set the URL of the external authentication service, if defined
print "==> EXTERNAL AUTH URL: " + os.getenv("GK_AUTHENTICATION_EXTERNAL_URI")
auth_ext_uri = os.getenv("GK_AUTHENTICATION_EXTERNAL_URI", AUTHENTICATION_EXTERNAL_URI_DEFAULT)
auth.setExternalServiceURL(auth_ext_uri)


#load Access Control List 
auth_acl_path = os.getenv("GK_AUTHORIZATION_ACL_PATH", AUTHORIZATION_ACL_PATH_DEFAULT)
auth.loadACLData(auth_acl_path)

#load security data
sec_cert_path = os.getenv("GK_SECURITY_CERT_PATH", GK_SECURITY_CERT_PATH_DEFAULT)
cert_data = auth.loadCertData(sec_cert_path)

sec_pkey_path = os.getenv("GK_SECURITY_PKEY_PATH", GK_SECURITY_PKEY_PATH_DEFAULT)
pkey_data = auth.loadPKeyData(sec_pkey_path)

#create security objects (extract keys...)
auth.extractSecObjects(cert_data, pkey_data)

#set the URL of the docker registry to retrieve the catalog from
docker_uri = os.getenv("GK_DOCKER_REGISTRY_URI", DOCKER_REGISTRY_URI_DEFAULT)

#
# Utility functions
#
#

def getRequestArgument(request, argumentName):
  return request.values[argumentName]

def getRequestHeader(request, headerName):
    return request.headers[headerName]

def validateUser(request, restrictLocal=False, allowAnonymous=True):

  #extract authentication data from request
  access_authType, access_userCredentials = auth.getRequestAuthenticationData(request)
  if access_authType == None:
    return False 

  #extract username and password from provided basic credentials
  username, password = auth.getAccessCredentialsData(access_authType, access_userCredentials)
  if username == None:
    return False 

  #check for username:password validity
  if auth.authenticateUser(username, password, restrictLocal, allowAnonymous) == False:
    log.log(log.LOG_WARNING, "User authorization failed for user " + username)
    return False

  return True 


def getImageCreationTime(json_metadata):

  #iterate over v1Compatibility nodes and collect "created" timestamps
  timestamps = list()

  try:
    data = json_metadata["history"]
    for c in data:
      d = c["v1Compatibility"]
      dd = re.search("created\":\"([0-9-T:.]+Z)", d)
      if dd != None:
        timestamps.append(dd.group(1))

    #sort timestamps 
    timestamps.sort()

    #return the last element (highest date)
    return timestamps[-1]
  except KeyError:
    return ""



#
#
# Access points
#
#



app = Flask(__name__)

@app.route("/docker/token", methods=["GET", "POST", "PUT"])
def notification_sink():

  #create a response object
  response = make_response("")

  #allow CORS
  response.headers = {'Access-Control-Allow-Origin': '*'}

  #dump request data (if in debug mode)
  utils.dumpRequestData(request, preamble="token request")

  #
  #
  # USER AUTHENTICATION AND REQUEST CONSISTENCY 
  #
  #

  #extract authentication data from request
  access_authType, access_userCredentials = auth.getRequestAuthenticationData(request)
  if access_authType == None:
    return response, 401

  #check for existance of service argument (mandatory)
  try:
    service = getRequestArgument(request, "service") 
  except KeyError:
    log.log(log.LOG_DEBUG, "Service request parameter not found")
    return response, 400

  #check for existance of scope argument (optional!) 
  scope = ""
  try:
    scope = getRequestArgument(request, "scope")
  except KeyError:
    pass

  utils.debug("==>SERVICE & SCOPE: " + str(service) + "," + str(scope))

  #extract username and password from provided basic credentials
  username, password = auth.getAccessCredentialsData(access_authType, access_userCredentials)
  if username == None:
    return response, 401 

  #check match between username in Authorization header and
  #account field in GET arguments (if not anonymous access)
  try:
    if access_authType != auth.ANONYMOUS_AUTHORIZATION_TYPE:
      if username != getRequestArgument(request, "account"):
        log.log(log.LOG_DEBUG, "Basic authorization user does not match account parameter; Basic header=" + username + ", account=" + str(getRequestArgument(request, "account")))
        return response, 401
  except KeyError:
    log.log(log.LOG_DEBUG, "No account parameter specified in the request") 
    return response, 401

  #check for username:password validity
  if auth.authenticateUser(username, password) == False:
    log.log(log.LOG_WARNING, "User authorization failed for user " + username) 
    return response, 401
  


  #
  #
  #  CONSTRUCTING A RESPONSE
  #
  #


  #construct a response content holder
  resp_content = {}

  #add expires_in data
  resp_content["expires_in"] = tokens.getTokenExpiration(username, service, scope)

  #add issued_at data
  resp_content["issued_at"] = tokens.getIssuedTime()

  #if requested, add refresh token
  try:
    if getRequestArgument(request, "offline_token") == "true":
      #WARNING: docker fails to work if a refresh token is present in the response!!!
      #resp_content["refresh_token"] = getRefreshToken(access_userCredentials[0], service, scope)
      pass
  except KeyError: 
    pass


  #if "grant_type" argument is specified with the value "refresh_token", check for refresh token in the
  #refresh token registry
  ref_token_user = None
  try:
    if getRequestArgument(request, "grant_type") == "refresh_token":
      try:
        ref_token = getRequestArgument(request, "refresh_token") 
        ref_token_user = getUserFromRefreshToken(ref_token, checkTokenValidity=False) 
        if checkRefreshToken(ref_token, service=getRequestArgument(request, "service")) == False:
          log.log(log.LOG_DEBUG, "Refresh token not valid for user " + str(ref_token_user) )
          return response, 401
      except KeyError:
        log.log(log.LOG_DEBUG, "Refresh token not found in the refresh token registy")
        return response, 401 

  except KeyError:  #no grant_type found
    pass

  #try to find out user's name 
  client = username   #TODO: check if this is true in all cases (anonymous access should pass "")
  if client == auth.ANONYMOUS_USER_NAME:
    client = ""
  if ref_token_user != None:
    client = ref_token_user
  
  #issuer field, as in AUTHORIZATION_ISSUER environment variable 
  auth_issuer = os.getenv("GK_AUTHORIZATION_ISSUER", AUTHORIZATION_ISSUER_DEFAULT)

  #bearer token validity period 
  auth_period = os.getenv("GK_AUTHORIZATION_PERIOD", AUTHORIZATION_PERIOD_DEFAULT)
 
  #add bearer token
  resp_content["token"] = tokens.getBearerToken(client, service, scope, client, auth_issuer, auth_period)
 
  utils.debug("==>CONTENT: " + str(resp_content))
  
  #response content to JSON format
  resp_content = json.dumps(resp_content)

  response.mimetype = "application/json"
  response.set_data(resp_content)

  return response


@app.route("/authenticate", methods=["GET"])
def authenticate():

  #create a response object
  response = make_response("")
 
  #allow CORS
  response.headers = {'Access-Control-Allow-Origin': '*'}

  #dump request data (if in debug mode)
  utils.dumpRequestData(request, preamble="Authentication request")

  #validate user
  if validateUser(request) == False:
    return response, 401

  return response


@app.route("/acl", methods=["GET"])
def getACL():

  #create a response object
  response = make_response("")

  #allow CORS
  response.headers = {'Access-Control-Allow-Origin': '*'}

  #dump request data (if in debug mode)
  utils.dumpRequestData(request, preamble="ACL get")

  #validate user
  if validateUser(request) == False:
    return response, 401

  #return acl in json form
  response.mimetype = "application/json"
  response.set_data(auth.getJSONACLData())

  return response, 200


@app.route("/acl", methods=["PUT"])
def putACL():

  #create a response object
  response = make_response("")

  #allow CORS
  response.headers = {'Access-Control-Allow-Origin': '*'}

  #dump request data (if in debug mode)
  utils.dumpRequestData(request, preamble="ACL put")

  #validate user
  if validateUser(request) == False:
    return response, 401

  #get new ACL list
  print "==> " + str(request.data)
  json_content = request.get_json(silent=True)
  if json_content == None:
    print "==> JSON CONTENT ERROR" 
    return response, 400

  #if auth.putJSONACLData(json_content) == False:
  if auth.putJSONACLData(request.data) == False:
    print "==> JSON ACL ERROR"
    return response, 400

  return response, 200


@app.route("/catalog", methods=["GET"])
def catalog():


  #create a response object
  response = make_response("")

  #allow CORS
  response.headers = {'Access-Control-Allow-Origin': '*'}

  #get filter data (if exists)
  try: 
    filter = None
    filter = request.args["filter"]
    
    #expand the fiter (if defined) to a usable regex
    filter = filter.replace(USERNAME, USERNAME_REGEX)
  except KeyError:
    pass

  utils.debug("==>CATALOG REQUEST : " + str(filter))

  #extract username and password from provided basic credentials
  #username, password = auth.getAccessCredentialsData(access_authType, access_userCredentials)
  #if username == None:
  #  return response, 401 

  #check for username:password validity
  #if auth.authenticateUser(username, password) == False:
  #  log.log(log.LOG_WARNING, "User authorization failed for user " + username) 
  #  return response, 401

  #issuer field, as in AUTHORIZATION_ISSUER environment variable 
  auth_issuer = os.getenv("GK_AUTHORIZATION_ISSUER", AUTHORIZATION_ISSUER_DEFAULT)

  #bearer token validity period 
  auth_period = os.getenv("GK_AUTHORIZATION_PERIOD", AUTHORIZATION_PERIOD_DEFAULT)

  #quick and dirty solution, does not require 2 calls to docker registry
  service = "registry.docker.io"
  scope =  "registry:catalog:*"

  #get a JWT authorization (bearer token) from itself
  bearer = tokens.getBearerToken(SELF_NAME, service, scope, SELF_NAME, auth_issuer, auth_period)


  #create a request towards the Docker repository
  headers = dict()
  headers = {"Authorization": "Bearer " + bearer}

  #add path for /v2/_catalog
  docker_catalog_uri = docker_uri + "/v2/_catalog"

  #send the request to docker registry
  r = requests.get(docker_catalog_uri, headers=headers)

  utils.debug("==>ReGISTRY CATALOG REQUEST STATUS: " + str(docker_catalog_uri) + " :: " + str(r.status_code))

  #if the call has failed, log it and forward the error code to caller
  if r.status_code != requests.codes.ok:
    log.log(log.LOG_WARNING, "Fetching Docker registry catalog at " + docker_catalog_uri + " failed with code:" + r.status_code)
    return response, r.status_code

  utils.debug("==>CATALOG CONTENT: " + r.text)

  #repository set to be returned to the caller
  repo_list = dict()

  #get the result (returned in JSON format) as an array
  try:
    repo_array = r.json()["repositories"]
    
    #if it matches a supplied filter, add it to repo_list
    if filter != None:

      #iterate over each repo array item
      for repo in repo_array:

        res = re.search(filter, repo)
        if res == None or res.group(0) != repo:
          continue

        repo_list[repo] = ""

  except KeyError:
    #malformed result JSON - no root "repositories" object
    #return an empty repository list
    return response


  #for each image in the resulting list - get metadata from
  #the repository
  for image in repo_list:

    #construct scope parameter (avoiding 1st GET to registry with 401 result)
    scope="repository:" + image + ":pull"

    #get a JWT authorization (bearer token) from itself
    bearer = tokens.getBearerToken(SELF_NAME, service, scope, SELF_NAME, auth_issuer, auth_period)

    #create a request towards the Docker repository
    headers = {"Authorization": "Bearer " + bearer}

    #add path for /v2/...image...
    tag = "latest"
    docker_image_metadata_uri = docker_uri + "/v2/" + image + "/manifests/" + tag

    #send a request to docker registry
    r = requests.get(docker_image_metadata_uri, headers=headers)
    r_json = r.json()

    #utils.debug("==> METADATA for " + image + ": " + r.text)

    #get the image's timestamp
    timestamp = getImageCreationTime(r_json)

    #add it as a property
    t = dict()
    t["timestamp"] = timestamp

    #add properties to the image record
    repo_list[image] = t 

  utils.debug("==>ReGISTRY CATALOG REQUEST STATUS: " + str(docker_catalog_uri) + " :: " + str(r.status_code))


  #set response content type
  response.mimetype = "application/json"

  #allow CORS
  response.headers = {'Access-Control-Allow-Origin': '*'}

  #create resulting json
  response.data = json.dumps(repo_list) 

  return response



@app.route("/auth2", methods=["GET"])
def auth2():

  #TODO test - remove later
  #create a response object

  response = make_response("")

  #allow CORS
  response.headers = {'Access-Control-Allow-Origin': '*'}

  r = requests.get("http://dockertest.fairuse.org:5001/authenticate", auth=('iki', 'iki'))

  print r.content

  return r.content
