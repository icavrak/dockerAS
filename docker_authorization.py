from flask import Flask
from flask import request
from flask import make_response
import requests


import json
import os 

#
#application-specific modules
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
# DEFAULT VALUES FOR ENVIRONMENT VARIABLES
#
#


AUTHORIZATION_ISSUER_DEFAULT = "dockertest.fairuse.org"
AUTHORIZATION_PERIOD_DEFAULT = 300

GK_SECURITY_CERT_PATH_DEFAULT = "/var/dauth/auth/cert.crt"
GK_SECURITY_PKEY_PATH_DEFAULT = "/var/dauth/auth/pkey.key"

AUTHENTICATION_HTPASSWD_PATH_DEFAULT = "/var/dauth/auth/htpasswd"
AUTHENTICATION_EXTERNAL_URL_DEFAULT =  ""

AUTHORIZATION_ACL_PATH_DEFAULT = "/var/dauth/auth/acl.json" 


#get filename for htpasswd-based authentication 
auth_htpasswd_path = os.getenv("GK_AUTHENTICATION_HTPASSWD_PATH", AUTHENTICATION_HTPASSWD_PATH_DEFAULT)
auth.loadHTPASSWDData(auth_htpasswd_path)

#set the URL of the external authentication service, if defined
auth_ext_url = os.getenv("GK_AUTHENTICATION_EXTERNAL_URL", AUTHENTICATION_EXTERNAL_URL_DEFAULT)
auth.setExternalServiceURL(auth_ext_url)


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


#
# Utility functions
#
#

def getRequestArgument(request, argumentName):
  return request.values[argumentName]

def getRequestHeader(request, headerName):
    return request.headers[headerName]


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

  #dump request data (if in debug mode)
  utils.dumpRequestData(request, preamble="token request")

  #
  #
  # USER AUTHENTICATION AND REQUEST CONSISTENCY 
  #
  #

  #extrach authentication data from request
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
      #WARNING: docker fails to work if refresh token is present in the response!!!
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
 
  #dump request data (if in debug mode)
  utils.dumpRequestData(request, preamble="token request")

  #extract authentication data from request
  access_authType, access_userCredentials = auth.getRequestAuthenticationData(request)
  if access_authType == None:
    return response, 401

  #extract username and password from provided basic credentials
  username, password = auth.getAccessCredentialsData(access_authType, access_userCredentials)
  if username == None:
    return response, 401

  #check for username:password validity
  if auth.authenticateUser(username, password) == False:
    log.log(log.LOG_WARNING, "User authorization failed for user " + access_userCredentials[0])
    return response, 401

  return response


@app.route("/auth2", methods=["GET"])
def auth2():

  #create a response object
  response = make_response("")

  r = requests.get("http://dockertest.fairuse.org:5001/authenticate", auth=('iki', 'iki'))

  print r.content

  return r.content
