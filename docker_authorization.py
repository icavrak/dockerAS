from flask import Flask
from flask import request
from flask import make_response
import json
import os 
import base64
import datetime
import calendar
import random

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

import jwt


#
#
# DEFAULT VALUES FOR ENVIRONMENT VARIABLES
#
#

AUTHORIZATION_ISSUER_DEFAULT = "dockertest.fairuse.org"
AUTHORIZATION_PERIOD_DEFAULT = 300

#DEFAULT VALUES FOR ANONYMOUS USER

ANONYMOUS_AUTHORIZATION_TYPE = "NoAuthType"
ANONYMOUS_USER_CREDENTIALS = "QW5vbnltb3VzOg==" #base64 encodeed "Anonymous:"
ANONYMOUS_USER_NAME = "Anonymous"
ANONYMOUS_USER_PASSWORD = ""

#
#Log levels
#
LOG_DEBUG = "DEBUG" 
LOG_WARNING = "WARNING" 
LOG_INFO = "INFO" 

#
#
# Refresh token registry
#
#
refresh_token_registry = dict()


#load security data
f = open("/home/icavrak/docker/certs/fairuse.crt", "rb")
cert_data = f.read()
f.close()
f = open("/home/icavrak/docker/certs/fairuse.key", "rb")
private_key_data = f.read()
f.close()

#create security objects (extract keys...)
cert_obj = load_pem_x509_certificate(cert_data, default_backend())
public_key = cert_obj.public_key()
private_key = serialization.load_pem_private_key(private_key_data, password=None, backend=default_backend()) 



#
#
# Logging functions
#
#
def log(loglevel, message):

   #TODO check current log level 

   #get current time
   d = str(datetime.datetime.utcnow())

   #create logging string
   logstring = d + " (" + loglevel + "): " + message

   #output log record TODO: log target?
   print logstring

#
# Utility functions
#
#

def getRequestArgument(request, argumentName):

    data = request.values[argumentName]



def getRequestHeader(request, headerName):

    return request.headers[headerName]


 
# Authentication and authorization
#
#

def authenticateUser(username, password):

  #Authenticate user Anonymous
  if username == ANONYMOUS_USER_NAME and password == ANONYMOUS_USER_PASSWORD:
    return True

  #TODO authenticate from interna/external user list 
  #htpassword file, LDAP, AD, ...
  if username=="iki" and password=="iki":
    return True

  return False

def getRefreshToken(username, service, scope):
  #Opaque token, should be user-, service and token specific
  #and checked upon each bearer token refresh request
  return base64.b64encode("Fixed Refresh Token")

def getAllowedActions(username, service, scope):

  #default allowed action list is empty
  if scope != None:
    allowedActions = ["push", "pull"]
  else: 
    allowedActions = []

  return allowedActions

def getBearerToken(username, service, scope, client):
  #TODO: implement JWT token
  allowedActionList = getAllowedActions(username, service, scope)

  #create payload object (dictionaty)
  payload = {}

  #issuer field, as in AUTHORIZATION_ISSUER environment variable 
  payload["iss"] = os.getenv("AUTHORIZATION_ISSUER", AUTHORIZATION_ISSUER_DEFAULT)

  #authorization subject field, value of client parameter is copied
  payload["sub"] = client

  #audience field, should be service name - value copied from service parameter
  payload["aud"] = service

  #expiration field, set to current time (posix) + AUTHORIZATION_PERIOD
  d = datetime.datetime.utcnow()
  unixtime = calendar.timegm(d.utctimetuple())
  expiration_unixtime = unixtime + os.getenv("AUTHORIZATION_PERIOD", AUTHORIZATION_PERIOD_DEFAULT)
  payload["exp"] = expiration_unixtime

  #not before time field, set to current unix time
  payload["nbf"] = unixtime

  #issued at time field, the same as nbf field
  payload["iat"] = unixtime

  #token id field 
  rnd_seed = calendar.timegm(datetime.datetime.utcnow().utctimetuple()) 
  random.seed(rnd_seed)
  jti_digest_material = str(random.randint(0, rnd_seed)) + str(service) + str(client)
  digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
  digest.update(bytes(jti_digest_material))
  jti_digest = digest.finalize()  
  payload["jti"] = base64.b64encode(jti_digest)
 

  #permission struct (only one permission per request assumed)
  access_permissions = dict() 
  if scope != None:
    try:
      access_permissions["type"] = scope.split(":")[0] 
      access_permissions["name"] = scope.split(":")[1] 
      access_permissions["actions"] = allowedActionList
 
      payload["access"] = list()
      payload["access"].append(access_permissions) 
    except IndexError:
      pass
   
  #kid construction (used on the client side to extract public
  #key from certficate bundle

  #extract DER representation of the public key
  public_key_der = public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
  #public_key_der = public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.PKCS1)

  #make SHA256 of the resulting DER representation and take only fist 240 bits (30 bytes)
  digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
  digest.update(public_key_der)
  kid_digest = digest.finalize()  
  kid_digest = kid_digest[0:30]

  #encode the digest in base32 format
  kid_base32 = base64.b32encode(kid_digest)

  #divide the base32 representation into four-digit groups separated by ":"
  kid = ""
  for i in range(len(kid_base32)/4):
    kid = kid + ":" + kid_base32[i*4: i*4+4]
  kid = kid[1:len(kid)]

  #create additional JTW header items placeholder
  headerItems = {}
  headerItems["kid"] = kid

  #print "==>KID: " + kid

  #create JWT 
  token = jwt.encode(payload, private_key, algorithm="RS256", headers=headerItems) 

  #TODO remove
  print "==>PAYLOAD: " + json.dumps(payload)

  return token 

def getTokenExpiration(username, service, scope):
  #default expiration 5min
  return 300

def getIssuedTime():
  d = datetime.datetime.utcnow()
  return d.isoformat('T') + "Z"

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

  #print request and header information
  print "\n\n-------------------------------------------------"
  print "==> Headers: " + str(request.headers)
  print "==> Request method: {0:s}".format(request.method) 
  print "==> Form content: " + str(request.form)
  print "==> Request args: " + str(request.args)
  print "==> Data: " + str(len(request.data)) + ", " + str(request.data)
  print "==> JSON: " + str(request.json)


  #extract username and password from Authorization: Basic <base64_coded_username_and_password>
  #header might not exist in case of an anonymous access
  credentials = list()
  try:
    credentials = getRequestHeader(request, "Authorization").strip().split()
    print "==> Credentials: " + str(credentials)
    access_authType = credentials[0]
    access_userCredentials = credentials[1]
  except KeyError:
    access_authType = ANONYMOUS_AUTHORIZATION_TYPE
    access_userCredentials = ANONYMOUS_USER_CREDENTIALS

  #check, if the authorization type is "Basic", that 
  #only one additional data string is provided in the Authorization header
  #also allow for anonymous access (no Authorization header present in the request)
  if len(credentials) == 2:
    if credentials[0] != "Basic":
      log(LOG_DEBUG, "Unsupported authorization metod " + credentials[0])
      return response, 401
  elif len(credentials) == 0:
    pass
  else:
    log(LOG_DEBUG, "Malformed Authorization header; " + getRequestHeader(request, "Authorization"))
    return response, 401

  #check for existance of service argument (mandatory)
  try:
    service = getRequestArgument(request, "service") 
  except KeyError:
    log(LOG_DEBUG, "Service request parameter not found")
    return response, 400

  #check for existance of scope argument (optional!) 
  scope = ""
  try:
    scope = getRequestArgument(request, "scope")
  except KeyError:
    pass

  #extract username and password from provided basic credentials
  #if basic credentials are not in base64, treat as unauthorized access
  raw = ""
  try:
    raw = base64.b64decode(access_userCredentials)
    access_userCredentials = raw.split(":")
  except TypeError:
    log(LOG_DEBUG, "Basic authorization credentials not base64 encoded; "+ access_userCredentials )
    return response, 401 

  #check match between username in Authorization header and
  #account field in GET arguments (if not anonymous access)
  try:
    if access_authType != ANONYMOUS_AUTHORIZATION_TYPE:
      if access_userCredentials[0] != getRequestArgument(request, "account"):
        log(LOG_DEBUG, "Basic authorization user does not match account parameter; Basic header="+ access_userCredentials[0] + ", account=" + getRequestArgument(request, "account"))
        return response, 401
  except KeyError:
    log(LOG_DEBUG, "No account parameter specified in the request") 
    return response, 401

  #check for username:password validity
  if authenticateUser(access_userCredentials[0], access_userCredentials[1]) == False:
    log(LOG_DEBUG, "User authorization failed for user " + access_userCredentials[0]) 
    return response, 401

  #construct a response content holder
  resp_content = {}

  #add expires_in data
  resp_content["expires_in"] = getTokenExpiration(access_userCredentials[0], service, scope)

  #add issued_at data
  resp_content["issued_at"] = getIssuedTime()

  #if requested, add refresh token
  try:
    if getRequestArgument(request, "offline_token") == "true":
      resp_content["refresh_token"] = getRefreshToken(access_userCredentials[0], service, scope)
  except KeyError: 
    pass

  #add bearer token
  client = access_userCredentials[0]   #TODO: check if this is true in all cases (anonymous access should pass "")
  if client == ANONYMOUS_USER_NAME:
    client = ""

  resp_content["token"] = getBearerToken(access_userCredentials[0], service, scope, client) 
 

  #response content to JSON format
  resp_content = json.dumps(resp_content)
  print "==> RESPONSE CONTENT: " + resp_content

  response.mimetype = "application/json"
  response.set_data(resp_content)

  return response


  for event in request_json["events"]:

    #skip if "action" is pull
    #if event["action"] == "pull":
    #  continue

    #skip if target.mediaType is not manifest
    #print event["target"]["mediaType"]
 
    if event["target"]["mediaType"] != "application/vnd.docker.distribution.manifest.v2+json":
      continue

    #create a new JSON object containing push data
    record = {}
    record["id"] = event["id"]
    record["timestamp"] = event["timestamp"]
    record["digest"] = event["target"]["digest"]
    record["image"] = event["target"]["repository"]
    record["url"] = event["target"]["url"]
    record["image_tag"] = event["target"]["tag"]
    record["client_addr"] = event["request"]["addr"]
    record["client_name"] = event["actor"]["name"]

    #read log filename from environment variable
    LOG_FILENAME = os.getenv("DOCKER_NOTIFICATION_LOG") 

    #if no log filename defined, output to stdout
    if LOG_FILENAME!= None:
      with open (LOG_FILENAME, "a") as logfile:
        json.dump(record, logfile)
        logfile.write("\n")
      logfile.closed 
    else:
      print json.dumps(record)

  return response 

