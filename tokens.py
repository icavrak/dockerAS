#
#
# I M P O R T S
#
#
import log
import utils
import auth

from passlib.apache import HtpasswdFile
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

import calendar
import datetime
import random
import base64
import jwt
import json
#
#
#  C O N S T A N T S
#
#
REFRESH_TOKEN_VALIDITY_PERIOD = 300

AUTHORIZATION_ISSUER_DEFAULT = "dockertest.fairuse.org"
AUTHORIZATION_PERIOD_DEFAULT = 300
#
#
# V A R I A B L E S
#
#
refresh_token_registry = dict()


###########################################################################
#
#           U T I L I T Y     F U N C T I O N S
#
###########################################################################
def getRandomToken(username, service, client):
  rnd_seed = calendar.timegm(datetime.datetime.utcnow().utctimetuple())
  random.seed(rnd_seed)
  token_digest_material = str(random.randint(0, rnd_seed)) + str(username) + str(service) + str(client)
  digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
  digest.update(bytes(token_digest_material))
  token_digest = digest.finalize()
  return base64.b64encode(token_digest)


def getTokenExpiration(username, service, scope):
  #default expiration 5min
  return 300


def getIssuedTime():
  d = datetime.datetime.utcnow()
  return d.isoformat('T') + "Z"


###########################################################################
#
#           R E F R E S H   T O K E N S 
#
###########################################################################

def getRefreshToken(username, service, scope):

  refreshToken = getRandomToken(username, service, scope)

  refreshTokenData = list()
  refreshTokenData.append(username)
  refreshTokenData.append(service)
  refreshTokenData.append(utils.getCurrentUnixTime() + REFRESH_TOKEN_VALIDITY_PERIOD)

  refresh_token_registry[refreshToken] = refreshTokenData

  return refreshToken


def checkRefreshToken(refreshToken, username=None, service=None):

  #find refresh token in the refresh token registry
  try:
    ref_token_data = refresh_token_registry[refreshToken]
  except KeyError:
    return False

  #check for time validity expiration
  now = utils.getCurrentUnixTime()
  if ref_token_data[2] < now:
    return False

  #check for service equality 
  if service != None:
    if ref_token_data[1] != service:
      return False

  #check for user equality
  if username != None:
    if ref_token_data[0] != username:
      return False

  #all checks passed successfuly
  return True


def getUserFromRefreshToken(refreshToken, service=None, checkTokenValidity=True):

  #check for token expiration
  if checkTokenValidity == True and checkRefreshToken(refreshToken, None, service) == False:
    return None

  try:
    ref_token_data = refresh_token_registry[refreshToken]
    return ref_token_data[0]
  except KeyError:
    return None


###########################################################################
#
#           B E A R E R    T O K E N S 
#
###########################################################################

def getBearerToken(username, service, scope, client, auth_issuer, auth_period):

  allowedActionList = auth.getAllowedActions(username, service, scope)

  #create payload object (dictionaty)
  payload = {}

  #issuer field, as in AUTHORIZATION_ISSUER environment variable 
  payload["iss"] = auth_issuer

  #authorization subject field, value of client parameter is copied
  payload["sub"] = client

  #audience field, should be service name - value copied from service parameter
  payload["aud"] = service

  #expiration field, set to current time (posix) + AUTHORIZATION_PERIOD
  unix_time_now = utils.getCurrentUnixTime()
  expiration_unixtime = unix_time_now + auth_period 
  payload["exp"] = expiration_unixtime

  #not before time field, set to current unix time
  payload["nbf"] = unix_time_now

  #issued at time field, the same as nbf field
  payload["iat"] = unix_time_now

  #token id field 
  payload["jti"] = getRandomToken(username, service, client)


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

  #create additional JTW header items placeholder
  headerItems = {}
  headerItems["kid"] = auth.getKID()

  #create JWT 
  token = jwt.encode(payload, auth.getPrivateKey(), algorithm="RS256", headers=headerItems)

  #check for validity by verifiying the signature
  #t2 = jwt.decode(token, public_key, audience=service, algorithm="RS256")

  utils.debug("==>PAYLOAD: " + json.dumps(payload))

  return token


