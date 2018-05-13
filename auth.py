#
#
# I M P O R T S
#
#
import log
import utils

from passlib.apache import HtpasswdFile
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

import json
import base64
import re
import requests

#
#
#  C O N S T A N T S
#
#
ANONYMOUS_AUTHORIZATION_TYPE	= "NoAuthType"
ANONYMOUS_USER_CREDENTIALS	= "QW5vbnltb3VzOg==" #base64 encodeed "Anonymous:"
ANONYMOUS_USER_NAME		= "Anonymous"
ANONYMOUS_USER_PASSWORD		= ""

ACL_ANY_FILENAME	= "$"
ACL_ANY_FILENAME_REGEX 	= "[A-Za-z0-9_]+"
ACL_ANY_PATH		= "*"
ACL_ANY_PATH_REGEX	= "((?:[A-Za-z0-9_]*)(?:\/[A-Za-z0-9_]+)*)"

AUTH_EXT_CAHCE_TIMEOUT  = 30 

#
#
# V A R I A B L E S
#
#
auth_htpasswd 		= None
auth_htpasswd_users 	= list()
auth_ext_url		= None

acl_data     		= None

sec_cert	= None
sec_public_key  = None
sec_private_key = None

auth_ext_cache	= dict()

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

def getPrivateKey():

  return sec_private_key


def getKID():

  #kid construction (used on the client side to extract public
  #key from certficate bundle

  #extract DER representation of the public key
  public_key_der = sec_public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
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

  return kid

###########################################################################
#
#               L O A D I N G    A U T H.  D A T A 
# 
###########################################################################

def loadHTPASSWDData(path):

  global auth_htpasswd, auth_htpasswd_users
  try:
    auth_htpasswd = HtpasswdFile(path)

    #create htpasswd user list
    auth_htpasswd_users = auth_htpasswd.users()
    log.log(log.LOG_INFO, "Loaded user authentication data from " + path)
    return True
  except IOError:
    log.log(log.LOG_WARNING, "Failed to load user authentication data from " + path)
  return False


def setExternalServiceURL(url):

  global auth_ext_url
  if url == "":
    return
  else:
    auth_ext_url = url


def loadACLData(path):

  global acl_data
  try:
    with open(path) as acl_file:
      acl_data = json.load(acl_file)
    log.log(log.LOG_INFO, "Loaded ACL data from " + path)
    return True
  except IOError:
    return False


def loadCertData(path):

  try:
    with open(path) as cert_file:
      cert_data = cert_file.read()
    log.log(log.LOG_INFO, "Loaded certificate data from " + path)
    return cert_data
  except IOError:
    log.log(log.LOG_WARNING, "Failed to load SSH security data from " + path)
  return None


def loadPKeyData(path):

  try:
    with open(path) as pkey_file:
      pkey_data = pkey_file.read()
    log.log(log.LOG_INFO, "Loaded private key data from " + path)
    return pkey_data
  except IOError:
    log.log(log.LOG_WARNING, "Failed to load SSH security data from " + path)
  return None


def extractSecObjects(cert_data, pkey_data):

  global sec_cert, sec_private_key, sec_public_key

  if cert_data == None or pkey_data == None:
    log.log(log.LOG_WARNING, "Failed to initialize security data")
    return False

  try:
    sec_cert = load_pem_x509_certificate(cert_data, default_backend())
    sec_public_key = sec_cert.public_key()
    sec_private_key = serialization.load_pem_private_key(pkey_data, password=None, backend=default_backend())
    log.log(log.LOG_INFO, "Initialized security data")
    return True
  except IOError:
    log.log(log.LOG_WARNING, "Failed to initialize security data")

  return False

###########################################################################
#
#              H T T P   H E A D E R   D A T A 
# 
###########################################################################

def getRequestAuthenticationData(request):

  #Eextract username and password from 
  #  Authorization:  Basic <base64_coded_username_and_password>
  #Header might not exist in case of an anonymous access
  credentials = list()
  access_authType = None
  access_userCredentials = None

  try:
    credentials = request.headers["Authorization"].strip().split()
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
      log.log(log.LOG_DEBUG, "Unsupported authorization metod " + credentials[0])
      return access_authType, access_userCredentials
  elif len(credentials) == 0:
    pass
  else:
    log.log(log.LOG_DEBUG, "Malformed Authorization header; " + getRequestHeader(request, "Authorization"))
    return access_authType, access_userCredentials

  return access_authType, access_userCredentials


def getAccessCredentialsData(auth_type, raw_credentials):

  #if Basic authorization type is provided
  if auth_type == "Basic":
    try:
      raw = base64.b64decode(raw_credentials)
      credentials = raw.split(":")
      return credentials[0], credentials[1]  
    except TypeError:
      log.log(log.LOG_DEBUG, "Basic authorization credentials not base64 encoded; "+ raw_credentials)
      return None, None 
    except IndexError:
      log.log(log.LOG_DEBUG, "Basic authorization credentials unexpected format; " + raw)
      return None, None 
  elif auth_type == ANONYMOUS_AUTHORIZATION_TYPE:
    return ANONYMOUS_USER_NAME, ANONYMOUS_USER_PASSWORD

  #authorization type is not supported
  else:
    log.log(log.LOG_WARNING, "Authorization type not supported: " + auth_type)
    return None, None



###########################################################################
#
#                   A U T H E N T I C A T I O N
# 
###########################################################################
def authenticateUser_HTPASSWD(username, password):

  global auth_htpasswd

  log.log(log.LOG_DEBUG, "Autenticating user " + username + " using HTPASSWD method")
  #Authenticate user Anonymous
  if username == ANONYMOUS_USER_NAME and password == ANONYMOUS_USER_PASSWORD:
    log.log(log.LOG_DEBUG, "Authenticated anonymous user ")
    return True

  #check that the htpasswd file has been loaded
  if auth_htpasswd == None:
    log.log(log.LOG_DEBUG, "No HTPASSWD authentication file provided")
    return False

  #reload htpasswd data, if changed
  auth_htpasswd.load_if_changed()

  #check for users in htpasswd file
  if username in auth_htpasswd.users():
    if auth_htpasswd.check_password(username, password) == True:
      log.log(log.LOG_DEBUG, "Authenticated user " + username + " using htpasswd authentication source")
      return True
    else:
      log.log(log.LOG_DEBUG, "Failed authenticating user " + username + " using htpasswd authentication source")
      return False

  #default response
  log.log(log.LOG_DEBUG, "Failed authenticating user " + username)
  return False



def authenticateUser_EXTERNAL(username, password):


  #check if external service's URL is defined, otherwise skip
  if auth_ext_url == None:
    return False

  log.log(log.LOG_DEBUG, "Autenticating user " + username + " using external method")


  #check if the record exists in the local cache
  try:
    #fetch the record (if exists)
    auth_record = auth_ext_cache[username]
    
    #get the password and expiration time data
    pwd = auth_record[0]
    exptime = auth_record[1] 

    #check for equalness of passwords
    if pwd != password:
      log.log(log.LOG_DEBUG, "Passwords in cache and provided password for user " + username + " do not match")
    else:
      #check for expiration time of cache record
      if( exptime < utils.getCurrentUnixTime() ):
        log.log(log.LOG_DEBUG, "Cache record for user " + username + " expired")
      else:
        #confirm username-password match
        log.log(log.LOG_DEBUG, "Autenticating user " + username + " succeeded using external method (cache)")
        return True
  except KeyError:
    pass

  #make an authentication request
  try:
    resp = requests.get(auth_ext_url, auth=(username, password))
  except Exception as e:
    log.log(log.LOG_WARNING, "External auth service at " + auth_ext_url + " responded with error: " + str(e))
    return False

  #check for response codes
  if resp.status_code == 200:
    
    #create cache record
    auth_record = list()
    auth_record.append(password)
    auth_record.append(utils.getCurrentUnixTime() + AUTH_EXT_CAHCE_TIMEOUT)
    auth_ext_cache[username] = auth_record
    log.log(log.LOG_DEBUG, "Created external authentication cahce record for user " + username)

    #return success
    log.log(log.LOG_DEBUG, "Autenticating user " + username + " succeeded using external method")
    return True

  else:
    log.log(log.LOG_WARNING, "External auth service response code: " + str(resp.status_code) + " for user " + username)

  #default response 
  return False


def authenticateUser(username, password):


  #first try to authenticate user using local htpasswd
  if authenticateUser_HTPASSWD(username, password) == True:
    return True

  #if external service URL is defined, try using it
  if authenticateUser_EXTERNAL(username, password) == True:
    return True

  #if LDAP/AD data is defined, try using it
  #TODO

  return False


###########################################################################
#
#                         A U T H O R I Z A T I O N 
# 
###########################################################################

def getAllowedActionsForUser(username, resource_name, service, resourceTypeACL):

  #check for resource name and access rights for particular username
  resourceACL = None
  userACL = None
  try:
    #try to find ACL for the particular resource (verbatim)
    resourceACL = resourceTypeACL[resource_name]
    #print "==>RESOURCE ACL: " + str(resourceACL)

    #try to find username in the ACL (verbatim)
    try:
      userACL = resourceACL[username]
      #print "==>USER ACL: " + str(userACL)

    except KeyError:
      log.log(log.LOG_INFO, "Could not find ACL data for user " + username + " for resource " + resource_name)
  except KeyError:
    log.log(log.LOG_INFO, "Could not find ACL data for resource " + resource_name + " for service: " + service)

  return userACL



def getAllowedActionsForUserExt(username, userGroups, resource_name, service, resourceTypeACL):

  #user access rights
  userACL = None

  #get the list of the resources for the given resource type and service
  resourceList = resourceTypeACL.keys()

  #iterate over the list of resource names
  for resource in resourceList:

    #expand the variables in the resource name, if exist:
    #user name - <USERNAME>
    resourceName = resource.replace("<USERNAME>", username)
    if username != "Anonymous":
      resourceName = resourceName.replace("<REGUSER>", username)

    #replace special symbols in the registry name with regex snippets
    resourceName = resourceName.replace(ACL_ANY_FILENAME, ACL_ANY_FILENAME_REGEX)
    resourceName = resourceName.replace(ACL_ANY_PATH, ACL_ANY_PATH_REGEX)

    utils.debug("username= " + username + "; resource=" + resource + "; exp="  + str(resourceName))

    #construct a regex from the expanded resource name
    res = re.search(resourceName, resource_name)

    #check if match is found, if not move to next resource 
    try:
      if res == None:
        continue

      if res.group(0) != resource_name:
        continue

      #match is found, check for generic username <USERNAME> in the user list
      resourceACL = resourceTypeACL[resource]
      try:
        #generic username found, stop iteration
        userACL = resourceACL["<USERNAME>"]
        break

      #no generic username found
      except KeyError:
        pass

      try:
        #generic username found, stop iteration
        userACL = resourceACL["<REGUSER>"]
        break

      #no generic username found
      except KeyError:
        pass

      #try to find current username
      try:
        #real username found in the ACL, stop iteration
        userACL = resourceACL[username]
        break

      #no current username found in the resource ACL
      except KeyError:
        pass

      #if no user groups are defined, move to next resource
      if userGroups != None:

        #iterate over user list, try to detect group names
        userList = resourceACL.keys()
        for user in userList:

          #is user actually a user list - "(groupname)"?
          if user.startswith("(") and user.endswith(")"):

            #extract group name (strip braces)
            user = user[1:len(user)-1]

            #try to find the group name in groups list for the current service
            try:
              group = userGroups[user]
             #is the username within the list of user names for the current group?
              if username in group:
                userACL = resourceACL["("+user+")"]
                break
            #user group definition not find for the current service
            except KeyError:
              continue

    except IndexError:
    #no regex match, continue with iterating over resources
      continue

  return userACL



def getAllowedActions(username, service, scope):

  #default actions - empty set
  allowedActions = []

  #check that ACL is loaded
  if acl_data == None:
    log.log(log.LOG_DEBUG, "No ACL data loaded, cannot perform local authorization service")
    return allowedActions

  #extract all information from scope argument, check for valid format
  #type:name:actions
  try:
    resource_type, resource_name, resource_actions = scope.split(":")
  except ValueError:
    log.log(log.LOG_DEBUG, "Malformed scope information: " + str(scope))
    return allowedActions

  try:
    #get service-specific sub-ACL
    serviceACL = acl_data[service]
    try:
      #get resource type-specific sub-ACL 
      resourceTypeACL = serviceACL[resource_type]
    except KeyError:
      log.log(log.LOG_INFO, "Could not find resource type: " + resource_type + " ACL data for service: " + service)
      return allowedActions
  except KeyError:
    log.log(log.LOG_INFO, "Could not find ACL data for service: " + service)
    return allowedActions

  #get access rights for particular username
  userACL = getAllowedActionsForUser(username, resource_name, service, resourceTypeACL)

  if userACL == None:
    log.log(log.LOG_DEBUG, "Static ACL information on user " + username + " not found, trying advanced one. ")

  #if userACL was not found in the "verbatim" interpretation of the ACL list,
  #for the requested service and resource type, try with the regex+varables interpretation 
  #and user groups, if defined for the authorization requesting service
  if userACL == None:
    userGroups = None
    try:
      userGroups = serviceACL["groups"]
    except KeyError:
      #no user groups defined for the service
      log.log(log.LOG_DEBUG, "No user groups defined for service " + service)
      pass

    userACL = getAllowedActionsForUserExt(username, userGroups, resource_name, service, resourceTypeACL)

  #determine granted access rights
  if userACL != None:
    s1 = set(userACL)
    s2 = set(resource_actions.split(","))
    allowedActions = list(s1.intersection(s2))

  return allowedActions


