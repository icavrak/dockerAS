#
#
# I M P O R T S
#
#
import datetime
import calendar
import json


#
#
# V A R I A B L E S 
#
#
debugMode = False



#
#
#  C O N S T A N T S
#
#




#
#
# F U N C T I O N S
#
#

def dumpRequestData(request, preamble = ""):

  #check if in silent mode
  if debugMode == True:
    return

  #dump preamble
  if preamble != "":
    print "------------ " + preamble + " ---------------------"

  #dump headers 
  print "==> Headers: " + str(request.headers)
  print "==> Request method: {0:s}".format(request.method)
  print "==> Form content: " + str(request.form)
  print "==> Request args: " + str(request.args)
  print "==> Data: " + str(len(request.data)) + ", " + str(request.data)
  print "==> JSON: " + str(request.json)




def debug(output):

  if debugMode == True:
    print output

def setDebugMode(active):
  global debugMode
  debugMode = active

def getCurrentUnixTime():
  d = datetime.datetime.utcnow()
  unixtime = calendar.timegm(d.utctimetuple())
  return unixtime

