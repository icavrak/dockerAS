#
#
# I M P O R T S
#
#
import datetime
import calendar
import json

import os
import sys

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
    try:
      print "------------ " + preamble + " ---------------------"
    except IOError:
      pass


  #dump headers 
  try:
    print "==> Headers: " + str(request.headers)
    print "==> Request method: {0:s}".format(request.method)
    print "==> Form content: " + str(request.form)
    print "==> Request args: " + str(request.args)
    print "==> Data: " + str(len(request.data)) + ", " + str(request.data)
    print "==> JSON: " + str(request.json)
  except IOError:
    pass



def debug(output):

  if debugMode == True:
    try:
      print output
    except IOError:
      pass




def setDebugMode(active):
  global debugMode
  debugMode = active




def getCurrentUnixTime():
  d = datetime.datetime.utcnow()
  unixtime = calendar.timegm(d.utctimetuple())
  return unixtime



def extractExceptionData(excObject):
  try:
    #iexc_type, exc_obj, exc_tb = sys.exc_info()
    exc_type, exc_obj, exc_tb = excObject 
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]

    #return exception type, filename and line number on which the exception occured
    return (exc_type, fname, exc_tb.tb_lineno)
  except:
    return None, None, None

