#
#
# I M P O R T S
#
#
import utils


import datetime


#
#
#  C O N S T A N T S
#
#
LOG_DEBUG = 2
LOG_INFO = 1
LOG_WARNING = 0

LOG_LEVEL_TEXT = ["WARNING", "INFO", "DEBUG"]

#
#
#
# V A R I A B L E S
#
logLevel = LOG_WARNING


#
#
# F U N C T I O N S
#
#
def setLogLevel(loglevel):
  
  global logLevel
  logLevel = loglevel

def getLogLevel():
  return logLevel

def log(loglevel, message):

   #TODO check current log level 
   #if loglevel > logLevel:
   #  return

   #get current time
   d = str(datetime.datetime.utcnow())

   #create logging string
   logstring = d + " (" + LOG_LEVEL_TEXT[loglevel] + "): " + message

   #output log record TODO: log target?
   print logstring

