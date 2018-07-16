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

LOG_OUTPUT_STDOUT = 0
LOG_OUTPUT_FILE = 1

LOG_STDOUT = "LOG_STDOUT"

#
#
#
# V A R I A B L E S
#
logLevel = LOG_WARNING

logOutput = LOG_OUTPUT_STDOUT 
logOutputFilename = None

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

def setLogOutput(output):

  global logOutput, logOutputFilename

  if output == LOG_STDOUT:
    logOutput = LOG_OUTPUT_STDOUT 
    logOutputFilename = None

  else:
    logOutput = LOG_OUTPUT_FILE
    logOutputFilename = output

def getLogOutput():
  return logOutput, logOutputFilename


def log(loglevel, message):

   #TODO check current log level 
   #if loglevel > logLevel:
   #  return

   #get current time
   d = str(datetime.datetime.utcnow())

   #create logging string
   logstring = d + " (" + LOG_LEVEL_TEXT[loglevel] + "): " + message + "\n"

   #output log record TODO: log target?
   if logOutput == LOG_OUTPUT_STDOUT:
     try:
       print logstring
     except IOError:
       pass
   else:
     with open(logOutputFilename, 'a') as f:
       f.write(logstring)


