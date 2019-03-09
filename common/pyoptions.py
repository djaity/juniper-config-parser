# ----------------------------------------------------
# Creation Date : Fev/2/2016
# Author : JT Graveaud
# ----------------------------------------------------
# This module has been developped to get parameters provided to python scripts
#
# use case example in your script:
#
# from pyoptions import script_opt
# DEBUG = script_opt('debug', False, sys.argv)
# PARAM = script_opt('param', 'default string')
# 
# Thus, if you provide the parameter --debug in your script, this will 
# display a list of parameter's values in your script.
#
# the function "script_opt" returns script parameters
# single dash followed by the name of the parameter expects a value
# double dash followed by the name of the parameter is just a flag and does not expect a value
# -<param> : expect a value
# --<param> : does not expect value

# those variables are global but stay local to this module
DISPLAY_PARAM=False
SYS_ARGV=None


def script_opt(name, default, argv=None, type='str', handle=None):
  global DISPLAY_PARAM, SYS_ARGV

  # memorize argv passed in the 3rd argument
  if argv==None:
    if SYS_ARGV:
      argv = SYS_ARGV
  else:
    SYS_ARGV = argv

  for a in range(len(argv)):
    # initialize a local variable that allows to undersand "-help", "--help", "-?", 
    # and "/?" as "--help" trigger
    if argv[a] == '-help' or argv[a] == '--help' or argv[a] == '-?' or argv[a] == '/?':
      argv[a] = '--help'

    # handle parameters expecting a value 
    # ex: -date 20160202
    if argv[a] == "-"+name:
      try:
        # check the following argument does not start by a '-'
        if not argv[a+1].startswith('-'):
          if type=='str':
            if handle:
              param_value = handle(argv[a+1])
            else:
              param_value = (str)(argv[a+1])
            if DISPLAY_PARAM:
              print 'Param: "'+name+'" Value: "'+param_value+'"'
            return param_value
          else:
            if DISPLAY_PARAM:
              print 'Param: "'+name+'" Value: "'+(str)(argv[a+1])+'"'
            return (int)(argv[a+1])
        # other return the default value
        else:
          if DISPLAY_PARAM:
            print 'Param: "'+name+'" Value: "'+(str)(default)+'"'
          # if value expected does not exit, return default
          if handle:
            default = handle(default)
          return default
      except IndexError:
        # the exception is thrown when argv[a+1] does not exist
        if DISPLAY_PARAM:
          print 'Param: "'+name+'" Value: "False" (exception)'
        return False

    # handle parameters that does not expect a value 
    # ex: --legend
    elif argv[a] == "--"+name:
      if DISPLAY_PARAM:
        print 'Param: "'+name+"\" : activated"

      # by default DISPLAY_PARAM is equal to False, 
      # in order to set the global parameter within the module, this is set here
      # when the parameter passed is 'debug'
      if name=="debug":
        print "--------------------------"
        print "List of parameters"
        print "--------------------------"
        DISPLAY_PARAM=True
      return True

  # if parameter not found return default
  if DISPLAY_PARAM:
    print 'Param: "'+name+'" Default value: "'+(str)(default)+'"'
  if handle:
    default = handle(default)
  return default

