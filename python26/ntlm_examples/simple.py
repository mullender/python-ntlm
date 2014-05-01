"""
Usage:  simple.py <password> <url>

This downloads an NTML-protected webpage to stdout.  The username is
constructed from the USERDOMAIN and USERNAME environment variables.
Note that the password is entered on the command line; this is almost
certainly a security risk but unfortunately I know of no foolproof
method in Python for prompting for a password from standard input.

This script only understands NTML authentication.
"""

import urllib2
import inspect, os, sys

try:
    from ntlm import HTTPNtlmAuthHandler
except ImportError:
    # assume ntlm is in the directory "next door"
    ntlm_folder = os.path.realpath(os.path.join(
        os.path.dirname(inspect.getfile(inspect.currentframe())),
        '..'))
    sys.path.insert(0, ntlm_folder)
    from ntlm import HTTPNtlmAuthHandler

def process(password, url):
    user = '%s\%s' % ( os.environ["USERDOMAIN"], os.environ["USERNAME"] )
    
    passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
    passman.add_password(None, url, user, password)
    # create the NTLM authentication handler
    auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)
    
    # create and install the opener
    opener = urllib2.build_opener(auth_NTLM)
    urllib2.install_opener(opener)
    
    # retrieve the result
    response = urllib2.urlopen(url)
    print(response.read())

# The following is adapted from Guido van van Rossum's suggestion.
# http://www.artima.com/weblogs/viewpost.jsp?thread=4829

class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg

import sys
import getopt

def main(argv=None):
    if argv is None:
        argv = sys.argv
    try:
        try:
            opts, args = getopt.getopt(argv[1:], "h", ["help"])
        except getopt.error, msg:
             raise Usage(msg)
        if opts:
            raise Usage(__doc__)
        if len(args) != 2:
            raise Usage('need exactly 2 arguments (%d given)' % len(args))
        process(*args)
    except Usage, err:
        print >>sys.stderr, err.msg
        if err.msg is not __doc__:
            print >>sys.stderr, "for help use --help"
        return 2

if __name__ == "__main__":
    sys.exit(main())
