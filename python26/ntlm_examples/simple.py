import urllib2
from ntlm import HTTPNtlmAuthHandler
import os
import sys

def main():
    assert len( sys.argv ) == 3, "Usage %s <password> <url>" % sys.argv[0]
    user = '%s\%s' % ( os.environ["USERDOMAIN"], os.environ["USERNAME"] )
    password = sys.argv[1]
    url = sys.argv[2]
    
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
