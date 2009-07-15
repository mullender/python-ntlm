import urllib2
from urlparse import urlparse, urlunparse
from ntlm import HTTPNtlmAuthHandler
import sys
import os

def main():
    assert len( sys.argv ) == 3, "Usage %s <password> <url>" % sys.argv[0]
    user = '%s\%s' % ( os.environ["USERDOMAIN"], os.environ["USERNAME"] )
    password = sys.argv[1]
    url = sys.argv[2]
    # determine a base_uri for which the username and password can be used
    parsed_url = urlparse(url)
    base_uri = urlunparse((parsed_url[0],parsed_url[1],"","","",""))
    
    passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
    passman.add_password(None, base_uri, user, password)
    # create the NTLM authentication handler
    auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)
    
    # other authentication handlers
    auth_basic = urllib2.HTTPBasicAuthHandler(passman)
    auth_digest = urllib2.HTTPDigestAuthHandler(passman)
    
    # disable proxies (if you want to stay within the corporate network)
    proxy_handler = urllib2.ProxyHandler({})
    
    # create and install the opener
    opener = urllib2.build_opener(proxy_handler, auth_NTLM, auth_digest, auth_basic)
    urllib2.install_opener(opener)
    
    # retrieve the result    
    response = urllib2.urlopen(url)
    print(response.read())
