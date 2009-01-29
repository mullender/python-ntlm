from HTTPNtlmAuthHandler import HTTPNtlmAuthHandler
import urllib2

class TestNTLMServer:
    url = "http://www.smallbusiness.com"
    user = u'SMALLBUSINESS\\duncan1'
    password = 'wwII1939to1945'

    def test_authenticate(self):
        response = self.do_complete_exchange()
	result = response.read()
	#Status will be 401 if there is a problem with authorisation
	assert response.fp.status == 200
	assert result == "<html><head></head><body>This is an example site</body></html>"

    def test_no_authenticate(self):
        response = self.do_complete_exchange(False)
	#Status will be 401 if there is a problem with authorisation
	assert response.fp.status == 401

    def do_complete_exchange(self, password=True):
	passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
	passman.add_password(None, self.url, self.user, self.password if password else "wrong password")
	auth_basic = urllib2.HTTPBasicAuthHandler(passman)
	auth_digest = urllib2.HTTPDigestAuthHandler(passman)
	auth_NTLM = HTTPNtlmAuthHandler(passman)
	
	# disable proxies (just for testing)
	proxy_handler = urllib2.ProxyHandler({}) 
    
	opener = urllib2.build_opener(proxy_handler, auth_NTLM) #, auth_digest, auth_basic)
	
	urllib2.install_opener(opener)
	
	return urllib2.urlopen(self.url)
	