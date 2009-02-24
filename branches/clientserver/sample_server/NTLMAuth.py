import cherrypy
from cherrypy.lib import httpauth

# Add a Tool to our new Toolbox.
def check_access(handler):
    if 'authorization' in cherrypy.request.headers:
        #Need to keep track of where requests are comming from
        client_details = (cherrypy.request.remote.ip, cherrypy.request.remote.port, cherrypy.request.remote.name)
        msg = cherrypy.request.headers['authorization']
        if msg[0:5].lower() != "ntlm ":
            if handler.default_login:
                raise handler.DefaultLoginRequired()
            raise cherrypy.HTTPError(401, "NTLM authentication is required. Please configure your browser to use NTLM when accessing this site.")
        msg = handler.parse_message(msg[5:].strip())
        msg.verify()
        if handler.is_negotiate_message(msg):
            cherrypy.response.headers['www-authenticate'] = 'NTLM %s'%(handler.get_challenge(msg, client_details))
            raise cherrypy.HTTPError(401)
        elif handler.is_authenticate_message(msg) and not handler.authentication_valid(msg, client_details):
            if handler.default_login:
                raise handler.DefaultLoginRequired()
            raise cherrypy.HTTPError(401, "NTLM Authentication failure. You do not have rights to access this site.")

    else:
        #client has just tried to access a page which requires authorisation
        cherrypy.response.headers['www-authenticate'] = 'NTLM'
        raise cherrypy.HTTPError(401)

cherrypy.tools.ntlm_auth = cherrypy.Tool('before_request_body', check_access)

#NTLMauthtools.check_access = cherrypy.Tool('before_request_body', check_access)
