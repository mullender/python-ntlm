import cherrypy
from cherrypy.lib import httpauth
import logging

#Provides a simple way of keeping track of when the user is logged in
active_connections = set()

# Add a Tool to our new Toolbox.
def check_access(handler):
    #Need to keep track of where requests are coming from. In reality these client details aren't specific enough but they will do
    #for the purposes of the example server.
    client_details = (cherrypy.request.remote.ip, cherrypy.request.remote.name)
    if 'authorization' in cherrypy.request.headers:
        msg = cherrypy.request.headers['authorization']
        if msg[0:5].lower() != "ntlm ":
            if handler.default_login:
                raise handler.DefaultLoginRequired()
            logging.debug("Received non-ntlm authorization message: %s", msg,)
            raise cherrypy.HTTPError(401, "NTLM authentication is required. Please configure your browser to use NTLM when accessing this site.")
        logging.debug("Parsing message: %s", msg[5:].strip())
        msg = handler.parse_message(msg[5:].strip())
        logging.debug("Verifying msg: %s", msg.pformat())
        msg.verify()
        if handler.is_negotiate_message(msg):
            challenge = handler.get_challenge(msg, client_details)
            logging.debug("Generated challenge in response to negotiate message (client_details %r): %s", client_details, challenge)
            cherrypy.response.headers['www-authenticate'] = 'NTLM %s' % (challenge,)
            raise cherrypy.HTTPError(401)
        elif handler.is_authenticate_message(msg):
            logging.debug("Received authenticate message")
            if not handler.authentication_valid(msg, client_details):
                logging.debug("Authenticate message was not valid")
                if handler.default_login:
                    raise handler.DefaultLoginRequired()
                raise cherrypy.HTTPError(401, "NTLM Authentication failure. You do not have rights to access this site.")
            active_connections.add(client_details)
    elif not client_details in active_connections:
        #client has just tried to access a page which requires authorisation
        cherrypy.response.headers['www-authenticate'] = 'NTLM'
        logging.debug("Sending initial NTLM authorization request back to client")
        raise cherrypy.HTTPError(401)

cherrypy.tools.ntlm_auth = cherrypy.Tool('before_request_body', check_access)

