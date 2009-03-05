# Create a new Toolbox.
import ntlm2
import socket

class HTTPServerAuthHandler(ntlm2.NTLMServerBase):

    class DefaultLoginRequired(Exception):
        """Raised if the HTTPServerAuthHandler allows the use of a manual login when SSO fails"""
        pass

    def __init__(self, users, default_login=False, unsupported_flags=0, version=1):
        """Initialise a simple HTTP server"""
        #This server does not support datagram/connectionless mode, the identify flag or session security
        unsupported_flags = unsupported_flags | ntlm2.NTLM_FLAGS.NTLMSSP_NEGOTIATE_IDENTIFY | ntlm2.NTLM_FLAGS.NTLMSSP_NEGOTIATE_DATAGRAM | ntlm2.NTLM_FLAGS.NTLMSSP_NEGOTIATE_SIGN | ntlm2.NTLM_FLAGS.NTLMSSP_NEGOTIATE_SEAL | ntlm2.NTLM_FLAGS.NTLMSSP_NEGOTIATE_KEY_EXCHANGE
        super(HTTPServerAuthHandler,self).__init__(unsupported_flags, version)
        self.users = users
        #If this value is true, then the user will be allowed to view the login page if SSO fails
        self.default_login = default_login
        #TODO - If clients do not respond to challenges, they should be removed from the list after a set time eg j5.Basic.TimeCache
        #Keep a list of clients and their most recent server challenges
        self.challenges = {}

    def cache_challenge(self, client_details, server_challenge, flags):
        """Must provide a means of caching the last challenge that the server sent the client with client_details."""
        #A very simple cache, which does not even delete old challenges if no response was received
        self.challenges[client_details] = {"flags" : flags, "server_challenge" : server_challenge}

    def get_cached_challenge(self, client_details):
        """Must provide a means of retrieving the last challenge that the server sent the client with client_details."""
        return self.challenges.get(client_details, None)

    def delete_cached_challenge(self, client_details):
        """Must provide a means of deleting the last challenge that the server sent the client with client_details."""
        del self.challenges[client_details]

    def get_authenticated_response(self, message, NegFlg, username, domainname, server_challenge, max_lifetime, encoding):
        """Must generate a ResponseData object and compare its values to the values in "message" (which is an Authenticate message).
           If the message values match the calculated values, return the ResponseData object otherwise, return None."""
        if not username in self.users:
            return None
        return message.authenticated_response(NegFlg, self.users[username], username, domainname, server_challenge, max_lifetime, encoding)

    def negotiated_security_ok(self, NegFlg):
        return True

    def domain_joined(self):
        """From [MS-NLMP] page 52. Should presumably return true if the server is joined to a domain"""
        return False

    def get_NetBIOS_name(self):
        """Must return None or the NetBIOS name of the server"""
        return socket.gethostname()

    def get_NetBIOS_domain(self):
        """Must return None or the NetBIOS domain name of the server"""
        return socket.getfqdn()

    def get_DNS_name(self):
        """Must return None or the server's Active Directory DNS computer name."""
        return None

    def get_DNS_domain(self):
        """Must return None or the server's Active Directory DNS domain name."""
        return None

    def get_DNS_forest_name(self):
        """Must return None or the server's Active Directory DNS forest tree name."""
        return None

    def client_supplied_target_name(self):
        """Service principal name (SPN) of the service that the client wishes to authenticate to. This value is optional."""
        return None

    def server_channel_bindings_unhashed(self):
        """The gss_channel_bindings_struct ([RFC2744] section 3.11). This value is supplied by the application and used by the protocol.
           This value is optional."""
        return None
