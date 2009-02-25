# Create a new Toolbox.
import ntlm2
import base64
import socket
import StringIO

class HTTPServerAuthHandler(ntlm2.ServerInterface):

    class DefaultLoginRequired(Exception):
        """Raised if the HTTPServerAuthHandler allows the use of a manual login when SSO fails"""
        pass

    def __init__(self, users, default_login=False, unsupported_flags=0, version=1):
        super(HTTPServerAuthHandler,self).__init__(unsupported_flags, version)
        self.users = users
        #If this value is true, then the user will be allowed to view the login page if SSO fails
        self.default_login = default_login
        #TODO - If clients do not respond to challenges, they should be removed from the list after a set time
        #Keep a list of clients and their most recent server challenges
        self.challenges = {}

    def is_negotiate_message(self, msg):
        return msg.Header.MessageType == ntlm2.NTLM_MESSAGE_TYPE.NtLmNegotiate.const

    def is_authenticate_message(self, msg):
        return msg.Header.MessageType == ntlm2.NTLM_MESSAGE_TYPE.NtLmAuthenticate.const

    def parse_message(self, message):
        message = StringIO.StringIO(base64.b64decode(message))
        return self.challenge_class.read(message)

    def get_challenge(self, msg, client_details, additional_flags=0):
        """Create a challenge message. If no client_flags or additional_flags are set, only the default challenge flags will be used"""
        client_flags=msg.MessageFields.NegotiateFlags
        msg = self.challenge_class.create(client_flags, additional_flags, self)

        #In Connectionless mode, the server does not store the negotiated flags
        if msg.MessageFields.NegotiateFlags & ntlm2.NTLM_FLAGS.NTLMSSP_NEGOTIATE_DATAGRAM:
            self.challenges[client_details] = {"flags" : None,
                                               "server_challenge" : "".join([chr(x) for x in msg.ServerChallenge])}
        else:
            self.challenges[client_details] = {"flags" : msg.MessageFields.NegotiateFlags,
                                               "server_challenge" : "".join([chr(x) for x in msg.ServerChallenge])}

        return base64.b64encode(msg.get_message_contents())

    def authentication_valid(self, msg, client_details):
        if not self.is_authenticate_message(msg) or not msg.UserName:
            return False

        temp=self.challenges.get(client_details, None)
        if temp is None:
            return False
        #Remove challenge from list regardless of whether the client authentication is valid. All that matters is that the client has responded
        del self.challenges[client_details]

        if temp["flags"] == None:
            NegFlg = msg.MessageFields.NegotiateFlags
        else:
            NegFlg = temp["flags"]

        encoding = msg.unicode if NegFlg&ntlm2.NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE else msg.oem if NegFlg&ntlm2.NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM else None
        domainname = msg.DomainName.decode(encoding) if encoding else msg.DomainName
        username = msg.UserName.decode(encoding) if encoding else  msg.UserName
        if not username in self.users:
            return False

        return msg.check(NegFlg, self.users[username], username, domainname, temp["server_challenge"], self.max_lifetime(), encoding)

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
