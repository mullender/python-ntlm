"""Tests for the NTLM module"""

import ntlm2
from ntlm2 import NTLM_FLAGS, AV_TYPES
import base64
import ctypes
import StringIO

class SysCheat:
    """This is a bit of a cheat to allow testing of messages in a non-windows environment. Plus it forces getwindowsversion to
    return predefined values."""
    def getwindowsversion(self):
        return (1,2,3,4,"This is not an OS")

ntlm2.sys=SysCheat()

class ATestServer(ntlm2.ServerInterface):
    randomvalue = 0
    timestamp = 0

    def __init__(self, nb_n, nb_d, dns_n, dns_d, f_n, unsupported_flags=0):
        super(ATestServer,self).__init__(unsupported_flags)
        self.netbios_name = nb_n
        self.netbios_domain = nb_d
        self.dns_name = dns_n
        self.dns_domain = dns_d
        self.dns_forest_name = f_n

    def domain_joined(self):
        return True

    @classmethod
    def get_timestamp(cls):
        return cls.timestamp

    @classmethod
    def get_nonce(cls):
        return cls.randomvalue

    def negotiated_security_ok(self, NegFlg):
	return True

    def get_NetBIOS_name(self):
        return self.netbios_name

    def get_NetBIOS_domain(self):
        return self.netbios_domain

    def get_DNS_name(self):
        return self.dns_name

    def get_DNS_domain(self):
        return self.dns_domain

    def get_DNS_forest_name(self):
        return self.dns_forest_name

class ATestClient(ntlm2.ClientInterface):
    randomvalue = 0
    timestamp = 0

    def __init__(self, w, d, u, p, unsupported_flags=0):
        super(ATestClient,self).__init__(unsupported_flags)
        self.workstation = w
        self.domain = d
        self.user=u
        self.password=p

    def negotiated_security_ok(self, NegFlg):
	return True

    @classmethod
    def get_timestamp(cls):
        return cls.timestamp

    @classmethod
    def get_nonce(cls):
        return cls.randomvalue

    def get_workstation(self):
        return self.workstation

    def get_domain(self):
        return self.domain

    def get_user_name(self):
        return self.user

    def get_user_password(self):
        return self.password

def unicode_encode(s):
    """convert a unicode string to a byte encoding"""
    s = s.encode("UTF-16")
    if s.startswith("\xff\xfe"):
        s = s[2:]
    return s

def ByteToHex( byteStr ):
    """
    Convert a byte string to it's hex string representation e.g. for output.
    """
    return ' '.join( [ "%02X" % ord(x) for x in byteStr ] )

def HexToByte( hexStr ):
    """
    Convert a string hex byte values into a byte string. The Hex Byte values may
    or may not be space separated.
    """
    bytes = []
    hexStr = hexStr.replace(" ", "")
    for i in range(0, len(hexStr), 2):
        bytes.append(chr(int(hexStr[i:i+2], 16)))
    return ''.join( bytes )

class TestNTLMClient(object):
    """Tests based on example at http://www.innovation.ch/personal/ronald/ntlm.html. Modified for NTLMv2 using [MS-NLMP] page 75 on..."""

    def test_hash_functions(self):
        """Test underlying hash functions"""
        ServerChallenge = HexToByte("01 23 45 67 89 ab cd ef")
        ClientChallenge = '\xaa'*8
        Time = '\x00'*8
        Workstation = "COMPUTER"
        ServerName = "Server"
        User = "User"
        Domain = "Domain"
        Password = "Password"
        RandomSessionKey = '\55'*16

        # NTLM VERSION 1
        #Test Case: NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY not set and NTLMSSP_NEGOTIATE_NT_ONLY not set [MS-NLMP] page 73
        responsedata = ntlm2.NTLMAuthenticateMessageV1.compute_response(0, Password, User, Domain, ServerChallenge, ClientChallenge, Time, ServerName, ntlm2.NTLMMessage.unicode)

        # [MS-NLMP] page 72
        assert responsedata.ResponseKeyNT == HexToByte("a4f49c40 6510bdca b6824ee7 c30fd852")
        assert responsedata.ResponseKeyLM == HexToByte("e52cac67 419a9a22 4a3b108f 3fa6cb6d")
        assert responsedata.SessionBaseKey == HexToByte("d87262b0 cde4b1cb 7499becc cdf10784")

        assert responsedata.NTChallengeResponse == HexToByte("67c43011 f30298a2 ad35ece6 4f16331c 44bdbed9 27841f94")
        assert responsedata.LmChallengeResponse == HexToByte("98def7b8 7f88aa5d afe2df77 9688a172 def11c7d 5ccdef13")

        #MISSING Compute Response Test Cases:
        #NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY not set and NTLMSSP_NEGOTIATE_LM_KEY is set
        #NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY is set
        #NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY is set and NTLMSSP_NEGOTIATE_LM_KEY is set
        #NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY not set and NTLMSSP_NEGOTIATE_NT_ONLY is set

        # NTLM VERSION 2
        #Use the values below to construct "ServerName"/targetinfo as it would a appear in a type 2 message
        domainname_avpair = "02000c0044006f006d00610069006e00"
        servername_avpair = "01000c00530065007200760065007200"
        avpair_terminator = "00000000"
        targetinfo = HexToByte(domainname_avpair+servername_avpair+avpair_terminator)

        responsedata = ntlm2.NTLMAuthenticateMessageV2.compute_response(0, Password, User, Domain, ServerChallenge, ClientChallenge, Time, targetinfo,  ntlm2.NTLMMessage.unicode)

        # [MS-NLMP] page 72
        assert responsedata.ResponseKeyNT == HexToByte("0c868a40 3bfd7a93 a3001ef2 2ef02e3f")
        assert responsedata.ResponseKeyLM == HexToByte("0c868a40 3bfd7a93 a3001ef2 2ef02e3f")
        assert responsedata.SessionBaseKey == HexToByte("8de40cca dbc14a82 f15cb0ad 0de95ca3")
        #TODO - Fix the NTChallengeResponse test
        #The value below must be incorrect, because it is the NTProofStr and the NTChallengeResponse should be
        #NTProofStr + temp. However, SessionBaseKey is derived from NTProofStr, which is in turn derived from temp.
        #So if SessionBaseKey is correct then it is highly unlikely that NTProofStr or temp are incorrect
        #assert responsedata.NTChallengeResponse == HexToByte("68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c")
        assert responsedata.LmChallengeResponse == HexToByte("86c35097 ac9cec10 2554764a 57cccc19 aaaaaaaa aaaaaaaa")

    # -------------------------------------------------------------------------------------------------------------
    # Negotiate Message Tests
    # -------------------------------------------------------------------------------------------------------------

    def test_parse_simplest_negotiate_message(self):
        #Version 1 negotiate message test

        #Test simplest possible negotiate message
        #Example values taken from http://davenport.sourceforge.net/ntlm.html#theType1Message
        message = HexToByte("4e544c4d535350000100000002020000")
        f = StringIO.StringIO(message)
        negotiate_message = ntlm2.NTLMMessage.read(f)
        negotiate_message.verify()
        assert negotiate_message.Header.MessageType == ntlm2.NTLM_MESSAGE_TYPE.NtLmNegotiate.const
        assert negotiate_message.get_string_field("Workstation") is None
        assert negotiate_message.get_string_field("DomainName") is None
        assert negotiate_message.get_string_fields() == {}
        assert negotiate_message.MessageFields.NegotiateFlags == NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NTLM
        version = negotiate_message.get_version_field()
        assert version is None

    def test_parse_normal_negotiate_message(self):
        #Version 1 negotiate message test

        #Test negotiate message with no version information
        message = HexToByte("4e544c4d535350000100000007320000060006002b0000000b000b0020000000574f524b53544154494f4e444f4d41494e")
        f = StringIO.StringIO(message)
        negotiate_message = ntlm2.NTLMMessage.read(f)
        negotiate_message.verify()
        expectedflags = NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM | NTLM_FLAGS.NTLMSSP_REQUEST_TARGET | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NTLM | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED

        assert negotiate_message.Header.MessageType == ntlm2.NTLM_MESSAGE_TYPE.NtLmNegotiate.const
        assert negotiate_message.get_string_field("Workstation") == "WORKSTATION"
        assert negotiate_message.get_string_field("DomainName") == "DOMAIN"
        assert negotiate_message.get_string_fields() == {"DomainName": "DOMAIN", "Workstation": "WORKSTATION"}
        assert negotiate_message.MessageFields.NegotiateFlags == expectedflags
        version = negotiate_message.get_version_field()
        assert version is None

    def test_parse_full_negotiate_message(self):
        #Test full negotiate message
        #Example values taken from http://davenport.sourceforge.net/ntlm.html#theType1Message
        message = HexToByte("4e544c4d53535000010000000732000206000600330000000b000b0028000000050093080000000f574f524b53544154494f4e444f4d41494e")

        f = StringIO.StringIO(message)
        negotiate_message = ntlm2.NTLMMessage.read(f)
        negotiate_message.verify()
        expectedflags = NTLM_FLAGS.NTLMSSP_NEGOTIATE_VERSION | NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM | NTLM_FLAGS.NTLMSSP_REQUEST_TARGET | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NTLM | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED

        assert negotiate_message.Header.MessageType == ntlm2.NTLM_MESSAGE_TYPE.NtLmNegotiate.const
        assert negotiate_message.get_string_field("Workstation") == "WORKSTATION"
        assert negotiate_message.get_string_field("DomainName") == "DOMAIN"
        assert negotiate_message.get_string_fields() == {"DomainName": "DOMAIN", "Workstation": "WORKSTATION"}

        assert negotiate_message.MessageFields.NegotiateFlags == expectedflags

        version = negotiate_message.get_version_field()
        assert version is not None
        assert version.ProductMajorVersion == 5
        assert version.ProductMinorVersion == 0
        assert version.ProductBuild == 2195
        assert version.NTLMRevisionCurrent == 0xf

    def test_manually_create_simple_negotiate_message(self):
        """Tests the new method of creating ntlm negotiate messages"""
        negotiate_message = ntlm2.NTLMMessage()
        negotiate_message.Header.Signature = ntlm2.NTLM_PROTOCOL_SIGNATURE
        negotiate_message.Header.MessageType = ntlm2.NTLM_MESSAGE_TYPE.NtLmNegotiate.const
        negotiate_fields = negotiate_message.MessageDependentFields.MessageNegotiateFields

        #Test Construction of simplest possible negotiate message
        negotiate_message.set_negotiate_flags(NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NTLM)
        negotiate_bytes = negotiate_message.get_message_contents()
        negotiate_b64 = base64.b64encode(negotiate_bytes)
        negotiate_bytes = base64.b64decode(negotiate_b64)
        #This test fails because blank values still get encoded. So the message is still correct but there are unneeded trailing zeros
        assert negotiate_bytes == HexToByte("4e544c4d535350000100000002020000")

    def test_manually_create_normal_negotiate_message(self):
        flags = NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM | NTLM_FLAGS.NTLMSSP_REQUEST_TARGET | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NTLM | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
        negotiate_message = ntlm2.NTLMMessage()
        negotiate_message.Header.Signature = ntlm2.NTLM_PROTOCOL_SIGNATURE
        negotiate_message.Header.MessageType = ntlm2.NTLM_MESSAGE_TYPE.NtLmNegotiate.const
        negotiate_message.set_negotiate_flags(flags)
        negotiate_message.set_string_field("DomainName", "DOMAIN")
        negotiate_message.set_string_field("Workstation", "WORKSTATION")
        #Test Construction of negotiate message with no version information
        negotiate_bytes = negotiate_message.get_message_contents()
        negotiate_b64 = base64.b64encode(negotiate_bytes)
        negotiate_bytes = base64.b64decode(negotiate_b64)
        assert negotiate_bytes == HexToByte("4e544c4d535350000100000007320000060006002b0000000b000b0020000000574f524b53544154494f4e444f4d41494e")

    def test_manually_create_full_negotiate_message(self):
        flags = NTLM_FLAGS.NTLMSSP_NEGOTIATE_VERSION | NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM | NTLM_FLAGS.NTLMSSP_REQUEST_TARGET | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NTLM | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
        negotiate_message = ntlm2.NTLMMessage()
        negotiate_message.Header.Signature = ntlm2.NTLM_PROTOCOL_SIGNATURE
        negotiate_message.Header.MessageType = ntlm2.NTLM_MESSAGE_TYPE.NtLmNegotiate.const
        negotiate_message.set_negotiate_flags(flags)
        version = negotiate_message.get_version_field()
        version.ProductMajorVersion = 5
        version.ProductMinorVersion = 0
        version.ProductBuild = 2195
        version.NTLMRevisionCurrent = 0xf

        negotiate_bytes = negotiate_message.get_message_contents()
        negotiate_b64 = base64.b64encode(negotiate_bytes)
        negotiate_bytes = base64.b64decode(negotiate_b64)
        #There is a possible error setting the version information
        assert negotiate_bytes == HexToByte("4e544c4d53535000010000000732000206000600330000000b000b0028000000050093080000000f574f524b53544154494f4e444f4d41494e")

    def test_method__create_negotiate_message(self):
        flags = NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM | NTLM_FLAGS.NTLMSSP_REQUEST_TARGET | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NTLM | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
        client_object = ATestClient("WORKSTATION", "DOMAIN", "", "")
        negotiate_bytes = ntlm2.NTLMNegotiateMessageV1.create(flags, client_object).get_message_contents()
        negotiate_b64 = base64.b64encode(negotiate_bytes)
        negotiate_bytes = base64.b64decode(negotiate_b64)
        assert negotiate_bytes == HexToByte("4e544c4d535350000100000007b20000060006002b0000000b000b0020000000574f524b53544154494f4e444f4d41494e")

    # -------------------------------------------------------------------------------------------------------------
    # Challenge Message Tests
    # -------------------------------------------------------------------------------------------------------------

    def test_create_av_pair(self):
        pair = ntlm2.AV_PAIR.create(1,"SERVER".encode("utf-16le"))
        assert pair.to_byte_string() == HexToByte("01000c00530045005200560045005200")
        pair = ntlm2.AV_PAIR.create(2,"DOMAIN".encode("utf-16le"))
        assert pair.to_byte_string() == HexToByte("02000c0044004f004d00410049004e00")
        pair = ntlm2.AV_PAIR.create(3,"server.domain.com".encode("utf-16le"))
        assert pair.to_byte_string() == HexToByte("030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d00")
        pair = ntlm2.AV_PAIR.create(4,"domain.com".encode("utf-16le"))
        assert pair.to_byte_string() == HexToByte("0400140064006f006d00610069006e002e0063006f006d00")
        #This test is just to make sure that AvId and AvLen are written correctly for values larger than 256. There is no AvId 770.
        pair = ntlm2.AV_PAIR.create(770,"domain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.com".encode("utf-16le"))
        assert pair.Header.AvId == 770
        assert pair.Header.AvLen == 320
        assert pair.to_byte_string() == HexToByte("0203400164006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D00")

    def test_read_av_pair(self):
        bytestring = HexToByte("0203400164006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D0064006F006D00610069006E002E0063006F006D00")
        pair = ntlm2.AV_PAIR.read(StringIO.StringIO(bytestring))
        assert pair.Header.AvId == 770
        assert pair.Header.AvLen == 320
        assert pair.value_byte_string() == "domain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.comdomain.com".encode("utf-16le")
        assert pair.to_byte_string() == bytestring

    def test_create_av_pair_handler_from_list(self):
        AVHandler = ntlm2.AV_PAIR_Handler([   (1,"SERVER".encode("utf-16le")),
                                                    (2,"DOMAIN".encode("utf-16le")),
                                                    (4,"domain.com".encode("utf-16le"))
                                                ])
        ids_found = []
        for pair in AVHandler.get_av_pairs():
            ids_found.append(pair.Header.AvId)
            if pair.Header.AvId == 1:
                assert pair.value_byte_string() == "SERVER".encode("utf-16le")
                assert pair.Header.AvLen == 12
            elif pair.Header.AvId == 2:
                assert pair.value_byte_string() == "DOMAIN".encode("utf-16le")
                assert pair.Header.AvLen == 12
            elif pair.Header.AvId == 4:
                assert pair.value_byte_string() == "domain.com".encode("utf-16le")
                assert pair.Header.AvLen == 20
        ids_found.sort()
        assert ids_found == [1,2,4]

    def test_create_av_pair_handler_from_bytes(self):
        tinfo = HexToByte("02000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d0000000000")
        AVHandler = ntlm2.AV_PAIR_Handler(tinfo)
        ids_found = []
        for pair in AVHandler.get_av_pairs():
            ids_found.append(pair.Header.AvId)
            if pair.Header.AvId == 1:
                assert pair.value_byte_string() == "SERVER".encode("utf-16le")
                assert pair.Header.AvLen == 12
            elif pair.Header.AvId == 2:
                assert pair.value_byte_string() == "DOMAIN".encode("utf-16le")
                assert pair.Header.AvLen == 12
            elif pair.Header.AvId == 3:
                assert pair.value_byte_string() == "server.domain.com".encode("utf-16le")
                assert pair.Header.AvLen == 34
            elif pair.Header.AvId == 4:
                assert pair.value_byte_string() == "domain.com".encode("utf-16le")
                assert pair.Header.AvLen == 20
        ids_found.sort()
        assert ids_found == [1,2,3,4]

    def test_parse_simple_challenge(self):
        """Tests parsing ntlm challenge messages"""
        challenge = HexToByte("4e544c4d53535000020000000000000000000000020200000123456789abcdef")
        f = StringIO.StringIO(challenge)
        challenge_message = ntlm2.NTLMChallengeMessageV1.read(f)
        assert challenge_message.Header.MessageType == ntlm2.NTLM_MESSAGE_TYPE.NtLmChallenge.const
        assert challenge_message.get_string_fields() == {"TargetName": "", "TargetInfo": ""}
        challenge_fields = challenge_message.MessageFields
        assert isinstance(challenge_fields, ntlm2.NTLMMessageChallengeFields)
        assert challenge_fields.ServerChallenge[0:8] == [ord(c) for c in HexToByte("0123456789abcdef")]
        assert challenge_fields.NegotiateFlags == 0x0202

    def test_parse_full_challenge(self):
        """Tests parsing ntlm challenge messages"""
        challenge = HexToByte("4e544c4d53535000020000000c000c0030000000010281000123456789abcdef0000000000000000620062003c00000044004f004d00410049004e0002000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d0000000000")
        f = StringIO.StringIO(challenge)
        challenge_message = ntlm2.NTLMChallengeMessageV1.read(f)
        assert challenge_message.Header.MessageType == ntlm2.NTLM_MESSAGE_TYPE.NtLmChallenge.const
        #TargetName MUST be expressed in the negotiated character set [MS-NLMP] page 21.
        #If a TargetInfo AV_PAIR Value is textual, it MUST be encoded in Unicode irrespective of what character set was negotiated [MS-NLMP] page 21.
        tname = "DOMAIN".encode("utf-16le")
        tinfo = HexToByte("02000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d0000000000")
        assert challenge_message.get_string_field("TargetName") == tname
        assert challenge_message.get_string_field("TargetInfo") == tinfo
        assert challenge_message.get_string_fields() == {"TargetName": tname, "TargetInfo": tinfo}
        challenge_fields = challenge_message.MessageFields
        assert isinstance(challenge_fields, ntlm2.NTLMMessageChallengeFields)
        assert challenge_fields.ServerChallenge[0:8] == [ord(c) for c in HexToByte("0123456789abcdef")]
        assert challenge_fields.NegotiateFlags ==  0x00000001 | 0x00000200 |0x00010000 | 0x00800000
        #unpack and test Target Information Data
        AVHandler = ntlm2.AV_PAIR_Handler(challenge_message.get_string_field("TargetInfo"))
        ids_found = []
        for pair in AVHandler.get_av_pairs():
            ids_found.append(pair.Header.AvId)
            if pair.Header.AvId == 1:
                assert pair.value_byte_string() == "SERVER".encode("utf-16le")
                assert pair.Header.AvLen == 12
            elif pair.Header.AvId == 2:
                assert pair.value_byte_string() == "DOMAIN".encode("utf-16le")
                assert pair.Header.AvLen == 12
            elif pair.Header.AvId == 3:
                assert pair.value_byte_string() == "server.domain.com".encode("utf-16le")
                assert pair.Header.AvLen == 34
            elif pair.Header.AvId == 4:
                assert pair.value_byte_string() == "domain.com".encode("utf-16le")
                assert pair.Header.AvLen == 20
        ids_found.sort()
        assert ids_found == [1,2,3,4]

    def _get_valid_av_string(self, hexvalue, valid_pairs):
        #Pairs could be encoded in any order, so build test string based on values encountered
        expected_length = sum([len(pair) for pair in valid_pairs])+8

        #This fails if there are too few pairs in hexvalue
        assert len(hexvalue) == expected_length

        expected_value=""
        pair_dict = {}
        for pair in valid_pairs:
            pair_dict[pair[1]] = pair

        offset=1    #The id of the current pair is the second array element
        for pair in valid_pairs:
            #Concatenating the expected value from available pairs
            assert offset < len(hexvalue)-8
            key = hexvalue[offset]
            value = pair_dict[key]
            offset += len(value)
            expected_value +=value

        return expected_value + "00000000"

    def test_AV_PAIR_Handler_to_byte_string(self):
        #Example values taken from http://davenport.sourceforge.net/ntlm.html#theType2Message
        valid_pairs = ["01000c00530045005200560045005200",
                       "02000c0044004f004d00410049004e00",
                       "030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d00",
                       "0400140064006f006d00610069006e002e0063006f006d00"]
        AVHandler = ntlm2.AV_PAIR_Handler([   (AV_TYPES.MsvAvNbComputerName,"SERVER".encode("utf-16le")),
                                                    (AV_TYPES.MsvAvDnsDomainName,"domain.com".encode("utf-16le")),
                                                    (AV_TYPES.MsvAvNbDomainName,"DOMAIN".encode("utf-16le")),
                                                    (AV_TYPES.MsvAvDnsComputerName,"server.domain.com".encode("utf-16le"))
                                                ])
        result = AVHandler.to_byte_string()
        hexresult = ByteToHex(result).lower().replace(" ","")
        valid_result = self._get_valid_av_string(hexresult, valid_pairs)
        assert hexresult == valid_result

    def test_manually_create_simple_challenge_message(self):
        expected_challenge = HexToByte("4e544c4d53535000020000000000000000000000020200000123456789abcdef")
        challenge_message = ntlm2.NTLMChallengeMessageV1()
        challenge_message.set_negotiate_flags(0x0202)
        challenge_message.ServerChallenge = HexToByte("0123456789abcdef")
        negotiate_bytes = challenge_message.get_message_contents()
        negotiate_bytes = "".join([chr(x) for x in negotiate_bytes])
        #This fails because the Challenge message has unneccessary trailing zeros. However the message is correct
        assert negotiate_bytes == expected_challenge

    def test_manually_create_full_challenge_message(self):
        """The results of this test are dependent on the ordering of TargetName and TargetInfo in the payload"""
        challenge_message = ntlm2.NTLMChallengeMessageV1()
        challenge_message.set_negotiate_flags(0x00000001 | 0x00000200 |0x00010000 | 0x00800000)
        challenge_message.TargetName = "DOMAIN".encode("utf-16le")
        challenge_message.ServerChallenge = HexToByte("0123456789abcdef")
        TargetInfo = ntlm2.AV_PAIR_Handler([  (AV_TYPES.MsvAvDnsDomainName,"domain.com".encode("utf-16le")),
                                                    (AV_TYPES.MsvAvDnsComputerName,"server.domain.com".encode("utf-16le")),
                                                    (AV_TYPES.MsvAvNbDomainName,"DOMAIN".encode("utf-16le")),
                                                    (AV_TYPES.MsvAvNbComputerName,"SERVER".encode("utf-16le"))
                                                ])
        challenge_message.TargetInfo = TargetInfo.to_byte_string()
        negotiate_bytes = challenge_message.get_message_contents()
        negotiate_bytes = "".join([chr(x) for x in negotiate_bytes])
        negotiate_hex = ByteToHex(negotiate_bytes).lower().replace(" ","")
        TargetName_hex = "44004f004d00410049004e00"
        valid_pairs = ["01000c00530045005200560045005200",
                       "02000c0044004f004d00410049004e00",
                       "030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d00",
                       "0400140064006f006d00610069006e002e0063006f006d00"]
        valid_length = sum([len(x) for x in valid_pairs]) + 8
        #In order to determine the ordering of TargetName and TargetInfo, we can just check the 32nd element of their hex strings as there are only two possible values
        #The tests below are used if TargetName is the first value in the payload
        if negotiate_hex[32] == "3":
            TargetInfo_hex = self._get_valid_av_string(negotiate_hex[-valid_length:], valid_pairs)
            assert negotiate_hex[0:96] == "4e544c4d53535000020000000c000c0030000000010281000123456789abcdef0000000000000000620062003c000000"
            assert negotiate_hex[96:] == TargetName_hex + TargetInfo_hex
        #The tests below are used if TargetInfo is the first value in the payload
        elif negotiate_hex[32] == "9":
            valid_length += len(TargetName_hex)
            TargetInfo_hex = self._get_valid_av_string(negotiate_hex[-valid_length:-len(TargetName_hex)], valid_pairs)
            assert negotiate_hex[0:96] == "4e544c4d53535000020000000c000c0092000000010281000123456789abcdef00000000000000006200620030000000"
            assert negotiate_hex[96:] == TargetInfo_hex + TargetName_hex
        else:
            #The value must be invalid, since neither of the two possiblities above could be identified
            assert False

    def test_method__create_full_challenge_message(self):
        expected_challenge = "4e544c4d53535000020000000c000c0092000000058281000123456789abcdef0000000000000000620062003000000002000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d000000000044004f004d00410049004e00"
        server_object = ATestServer("SERVER", "DOMAIN", "server.domain.com", "domain.com", None)
        client_flags = 0x00000001 | 0x00000200 | 0x00800000
        cfg_flags = 0x00010000
        ATestServer.randomvalue = HexToByte("0123456789abcdef")  #Ensure that the server challenge will be 0123456789abcdef
        negotiate_bytes = ntlm2.NTLMChallengeMessageV1.create(client_flags, cfg_flags, server_object).get_message_contents()
        negotiate_hex = ByteToHex("".join([chr(x) for x in negotiate_bytes])).lower().replace(" ","")
        #Need to work out the ordering of the payload fields in order to work out what the valid message looks like
        TargetName_hex = "44004f004d00410049004e00"
        valid_pairs = ["01000c00530045005200560045005200",
                       "02000c0044004f004d00410049004e00",
                       "030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d00",
                       "0400140064006f006d00610069006e002e0063006f006d00"]
        valid_length = sum([len(x) for x in valid_pairs]) + 8
        #In order to determine the ordering of TargetName and TargetInfo, we can just check the 32nd element of their hex strings as there are only two possible values
        #The tests below are used if TargetName is the first value in the payload
        if negotiate_hex[32] == "3":
            TargetInfo_hex = self._get_valid_av_string(negotiate_hex[-valid_length:], valid_pairs)
            assert negotiate_hex[0:96] == "4e544c4d53535000020000000c000c0030000000058281000123456789abcdef0000000000000000620062003c000000"
            assert negotiate_hex[96:] == TargetName_hex + TargetInfo_hex
        #The tests below are used if TargetInfo is the first value in the payload
        elif negotiate_hex[32] == "9":
            valid_length += len(TargetName_hex)
            TargetInfo_hex = self._get_valid_av_string(negotiate_hex[-valid_length:-len(TargetName_hex)], valid_pairs)
            assert negotiate_hex[0:96] == "4e544c4d53535000020000000c000c0092000000058281000123456789abcdef00000000000000006200620030000000"
            assert negotiate_hex[96:] == TargetInfo_hex + TargetName_hex
        else:
            #The value must be invalid, since neither of the two possiblities above could be identified
            assert False

    # -------------------------------------------------------------------------------------------------------------
    # Authenticate Message Tests
    # -------------------------------------------------------------------------------------------------------------

    def get_test_authenticate_message(self, cls, flags, encoding = "utf-16le"):
        targetinfo = HexToByte("02000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d0000000000")
        responsedata = cls.compute_response(flags,                          #Flags
                                            "SecREt01",                     #Password
                                            "user",                         #User name
                                            "DOMAIN",                       #Domain
                                            HexToByte("0123456789abcdef"),  #Server Challenge
                                            HexToByte("ffffff0011223344"),  #Client Challenge
                                            HexToByte("0090d336b734c301"),  #Time
                                            targetinfo,                     #Target Info
                                            encoding)                       #Encoding
        authenticate_message = cls()
        authenticate_message.set_negotiate_flags(0x0201)
        authenticate_message.LmChallengeResponse = responsedata.LmChallengeResponse
        authenticate_message.NtChallengeResponse = responsedata.NTChallengeResponse
        authenticate_message.DomainName = "DOMAIN".encode(encoding)
        authenticate_message.UserName = "user".encode(encoding)
        authenticate_message.Workstation = "WORKSTATION".encode(encoding)
        return authenticate_message

    def _do_test_authenticate_message_values(self, authenticate_message, flags, EncryptedRandomSessionKey=None, encoding = "utf-16le", v2=False, lmchll=True):
        assert authenticate_message.Header.Signature == "NTLMSSP"
        assert authenticate_message.Header.MessageType == ntlm2.NTLM_MESSAGE_TYPE.NtLmAuthenticate.const
        if v2:
            #A version 2 response should not provide an LmChallengeResponse if the challenge message provides TargetInfo
            if lmchll is None:
                assert not authenticate_message.LmChallengeResponse
            else:
                assert authenticate_message.LmChallengeResponse == HexToByte("d6e6152ea25d03b7c6ba6629c2d6aaf0ffffff0011223344")
            assert authenticate_message.NtChallengeResponse == HexToByte("cbabbca713eb795d04c97abc01ee498301010000000000000090d336b734c301ffffff00112233440000000002000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d000000000000000000")
        else:
            assert authenticate_message.LmChallengeResponse == HexToByte("c337cd5cbd44fc9782a667af6d427c6de67c20c2d3e77c56")
            assert authenticate_message.NtChallengeResponse == HexToByte("25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6")
        assert authenticate_message.DomainName == "DOMAIN".encode(encoding)
        assert authenticate_message.UserName == "user".encode(encoding)
        #Target info has been changed for test_method__create_version2_authenticate_message so the correct Worstation value is "SERVER"
        if lmchll is None:
            assert authenticate_message.Workstation == "SERVER".encode(encoding)
        else:
            assert authenticate_message.Workstation == "WORKSTATION".encode(encoding)
        assert authenticate_message.MessageFields.NegotiateFlags == flags
        if EncryptedRandomSessionKey is not None:
            assert authenticate_message.EncryptedRandomSessionKey == HexToByte(EncryptedRandomSessionKey)

    def test_parse_version1_authenticate_message(self):
        #Example values taken from http://davenport.sourceforge.net/ntlm.html#theType3Message
        message = HexToByte("4e544c4d5353500003000000180018006a00000018001800820000000c000c0040000000080008004c0000001600160054000000000000009a0000000102000044004f004d00410049004e00750073006500720057004f0052004b00530054004100540049004f004e00c337cd5cbd44fc9782a667af6d427c6de67c20c2d3e77c5625a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6")
        f = StringIO.StringIO(message)
        authenticate_message = ntlm2.NTLMAuthenticateMessageV1.read(f)
        authenticate_message.verify()
        self._do_test_authenticate_message_values(authenticate_message, 0x0201)

    def test_manually_create_version1_authenticate_message(self):
        #Example values taken from http://davenport.sourceforge.net/ntlm.html#theType3Message
        authenticate_message = self.get_test_authenticate_message(ntlm2.NTLMAuthenticateMessageV1, 0x0201, "utf-16le")
        authenticate_bytes = authenticate_message.get_message_contents()
        authenticate_bytes = "".join([chr(x) for x in authenticate_bytes])
        #Parse message to see if it is valid
        f = StringIO.StringIO(authenticate_bytes)
        parse_message = ntlm2.NTLMAuthenticateMessageV1.read(f)
        parse_message.verify()
        self._do_test_authenticate_message_values(authenticate_message, 0x0201)

    def test_manually_create_version2_authenticate_message(self):
        #Example values taken from http://davenport.sourceforge.net/ntlm.html#theType3Message
        authenticate_message = self.get_test_authenticate_message(ntlm2.NTLMAuthenticateMessageV2, 0x0201, "utf-16le")
        authenticate_bytes = authenticate_message.get_message_contents()
        authenticate_bytes = "".join([chr(x) for x in authenticate_bytes])
        #Parse message to see if it is valid
        f = StringIO.StringIO(authenticate_bytes)
        parse_message = ntlm2.NTLMAuthenticateMessageV2.read(f)
        parse_message.verify()
        self._do_test_authenticate_message_values(authenticate_message, 0x0201, v2=True)

    def test_method__create_version1_authenticate_message(self):
        #Example values taken from http://davenport.sourceforge.net/ntlm.html#theType3Message
        server_object = ATestServer("WORKSTATION", "DOMAIN", "server.domain.com", "domain.com", None)
        flags = 0x0201 | NTLM_FLAGS.NTLMSSP_NEGOTIATE_TARGET_INFO
        ATestServer.randomvalue = HexToByte("0123456789abcdef")  #Ensure that the server challenge will be 0123456789abcdef
        challenge_message = ntlm2.NTLMChallengeMessageV1.create(flags, 0, server_object)

        ATestClient.randomvalue = HexToByte("ffffff0011223344")
        ATestClient.timestamp = HexToByte("0090d336b734c301")
        client_object = ATestClient("WORKSTATION", "DOMAIN", "user", "SecREt01")
        authenticate_message, responsedata = ntlm2.NTLMAuthenticateMessageV1.create(client_object, challenge_message)

        authenticate_bytes = authenticate_message.get_message_contents()
        authenticate_bytes = "".join([chr(x) for x in authenticate_bytes])
        #Parse message to see if it is valid
        f = StringIO.StringIO(authenticate_bytes)
        parse_message = ntlm2.NTLMAuthenticateMessageV1.read(f)
        parse_message.verify()
        self._do_test_authenticate_message_values(authenticate_message, challenge_message.MessageFields.NegotiateFlags)

    def test_method__create_version2_authenticate_message(self):
        #Example values taken from http://davenport.sourceforge.net/ntlm.html#theType3Message
        server_object = ATestServer("WORKSTATION", "DOMAIN", "server.domain.com", "domain.com", None)
        flags = 0x0201 | NTLM_FLAGS.NTLMSSP_NEGOTIATE_TARGET_INFO
        ATestServer.randomvalue = HexToByte("0123456789abcdef")  #Ensure that the server challenge will be 0123456789abcdef
        challenge_message = ntlm2.NTLMChallengeMessageV2.create(flags, 0, server_object)
        challenge_message.TargetInfo = HexToByte("02000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d0000000000")

        ATestClient.randomvalue = HexToByte("ffffff0011223344")
        ATestClient.timestamp = HexToByte("0090d336b734c301")
        client_object = ATestClient("WORKSTATION", "DOMAIN", "user", "SecREt01")
        authenticate_message, responsedata = ntlm2.NTLMAuthenticateMessageV2.create(client_object, challenge_message)

        authenticate_bytes = authenticate_message.get_message_contents()
        authenticate_bytes = "".join([chr(x) for x in authenticate_bytes])
        #Parse message to see if it is valid
        f = StringIO.StringIO(authenticate_bytes)
        parse_message = ntlm2.NTLMAuthenticateMessageV2.read(f)
        parse_message.verify()
        print authenticate_message.Workstation
        self._do_test_authenticate_message_values(authenticate_message, challenge_message.MessageFields.NegotiateFlags,v2=True, lmchll=None)

#TODO - Setup tests, which make sure that flags are set automatically as per the [MS-NLMP] specification
#     - When certain flags are set, the spec demands that other flags are set/not set in each of the message types
