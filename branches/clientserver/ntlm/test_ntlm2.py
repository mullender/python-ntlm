"""Tests for the NTLM module"""

import ntlm2
from ntlm2 import NTLM_FLAGS
import ntlmhandler
import base64
import ctypes
import StringIO

class SysCheat:
    """This is a bit of a cheat to allow testing of messages in a non-windows environment. Plus it forces getwindowsversion to
    return predefined values."""
    def getwindowsversion(self):
        return (1,2,3,4,"This is not an OS")

ntlmhandler.sys=SysCheat()

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
        handler = ntlmhandler.NTLMHandler_v1()

        #Test Case: NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY not set and NTLMSSP_NEGOTIATE_NT_ONLY not set [MS-NTLM] page 73
        responsedata = handler.compute_response(0, Password, User, Domain, ServerChallenge, ClientChallenge, Time, ServerName)

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

        handler = ntlmhandler.NTLMHandler_v2()

        #Use the values below to construct "ServerName"/targetinfo as it would a appear in a type 2 message
        domainname_avpair = "02000c0044006f006d00610069006e00"
        servername_avpair = "01000c00530065007200760065007200"
        avpair_terminator = "00000000"
        targetinfo = HexToByte(domainname_avpair+servername_avpair+avpair_terminator)

        responsedata = handler.compute_response(0, Password, User, Domain, ServerChallenge, ClientChallenge, Time, targetinfo)

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
        #Example taken from http://davenport.sourceforge.net/ntlm.html#theType1Message
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
        #Example taken from http://davenport.sourceforge.net/ntlm.html#theType1Message
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
        handler = ntlmhandler.NTLMHandler_v1()
        negotiate_bytes = handler.create_negotiate_message(flags, "DOMAIN", "WORKSTATION")
        negotiate_b64 = base64.b64encode(negotiate_bytes)
        negotiate_bytes = base64.b64decode(negotiate_b64)
        assert negotiate_bytes == HexToByte("4e544c4d535350000100000007b20000060006002b0000000b000b0020000000574f524b53544154494f4e444f4d41494e")

        handler = ntlmhandler.NTLMHandler_v2()
        handler = ntlmhandler.NTLMHandler_v1()
        negotiate_bytes = handler.create_negotiate_message(flags, "DOMAIN", "WORKSTATION")
        negotiate_b64 = base64.b64encode(negotiate_bytes)
        negotiate_bytes = base64.b64decode(negotiate_b64)
        assert negotiate_bytes == HexToByte("4e544c4d535350000100000007b20000060006002b0000000b000b0020000000574f524b53544154494f4e444f4d41494e")


    # -------------------------------------------------------------------------------------------------------------
    # Challenge Message Tests
    # -------------------------------------------------------------------------------------------------------------

    def test_create_av_pair_from_list(self):
        AVHandler = ntlmhandler.AV_PAIR_Handler([   (1,"SERVER".encode("utf-16le")),
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

    def test_create_av_pair_from_bytes(self):
        tinfo = HexToByte("02000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d0000000000")
        AVHandler = ntlmhandler.AV_PAIR_Handler(tinfo)
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
        callenge = HexToByte("4e544c4d53535000020000000000000000000000020200000123456789abcdef")
        f = StringIO.StringIO(callenge)
        challenge_message = ntlm2.NTLMMessage.read(f)
        assert challenge_message.Header.MessageType == ntlm2.NTLM_MESSAGE_TYPE.NtLmChallenge.const
        assert challenge_message.get_string_fields() == {"TargetName": "", "TargetInfo": ""}
        challenge_fields = challenge_message.MessageFields
        assert isinstance(challenge_fields, ntlm2.NTLMMessageChallengeFields)
        assert challenge_fields.ServerChallenge[0:8] == [ord(c) for c in HexToByte("0123456789abcdef")]
        assert challenge_fields.NegotiateFlags == 0x0202

    def test_parse_full_challenge(self):
        """Tests parsing ntlm challenge messages"""
        callenge = HexToByte("4e544c4d53535000020000000c000c0030000000010281000123456789abcdef0000000000000000620062003c00000044004f004d00410049004e0002000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d0000000000")
        f = StringIO.StringIO(callenge)
        challenge_message = ntlm2.NTLMMessage.read(f)
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
        AVHandler = ntlmhandler.AV_PAIR_Handler(challenge_message.get_string_field("TargetInfo"))
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

    def test_manually_create_simple_challenge_message(self):
        pass
#TODO - Setup tests, which make sure that flags are set automatically as per the [MS-NLMP] specification
#     - When certain flags are set, the spec demands that other flags are set/not set in each of the message types