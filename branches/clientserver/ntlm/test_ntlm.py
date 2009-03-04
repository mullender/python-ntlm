"""Tests for the NTLM module"""

import ntlm
import ntlm2
import base64
import ctypes
import StringIO

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
    """Tests from example at http://www.innovation.ch/personal/ronald/ntlm.html"""
    @classmethod
    def setup_class(cls):
        """Sets up the methods for testing"""
        cls.old_gethostname = ntlm.gethostname
        cls.expectedhostname = "LightCity"
        ntlm.gethostname = cls.gethostname

    @classmethod
    def teardown_class(cls):
        ntlm.gethostname = cls.old_gethostname

    @classmethod
    def gethostname(cls):
        return cls.expectedhostname

    def test_hash_functions(self):
        """Test underlying hash functions"""
        ServerChallenge = HexToByte("01 23 45 67 89 ab cd ef")
        ClientChallenge = '\xaa'*8
        Time = '\x00'*8
        Workstation = "COMPUTER".encode('utf-16-le')
        ServerName = "Server".encode('utf-16-le')
        User = "User"
        Domain = "Domain"
        Password = "Password"
        RandomSessionKey = '\55'*16
        assert HexToByte("e52cac67 419a9a22 4a3b108f 3fa6cb6d") == ntlm.create_LM_hashed_password_v1(Password) # [MS-NLMP] page 72
        assert HexToByte("a4f49c40 6510bdca b6824ee7 c30fd852") == ntlm.create_NT_hashed_password_v1(Password) # [MS-NLMP] page 73
        assert HexToByte("d87262b0 cde4b1cb 7499becc cdf10784") == ntlm.create_sessionbasekey(Password)
        NTHashedPassword = ntlm.create_NT_hashed_password_v1(Password)
        assert HexToByte("67c43011 f30298a2 ad35ece6 4f16331c 44bdbed9 27841f94") == ntlm.calc_resp(NTHashedPassword, ServerChallenge)
        LMHashedPassword = ntlm.create_LM_hashed_password_v1(Password)
        assert HexToByte("98def7b8 7f88aa5d afe2df77 9688a172 def11c7d 5ccdef13") == ntlm.calc_resp(LMHashedPassword, ServerChallenge)
        
        (NTLMv1Response,LMv1Response) = ntlm.ntlm2sr_calc_resp(ntlm.create_NT_hashed_password_v1(Password), ServerChallenge, ClientChallenge)
        assert HexToByte("aaaaaaaa aaaaaaaa 00000000 00000000 00000000 00000000") == LMv1Response  # [MS-NLMP] page 75
        assert HexToByte("7537f803 ae367128 ca458204 bde7caf8 1e97ed26 83267232") == NTLMv1Response
        
        assert HexToByte("0c868a40 3bfd7a93 a3001ef2 2ef02e3f") == ntlm.create_NT_hashed_password_v2(Password, User, Domain) # [MS-NLMP] page 76
        ResponseKeyLM = ResponseKeyNT = ntlm.create_NT_hashed_password_v2(Password, User, Domain)
        (NTLMv2Response,LMv2Response) = ntlm.ComputeResponse(ResponseKeyNT, ResponseKeyLM, ServerChallenge, ServerName, ClientChallenge, Time)
        assert HexToByte("86c35097 ac9cec10 2554764a 57cccc19 aaaaaaaa aaaaaaaa") == LMv2Response  # [MS-NLMP] page 76
        
        # expected failure
        # According to the spec in section '3.3.2 NTLM v2 Authentication' the NTLMv2Response should be longer than the value given on page 77 (this suggests a mistake in the spec)
        #~ assert HexToByte("68cd0ab8 51e51c96 aabc927b ebef6a1c") == NTLMv2Response, "\nExpected: 68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c\nActual:   %s" % ByteToHex(NTLMv2Response) # [MS-NLMP] page 77

    def test_old_hash_functions(self):
        """tests the old hash function calculators"""
        lmowf = ntlm.create_LM_hashed_password_v1("Password") # MS-NLMP 4.2.2.1.1
        assert lmowf == HexToByte("e5 2c ac 67 41 9a 9a 22 4a 3b 10 8f 3f a6 cb 6d")
        ntowf = ntlm.create_NT_hashed_password_v1("Password") # MS-NLMP 4.2.2.1.2
        assert ntowf == HexToByte("a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52")
        sbk = ntlm.create_sessionbasekey("Password") # MS-NLMP 4.2.2.1.3
        assert sbk == HexToByte("d8 72 62 b0 cd e4 b1 cb 74 99 be cc cd f1 07 84")
        nonce = HexToByte("01 23 45 67 89 ab cd ef")
        nt_challenge_response = ntlm.calc_resp(ntowf, nonce) # MS-NLMP 4.2.2.2.1
        assert nt_challenge_response == HexToByte("67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c  44 bd be d9 27 84 1f 94")
        lm_challenge_response = ntlm.calc_resp(lmowf, nonce) # MS-NLMP 4.2.2.2.2
        assert lm_challenge_response == HexToByte("98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72  de f1 1c 7d 5c cd ef 13")
        # TODO: NTLMSSP_NEGOTIATE_LM_KEY is set: b0 9e 37 9f 7f be cb 1e af 0a fd cb 03 83 c8 a0
        # TODO: 4.2.2.2.3 Encrypted Session Key

    def test_old_create_negotiate(self):
        """Tests the create_NTLM_NEGOTIATE_MESSAGE"""
        created_negotiate_b64 = ntlm.create_NTLM_NEGOTIATE_MESSAGE("Ursa-Minor\\Zaphod")
        f = StringIO.StringIO(base64.b64decode(created_negotiate_b64))
        negotiate_message = ntlm2.NTLMMessage.read(f)
        negotiate_message.verify()
        assert negotiate_message.Header.MessageType == ntlm2.NTLM_MESSAGE_TYPE.NtLmNegotiate.const
        assert negotiate_message.get_string_field("Workstation") == "LIGHTCITY"
        assert negotiate_message.get_string_fields() == {"DomainName": "URSA-MINOR", "Workstation": "LIGHTCITY"}
        version = negotiate_message.get_version_field()
        assert version is not None
        assert version.ProductMajorVersion == 5
        assert version.ProductMinorVersion == 1
        assert version.ProductBuild == 2600
        assert version.NTLMRevisionCurrent == 0xf
        # final check that we have the exact binary result we expect
        assert created_negotiate_b64 == "TlRMTVNTUAABAAAAB7IIogoACgAxAAAACQAJACgAAAAFASgKAAAAD0xJR0hUQ0lUWVVSU0EtTUlOT1I="

    def test_parse_negotiate(self):
        """Tests parsing the ntlm negotiate message"""
        # the sample message from the docs
        sample_negotiate_b64_1 = "TlRMTVNTUAABAAAAA7IAAAoACgApAAAACQAJACAAAABMSUdIVENJVFlVUlNBLU1JTk9S"
        # what ntlm.create_message produces
        sample_negotiate_b64_2 = "TlRMTVNTUAABAAAAB7IIogoACgAxAAAACQAJACgAAAAFASgKAAAAD0xJR0hUQ0lUWVVSU0EtTUlOT1I="
        for negotiate_b64 in [sample_negotiate_b64_1, sample_negotiate_b64_2]:
            f = StringIO.StringIO(base64.b64decode(negotiate_b64))
            negotiate_message = ntlm2.NTLMMessage.read(f)
            assert negotiate_message.Header.MessageType == ntlm2.NTLM_MESSAGE_TYPE.NtLmNegotiate.const
            assert isinstance(negotiate_message.MessageFields, ntlm2.NTLMMessageNegotiateFields)
            assert negotiate_message.get_string_field("Workstation") == "LIGHTCITY"
            assert negotiate_message.get_string_fields() == {"DomainName": "URSA-MINOR", "Workstation": "LIGHTCITY"}
            version = negotiate_message.get_version_field()
            if negotiate_b64 == sample_negotiate_b64_2:
                assert version.ProductMajorVersion == 5
                assert version.ProductMinorVersion == 1
                assert version.ProductBuild == 2600
                assert version.NTLMRevisionCurrent == 0xf

    def test_create_negotiate(self):
        """Tests the new method of creating ntlm negotiate messages"""
        negotiate_message = ntlm2.NTLMMessage()
        negotiate_message.Header.Signature = ntlm2.NTLM_PROTOCOL_SIGNATURE
        negotiate_message.Header.MessageType = ntlm2.NTLM_MESSAGE_TYPE.NtLmNegotiate.const
        negotiate_fields = negotiate_message.MessageDependentFields.MessageNegotiateFields
        negotiate_fields.NegotiateFlags = 0xb203
        negotiate_message.set_string_field("DomainName", "URSA-MINOR")
        negotiate_message.set_string_field("Workstation", "LIGHTCITY")
        negotiate_bytes = negotiate_message.get_message_contents()
        negotiate_b64 = base64.b64encode(negotiate_bytes)
        expected_b64 = "TlRMTVNTUAABAAAAA7IAAAoACgApAAAACQAJACAAAABMSUdIVENJVFlVUlNBLU1JTk9S"
        expected_bytes = base64.b64decode(expected_b64)
        f = StringIO.StringIO(expected_bytes)
        expected_message = ntlm2.NTLMMessage.read(f)
        assert negotiate_b64 == expected_b64

    def test_create_negotiate_class(self):
        """Tests the new method of creating ntlm negotiate messages"""
        negotiate_message = ntlm2.NTLMNegotiateMessageV1(DomainName="URSA-MINOR", Workstation="LIGHTCITY")
        negotiate_message.set_negotiate_flag(ntlm2.NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM, True)
        negotiate_message.set_negotiate_flag(ntlm2.NTLM_FLAGS.NTLMSSP_REQUEST_TARGET, False)
        negotiate_bytes = negotiate_message.get_message_contents()
        negotiate_b64 = base64.b64encode(negotiate_bytes)
        expected_b64 = "TlRMTVNTUAABAAAAA7IAAAoACgApAAAACQAJACAAAABMSUdIVENJVFlVUlNBLU1JTk9S"
        expected_bytes = base64.b64decode(expected_b64)
        f = StringIO.StringIO(expected_bytes)
        expected_message = ntlm2.NTLMMessage.read(f)
        assert negotiate_b64 == expected_b64

    def test_old_parse_challenge(self):
        """Tests the old method of parsing ntlm challenge messages"""
        challenge_b64 = "TlRMTVNTUAACAAAAAAAAACgAAAABggAAU3J2Tm9uY2UAAAAAAAAAAA=="
        challenge_bytes = base64.b64decode(challenge_b64)
        if True:
            # FIXME: these fields are required by the spec but not in the example above
            if len(challenge_bytes) < 48:
                challenge_bytes += "\0" * (48-len(challenge_bytes))
            challenge_b64 = base64.b64encode(challenge_bytes)
        ServerChallenge, NegotiateFlags = ntlm.parse_NTLM_CHALLENGE_MESSAGE(challenge_b64)
        assert ServerChallenge == "SrvNonce"
        assert NegotiateFlags == 0x8201

    def test_parse_challenge(self):
        """Tests parsing ntlm challenge messages"""
        challenge_b64 = "TlRMTVNTUAACAAAAAAAAACgAAAABggAAU3J2Tm9uY2UAAAAAAAAAAA=="
        challenge_bytes = base64.b64decode(challenge_b64)
        f = StringIO.StringIO(challenge_bytes)
        challenge_message = ntlm2.NTLMMessage.read(f)
        assert challenge_message.Header.MessageType == ntlm2.NTLM_MESSAGE_TYPE.NtLmChallenge.const
        assert challenge_message.get_string_fields() == {"TargetName": "", "TargetInfo": ""}
        challenge_fields = challenge_message.MessageFields
        assert isinstance(challenge_fields, ntlm2.NTLMMessageChallengeFields)
        assert challenge_fields.ServerChallenge[0:8] == [ord(c) for c in "SrvNonce"]
        assert challenge_fields.NegotiateFlags == 0x8201

    def test_create_challenge(self):
        """Tests creating ntlm challenge messages"""
        challenge_message = ntlm2.NTLMMessage()
        challenge_message.Header.Signature = ntlm2.NTLM_PROTOCOL_SIGNATURE
        challenge_message.Header.MessageType = ntlm2.NTLM_MESSAGE_TYPE.NtLmChallenge.const
        challenge_fields = challenge_message.MessageDependentFields.MessageChallengeFields
        challenge_fields.NegotiateFlags = 0x8201
        challenge_message.set_string_field("TargetName", "")
        challenge_message.set_string_field("TargetInfo", "")
        challenge_fields.ServerChallenge[0:8] = [ord(c) for c in "SrvNonce"]
        challenge_str = challenge_message.get_message_contents()
        challenge_b64 = base64.b64encode(challenge_str)
        challenge_bytes = base64.b64decode(challenge_b64)
        f = StringIO.StringIO(challenge_bytes)
        parsed_message = ntlm2.NTLMMessage.read(f)
        assert parsed_message.Header.MessageType == ntlm2.NTLM_MESSAGE_TYPE.NtLmChallenge.const
        challenge_fields = parsed_message.MessageFields
        assert isinstance(challenge_fields, ntlm2.NTLMMessageChallengeFields)
        assert parsed_message.get_string_fields() == {"TargetName": "", "TargetInfo": ""}
        assert challenge_fields.ServerChallenge[0:8] == [ord(c) for c in "SrvNonce"]
        assert challenge_fields.NegotiateFlags == 0x8201
        # finally verify that we get byte-for-byte what we want
        expected_b64 = "TlRMTVNTUAACAAAAAAAAADAAAAABggAAU3J2Tm9uY2UAAAAAAAAAAAAAAAAwAAAA"
        expected_bytes = base64.b64decode(expected_b64)
        f = StringIO.StringIO(expected_bytes)
        expected_message = ntlm2.NTLMMessage.read(f)
        assert challenge_b64 == expected_b64

    def test_create_challenge_class(self):
        """Tests creating ntlm challenge messages using the helper class"""
        challenge_message = ntlm2.NTLMChallengeMessageV1(ServerChallenge="SrvNonce")
        challenge_fields = challenge_message.MessageFields
        challenge_str = challenge_message.get_message_contents()
        challenge_b64 = base64.b64encode(challenge_str)
        challenge_bytes = base64.b64decode(challenge_b64)
        f = StringIO.StringIO(challenge_bytes)
        parsed_message = ntlm2.NTLMMessage.read(f)
        assert parsed_message.Header.MessageType == ntlm2.NTLM_MESSAGE_TYPE.NtLmChallenge.const
        challenge_fields = parsed_message.MessageFields
        assert isinstance(challenge_fields, ntlm2.NTLMMessageChallengeFields)
        assert parsed_message.get_string_fields() == {"TargetName": "", "TargetInfo": ""}
        assert challenge_fields.ServerChallenge[0:8] == [ord(c) for c in "SrvNonce"]
        assert challenge_fields.NegotiateFlags == 0x8201
        # finally verify that we get byte-for-byte what we want
        expected_b64 = "TlRMTVNTUAACAAAAAAAAADAAAAABggAAU3J2Tm9uY2UAAAAAAAAAAAAAAAAwAAAA"
        expected_bytes = base64.b64decode(expected_b64)
        f = StringIO.StringIO(expected_bytes)
        expected_message = ntlm2.NTLMMessage.read(f)
        assert challenge_b64 == expected_b64

    def test_old_create_authenticate(self):
        """Tests the create_NTLM_AUTHENTICATE_MESSAGE"""
        # It seems that the unicode flag (vs 0x8202) makes no difference to the calculations here
        NegotiateFlags = 0x8201
        # TODO: make sure this upper-cases the username?
        created_authenticate_b64 = ntlm.create_NTLM_AUTHENTICATE_MESSAGE("SrvNonce", u"Zaphod", u"Ursa-Minor", u"Beeblebrox", NegotiateFlags)
        f = StringIO.StringIO(base64.b64decode(created_authenticate_b64))
        authenticate_message = ntlm2.NTLMMessage.read(f)
        authenticate_message.verify()
        assert authenticate_message.Header.MessageType == ntlm2.NTLM_MESSAGE_TYPE.NtLmAuthenticate.const
        assert authenticate_message.get_string_field("Workstation") == unicode_encode("LIGHTCITY")
        string_fields = authenticate_message.get_string_fields()
        assert string_fields.pop("DomainName") == unicode_encode(u"URSA-MINOR")
        assert string_fields.pop("Workstation") == unicode_encode(u"LIGHTCITY")
        assert string_fields.pop("UserName") == unicode_encode(u"Zaphod")
        assert string_fields.pop("EncryptedRandomSessionKey") == ""
        LmChallengeResponse = string_fields.pop("LmChallengeResponse")
        NtChallengeResponse = string_fields.pop("NtChallengeResponse")
        # these values are from http://www.innovation.ch/personal/ronald/ntlm.html
        # print ByteToHex(LmChallengeResponse)
        # print ByteToHex(NtChallengeResponse)
        assert LmChallengeResponse == HexToByte("ad 87 ca 6d ef e3 46 85 b9 c4 3c 47 7a 8c  42 d6 00 66 7d 68 92 e7 e8 97")
        assert NtChallengeResponse == HexToByte("e0 e0 0d e3 10 4a  1b f2 05 3f 07 c7 dd a8 2d 3c 48 9a e9 89 e1 b0   00 d3")
        assert string_fields == {}
        version = authenticate_message.get_version_field()
        assert version is not None
        assert version.ProductMajorVersion == 5
        assert version.ProductMinorVersion == 1
        assert version.ProductBuild == 2600
        assert version.NTLMRevisionCurrent == 0xf
        # final check that we have the exact binary result we expect
        # assert created_authenticate_b64 == "TlRMTVNTUAABAAAAB7IIogoACgAxAAAACQAJACgAAAAFASgKAAAAD0xJR0hUQ0lUWVVSU0EtTUlOT1I="

    def test_old_create_authenticate_2(self):
        """Tests the create_NTLM_AUTHENTICATE_MESSAGE using sample values from the documentation"""
        type(self).expectedhostname = "COMPUTER"
        NegotiateFlags = 0x8201
        ServerChallenge = HexToByte("01 23 45 67 89 ab cd ef")
        created_authenticate_b64 = ntlm.create_NTLM_AUTHENTICATE_MESSAGE(ServerChallenge, "User", "Domain", "Password", NegotiateFlags)
        f = StringIO.StringIO(base64.b64decode(created_authenticate_b64))
        authenticate_message = ntlm2.NTLMMessage.read(f)
        authenticate_message.verify()
        assert authenticate_message.Header.MessageType == ntlm2.NTLM_MESSAGE_TYPE.NtLmAuthenticate.const
        assert authenticate_message.get_string_field("Workstation") == unicode_encode(u"COMPUTER")
        string_fields = authenticate_message.get_string_fields()
        assert string_fields.pop("DomainName") == unicode_encode(u"DOMAIN")
        assert string_fields.pop("Workstation") == unicode_encode(u"COMPUTER")
        assert string_fields.pop("UserName") == unicode_encode(u"User")
        assert string_fields.pop("EncryptedRandomSessionKey") == ""
        LmChallengeResponse = string_fields.pop("LmChallengeResponse")
        NtChallengeResponse = string_fields.pop("NtChallengeResponse")
        # print ByteToHex(LmChallengeResponse)
        # print ByteToHex(NtChallengeResponse)
        # from hash tests above - the same flags are used here
        assert LmChallengeResponse == HexToByte("98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72  de f1 1c 7d 5c cd ef 13")
        assert NtChallengeResponse == HexToByte("67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c  44 bd be d9 27 84 1f 94")
        # investigate these - these are from the examples in ntlm, but have different flags
        # assert HexToByte("86c35097 ac9cec10 2554764a 57cccc19 aaaaaaaa aaaaaaaa") == LmChallengeResponse  # [MS-NLMP] page 76
        # assert NtChallengeResponse == HexToByte("8c1b59e3 2e666dad f175745f ad62c133")
        assert string_fields == {}
        version = authenticate_message.get_version_field()
        assert version is not None
        assert version.ProductMajorVersion == 5
        assert version.ProductMinorVersion == 1
        assert version.ProductBuild == 2600
        assert version.NTLMRevisionCurrent == 0xf
        # final check that we have the exact binary result we expect
        # assert created_authenticate_b64 == "TlRMTVNTUAABAAAAB7IIogoACgAxAAAACQAJACgAAAAFASgKAAAAD0xJR0hUQ0lUWVVSU0EtTUlOT1I="

