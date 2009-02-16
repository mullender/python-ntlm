#!/usr/bin/env python

import random
import sys
import ctypes
import pprint
import des
import hashlib
import hmac
import StringIO

def unimplemented(func):
    """Simple decorator, to help identify unimplemented base class functions"""
    def wrapper(obj,*__args,**__kw):
        if hasattr(obj, "__class__"):
            raise NotImplementedError("%s.%s needs a \"%s\" function"%(obj.__class__.__module__, obj.__class__.__name__, func.__name__))
        else:
            inst = obj()
            raise NotImplementedError("%s.%s needs a \"%s\" function"%(inst.__class__.__module__, inst.__class__.__name__, func.__name__))

    return wrapper
#-----------------------------------------------------------------------------------------------------------

def desl(k, d):
    """Helper function which implements "Data Encryption Standard Long" algorithm.
       "k" should be a 16 byte value which gets padded by 5 bytes. "d" should be an 8 byte value."""
    # padding with zeros to make the hash 21 bytes long
    password_hash = k + '\0' * (21 - len(k))
    res = ''
    dobj = des.DES(password_hash[0:7])
    res = res + dobj.encrypt(d[0:8])

    dobj = des.DES(password_hash[7:14])
    res = res + dobj.encrypt(d[0:8])

    dobj = des.DES(password_hash[14:21])
    res = res + dobj.encrypt(d[0:8])
    return res

#-----------------------------------------------------------------------------------------------
# ClientInterface - Must be supported by NTLM client implementation
#-----------------------------------------------------------------------------------------------

class ClientInterface:
    """Provides access to information about the client machine. All information returned as strings
       should be unencoded. It is left to the NTLM handlers to encode strings correctly."""

    @unimplemented
    def get_workstation(self):
        """Must return None or the client workstation name"""

    @unimplemented
    def get_domain(self):
        """Must return None or the client domain name"""

#-----------------------------------------------------------------------------------------------
# ServerInterface - Must be supported by NTLM server implementation
#-----------------------------------------------------------------------------------------------

class ServerInterface:
    """Provides access to information about the server machine. All information returned as strings
       should be unencoded. It is left to the NTLM handlers to encode strings correctly."""

    @unimplemented
    def negotiated_security_ok(self, NegFlg):
	"""Must check that NegFlg meets the required security settings. See [MS-NLMP] page 51"""

    @unimplemented
    def get_NetBIOS_name(self):
        """Must return None or the NetBIOS name of the server"""

    @unimplemented
    def get_NetBIOS_domain(self):
        """Must return None or the NetBIOS domain name of the server"""

    @unimplemented
    def get_DNS_name(self):
        """Must return None or the server's Active Directory DNS computer name."""

    @unimplemented
    def get_DNS_domain(self):
        """Must return None or the server's Active Directory DNS domain name."""

    @unimplemented
    def get_DNS_forest_name(self):
        """Must return None or the server's Active Directory DNS forest tree name."""

#-----------------------------------------------------------------------------------------------
# ResponseData
#-----------------------------------------------------------------------------------------------

class ResponseData:
    def __init__(self, ResponseKeyNT, ResponseKeyLM, NTChallengeResponse=None, LmChallengeResponse=None, SessionBaseKey=None):
	self.ResponseKeyNT = ResponseKeyNT
	self.ResponseKeyLM = ResponseKeyLM
	self.NTChallengeResponse = NTChallengeResponse
	self.LmChallengeResponse = LmChallengeResponse
	self.SessionBaseKey = SessionBaseKey

#-----------------------------------------------------------------------------------------------
# NTLM_Exception
#-----------------------------------------------------------------------------------------------

class NTLM_Exception(Exception):
    pass

#-----------------------------------------------------------------------------------------------
# FileStructure
#-----------------------------------------------------------------------------------------------

class FileStructure(object):
    @classmethod
    def read(cls, f, size=None):
        if size is None:
            size = ctypes.sizeof(cls)
        disk_block = (ctypes.c_uint8*size)(*[ord(b) for b in f.read(size)])
        s = ctypes.cast(disk_block, ctypes.POINTER(cls)).contents
        s.verify()
        return s

    def verify(self):
        """verifies that the structure is valid"""
        return True

    def pformat(self):
        return pprint.pformat(dict([(field[0], getattr(self, field[0])) for field in self._fields_]))

    def __repr__(self):
       return "%s(%r)" % (self.__class__, dict([(field[0], getattr(self, field[0])) for field in self._fields_]))

#-----------------------------------------------------------------------------------------------
# FieldType
#-----------------------------------------------------------------------------------------------

class FieldType:
    def __init__(self, name, const, comment):
        self.name, self.const, self.comment = name, const, comment

#-----------------------------------------------------------------------------------------------
# EnumType
#-----------------------------------------------------------------------------------------------

class EnumType(object):
    @classmethod
    def valid_types(cls):
        for n in dir(cls):
            v = getattr(cls, n)
            if isinstance(v, FieldType):
                yield v
    @classmethod
    def valid_consts(cls):
        for v in cls.valid_types():
            yield v.const

#-----------------------------------------------------------------------------------------------
# NTLM_MESSAGE_TYPE
#-----------------------------------------------------------------------------------------------

class NTLM_MESSAGE_TYPE(EnumType):
    NtLmNegotiate = FieldType("NtLmNegotiate", 0x1, "The message is a NEGOTIATE_MESSAGE.")
    NtLmChallenge = FieldType("NtLmChallenge", 0x2, "The message is a CHALLENGE_MESSAGE.")
    NtLmAuthenticate = FieldType("NtLmAuthenticate", 0x3, "The message is an AUTHENTICATE_MESSAGE.")

#-----------------------------------------------------------------------------------------------
# NTLM_REVISION_TYPE
#-----------------------------------------------------------------------------------------------

class NTLM_REVISION_TYPE(EnumType):
    NTLMSSP_REVISION_W2K3 = FieldType("NTLMSSP_REVISION_W2K3", 0x0F, "Version 15 of the NTLMSSP is in use.")
    NTLMSSP_REVISION_W2K3_RC1 = FieldType("NTLMSSP_REVISION_W2K3_RC1", 0x0A, "Version 10 of the NTLMSSP is in use.")

#-----------------------------------------------------------------------------------------------
# NTLM_FLAGS
#-----------------------------------------------------------------------------------------------

class NTLM_FLAGS:
    NTLMSSP_NEGOTIATE_UNICODE                  =  0x00000001
    NTLMSSP_NEGOTIATE_OEM                      =  0x00000002
    NTLMSSP_REQUEST_TARGET                     =  0x00000004
    NTLMSSP_UNKNOWN9                           =  0x00000008
    NTLMSSP_NEGOTIATE_SIGN                     =  0x00000010
    NTLMSSP_NEGOTIATE_SEAL                     =  0x00000020
    NTLMSSP_NEGOTIATE_DATAGRAM                 =  0x00000040
    NTLMSSP_NEGOTIATE_LM_KEY                   =  0x00000080
    NTLMSSP_UNKNOWN8                           =  0x00000100
    NTLMSSP_NEGOTIATE_NTLM                     =  0x00000200
    NTLMSSP_NEGOTIATE_NT_ONLY                  =  0x00000400
    NTLMSSP_ANONYMOUS                          =  0x00000800
    NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED      =  0x00001000
    NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED =  0x00002000
    NTLMSSP_UNKNOWN6                           =  0x00004000
    NTLMSSP_NEGOTIATE_ALWAYS_SIGN              =  0x00008000
    NTLMSSP_TARGET_TYPE_DOMAIN                 =  0x00010000
    NTLMSSP_TARGET_TYPE_SERVER                 =  0x00020000
    NTLMSSP_TARGET_TYPE_SHARE                  =  0x00040000
    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY =  0x00080000
    NTLMSSP_NEGOTIATE_IDENTIFY                 =  0x00100000
    NTLMSSP_UNKNOWN5                           =  0x00200000
    NTLMSSP_REQUEST_NON_NT_SESSION_KEY         =  0x00400000
    NTLMSSP_NEGOTIATE_TARGET_INFO              =  0x00800000
    NTLMSSP_UNKNOWN4                           =  0x01000000
    NTLMSSP_NEGOTIATE_VERSION                  =  0x02000000
    NTLMSSP_UNKNOWN3                           =  0x04000000
    NTLMSSP_UNKNOWN2                           =  0x08000000
    NTLMSSP_UNKNOWN1                           =  0x10000000
    NTLMSSP_NEGOTIATE_128                      =  0x20000000
    NTLMSSP_NEGOTIATE_KEY_EXCHANGE             =  0x40000000
    NTLMSSP_NEGOTIATE_56                       =  0x80000000

#-----------------------------------------------------------------------------------------------
# AV_TYPES
#-----------------------------------------------------------------------------------------------

class AV_TYPES:
    MsvAvEOL                = 0
    MsvAvNbComputerName     = 1
    MsvAvNbDomainName       = 2
    MsvAvDnsComputerName    = 3
    MsvAvDnsDomainName      = 4
    MsvAvDnsTreeName        = 5
    MsvAvFlags              = 6
    MsvAvTimestamp          = 7
    MsAvRestrictions        = 8
    MsvAvTargetName         = 9
    MsvChannelBindings      = 10

NTLM_PROTOCOL_SIGNATURE = "NTLMSSP\0"

#-----------------------------------------------------------------------------------------------
# StringHeader
#-----------------------------------------------------------------------------------------------

class StringHeader(ctypes.LittleEndianStructure, FileStructure):
    _pack_ = 1
    _fields_ = [("Len", ctypes.c_uint16),
                # A 16-bit unsigned integer that defines the size, in bytes, of the field in Payload.
                ("MaxLen", ctypes.c_uint16),
                # A 16-bit unsigned integer that SHOULD be set to the value of Len and MUST be ignored.
                ("BufferOffset", ctypes.c_uint32),
                # A 32-bit unsigned integer that defines the offset, in bytes, from the beginning of the Message to the Field in Payload.
               ]
    def get_max_offset(self):
        return self.Len + self.BufferOffset

#-----------------------------------------------------------------------------------------------
# NTLMMessageDependentFieldsHandler
#-----------------------------------------------------------------------------------------------

class NTLMMessageDependentFieldsHandler(ctypes.LittleEndianStructure, FileStructure):
    def get_string_fields(self):
        return [field_name for field_name, field_type in self._fields_ if field_type == StringHeader]

    def get_max_payload(self):
        return max(getattr(self, field_name).get_max_offset() for field_name in self.get_string_fields())

    def read_payload(self, f):
        size = self.get_max_payload()
        disk_block = (ctypes.c_uint8*size)(*[ord(b) for b in f.read(size)])
        return disk_block

#-----------------------------------------------------------------------------------------------
# NTLMVersionStructure
#-----------------------------------------------------------------------------------------------

class NTLMVersionStructure(ctypes.LittleEndianStructure, FileStructure):
    _pack_ = 1
    _fields_ = [("ProductMajorVersion", ctypes.c_uint8),
                ("ProductMinorVersion", ctypes.c_uint8),
                ("ProductBuild", ctypes.c_uint16),
                ("Reserved", ctypes.c_uint8*3),
                ("NTLMRevisionCurrent", ctypes.c_uint8),
               ]

#-----------------------------------------------------------------------------------------------
# AV_Header
#-----------------------------------------------------------------------------------------------

class AV_Header(ctypes.LittleEndianStructure, FileStructure):
    _pack_ = 1
    _fields_ = [("AvId", ctypes.c_uint16),
                ("AvLen", ctypes.c_uint16),
               ]

#-----------------------------------------------------------------------------------------------
# AV_PAIR
#-----------------------------------------------------------------------------------------------

class AV_PAIR(ctypes.LittleEndianStructure, FileStructure):
    _pack_ = 1
    _fields_ = [("Header", AV_Header),
                ("Value", ctypes.POINTER(ctypes.c_uint8)),
               ]

    @classmethod
    def create(cls, AvId, Value):
        result = cls()
        disk_block = (ctypes.c_uint8*4)(*[0,0,0,0])
        result.Header = ctypes.cast(disk_block, ctypes.POINTER(AV_Header)).contents
        result.Header.AvId = AvId
        result.Header.AvLen = len(Value)
        result.Value = (ctypes.c_uint8*result.Header.AvLen)(*[ord(b) for b in Value])
        result.verify()
        return result

    @classmethod
    def read(cls, f):
        result = cls()
        disk_block = (ctypes.c_uint8*4)(*[ord(b) for b in f.read(4)])
        result.Header = ctypes.cast(disk_block, ctypes.POINTER(AV_Header)).contents
        result.Value = (ctypes.c_uint8*result.Header.AvLen)(*[ord(b) for b in f.read(result.Header.AvLen)])
        result.verify()
        return result

    def value_byte_string(self):
        return "".join([chr(x) for x in self.Value[0:self.Header.AvLen]])

    def to_byte_string(self):
        pointer = ctypes.POINTER(AV_Header)()
        pointer.contents = self.Header
        disk_block = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint8*4)).contents
        return "".join([chr(x) for x in disk_block[0:4]]) + self.value_byte_string()


#-----------------------------------------------------------------------------------------------
# AV_PAIR_Handler
#-----------------------------------------------------------------------------------------------

class AV_PAIR_Handler:
    def __init__(self, value=None):
	if value is not None:
	    self.set_av_pairs(value)
	else:
	    self._AV_PAIRS = []

    def get_av_pairs(self):
	return self._AV_PAIRS

    def set_av_pairs(self, value):
	#av_pairs will be stored as tuples of (AvId, Value) where Value is a "utf-16le" Byte String
	if isinstance(value, basestring):
	    self._set_av_pairs_from_bytes(value)
	elif isinstance(value, list) or isinstance(value, tuple):
	    self._set_av_pairs_from_list(value)

    def _set_av_pairs_from_list(self, alist):
	self._AV_PAIRS = []
	for pair in alist:
	    if (isinstance(pair, list) or isinstance(pair, tuple)) and len(pair) == 2 and isinstance(pair[0], int):
		self._AV_PAIRS.append(AV_PAIR.create(pair[0], pair[1]))

    def _set_av_pairs_from_bytes(self, bytes):
	self._AV_PAIRS = []
	stringio = StringIO.StringIO(bytes)
	while True:
	    current = AV_PAIR.read(stringio)
	    if current.Header.AvId == AV_TYPES.MsvAvEOL:
		break
	    if isinstance(current, AV_PAIR):
		#Don't bother to read the Terminating AV pair as it is not needed
		self._AV_PAIRS.append(current)

    def add_av_pair(self, AvId, Value):
	self._AV_PAIRS.append(AV_PAIR.create(AvId, Value))

    def to_byte_string(self):
	"""Convert List of AV_PAIRs to an encoded ByteString, which can be used in an NTLM message"""
	result = ""
	for pair in self._AV_PAIRS:
	    result += pair.to_byte_string()
	#Add terminating AV_PAIR
	result += AV_PAIR.create(AV_TYPES.MsvAvEOL, "").to_byte_string()
	return result

#-----------------------------------------------------------------------------------------------
# NTLMMessageNegotiateFields
#-----------------------------------------------------------------------------------------------

class NTLMMessageNegotiateFields(NTLMMessageDependentFieldsHandler):
    _pack_ = 1
    _fields_ = [("NegotiateFlags", ctypes.c_uint32),
                ("DomainName", StringHeader),
                ("Workstation", StringHeader),
               ]

#-----------------------------------------------------------------------------------------------
# NTLMMessageChallengeFields
#-----------------------------------------------------------------------------------------------

class NTLMMessageChallengeFields(NTLMMessageDependentFieldsHandler):
    _pack_ = 1
    _fields_ = [("TargetName", StringHeader),
                ("NegotiateFlags", ctypes.c_uint32),
                ("ServerChallenge", ctypes.c_uint8 * 8),
                ("Reserved", ctypes.c_uint8 * 8),
                ("TargetInfo", StringHeader),
               ]

#-----------------------------------------------------------------------------------------------
# NTLMMessageAuthenticateFields
#-----------------------------------------------------------------------------------------------

class NTLMMessageAuthenticateFields(NTLMMessageDependentFieldsHandler):
    _pack_ = 1
    _fields_ = [("LmChallengeResponse", StringHeader),
                ("NtChallengeResponse", StringHeader),
                ("DomainName", StringHeader),
                ("UserName", StringHeader),
                ("Workstation", StringHeader),
                ("EncryptedRandomSessionKey", StringHeader),
                ("NegotiateFlags", ctypes.c_uint32),
               ]

#-----------------------------------------------------------------------------------------------
# NTLMMessageDependentFields
#-----------------------------------------------------------------------------------------------

class NTLMMessageDependentFields(ctypes.Union, FileStructure):
    _pack_ = 1
    _fields_ = [("MessageNegotiateFields", NTLMMessageNegotiateFields),
                ("MessageChallengeFields", NTLMMessageChallengeFields),
                ("MessageAuthenticateFields", NTLMMessageAuthenticateFields),
               ]

    @classmethod
    def read(cls, f, size=None, MessageType=None):
        """Reads the approriate fields given the MessageType code"""
        if MessageType == NTLM_MESSAGE_TYPE.NtLmNegotiate.const:
            fields_class = NTLMMessageNegotiateFields
        elif MessageType == NTLM_MESSAGE_TYPE.NtLmChallenge.const:
            fields_class = NTLMMessageChallengeFields
        elif MessageType == NTLM_MESSAGE_TYPE.NtLmAuthenticate.const:
            fields_class = NTLMMessageAuthenticateFields
        else:
            raise ValueError("Unknown MessageType %r" % (MessageType,))
        fields = fields_class.read(f, size)
        if size is None:
           size = ctypes.sizeof(fields)
        field_bytes = ctypes.cast(ctypes.pointer(fields), ctypes.POINTER(ctypes.c_uint8 * size)).contents
        return ctypes.cast(field_bytes, ctypes.POINTER(cls)).contents

#-----------------------------------------------------------------------------------------------
# NTLMMessageHeader
#-----------------------------------------------------------------------------------------------

class NTLMMessageHeader(ctypes.LittleEndianStructure, FileStructure):
    _pack_ = 1
    _fields_ = [("Signature", ctypes.c_char*8),
                ("MessageType", ctypes.c_uint32),
               ]

    def verify(self):
        """verifies that the structure is valid"""
        assert self.Signature == NTLM_PROTOCOL_SIGNATURE.rstrip("\0")
        assert self.MessageType in NTLM_MESSAGE_TYPE.valid_consts()
        return True

#-----------------------------------------------------------------------------------------------
# NTLMOptionalFields
#-----------------------------------------------------------------------------------------------

class NTLMOptionalFields(ctypes.LittleEndianStructure, FileStructure):
    _pack_ = 1
    _fields_ = [("Version", NTLMVersionStructure),
                ("MIC", ctypes.c_uint8*16),
               ]

#-----------------------------------------------------------------------------------------------
# NTLMMessage
#-----------------------------------------------------------------------------------------------

class NTLMMessage(ctypes.LittleEndianStructure, FileStructure):
    _pack_ = 1
    _fields_ = [("Header", NTLMMessageHeader),
                ("MessageDependentFields", NTLMMessageDependentFields),
                ("payload", ctypes.POINTER(ctypes.c_uint8)),
               ]

    unicode = 'utf-16le'
    oem = 'utf-16le'	    #In the case of client and server communications, client and server must agree on a shared oem character set
                            #By default, just use unicode
    unsupported_flags = 0   #Set bits on this property to indicate which flags are unsupported

    #List of flags that do not have to be supported
    optional_flags = (NTLM_FLAGS.NTLMSSP_NEGOTIATE_56 | NTLM_FLAGS.NTLMSSP_NEGOTIATE_KEY_EXCHANGE | NTLM_FLAGS.NTLMSSP_NEGOTIATE_128
		     |NTLM_FLAGS.NTLMSSP_NEGOTIATE_VERSION | NTLM_FLAGS.NTLMSSP_REQUEST_NON_NT_SESSION_KEY | NTLM_FLAGS.NTLMSSP_NEGOTIATE_IDENTIFY
		     |NTLM_FLAGS.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
		     |NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NT_ONLY | NTLM_FLAGS.NTLMSSP_NEGOTIATE_LM_KEY
		     |NTLM_FLAGS.NTLMSSP_NEGOTIATE_DATAGRAM | NTLM_FLAGS.NTLMSSP_NEGOTIATE_SEAL | NTLM_FLAGS.NTLMSSP_NEGOTIATE_SIGN
		     |NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM)

    @classmethod
    def supported_flags(cls, flags):
	"""Function filters out any flags not supported by client/server"""
	temp = flags | cls.unsupported_flags
	return temp ^ cls.unsupported_flags

    @classmethod
    def _get_nonce(cls):
	result = ""
	for i in xrange(8):
	    result += chr(random.getrandbits(8))
	return result

    @classmethod
    def read(cls, f, size=None):
        header = NTLMMessageHeader.read(f)
        if header.MessageType == NTLM_MESSAGE_TYPE.NtLmNegotiate.const:
            message = NTLMNegotiateMessage()
        elif header.MessageType == NTLM_MESSAGE_TYPE.NtLmChallenge.const:
            message = NTLMChallengeMessage()
        else:
            message = cls()
        message.Header = header
        message.MessageDependentFields = NTLMMessageDependentFields.read(f, MessageType=header.MessageType)
        message.payload = message.MessageFields.read_payload(f)
        return message

    def get_message_fields(self):
        """Returns the fields appropriate to the MessageType"""
        MessageType = self.Header.MessageType
        if MessageType == NTLM_MESSAGE_TYPE.NtLmNegotiate.const:
            return self.MessageDependentFields.MessageNegotiateFields
        elif MessageType == NTLM_MESSAGE_TYPE.NtLmChallenge.const:
            return self.MessageDependentFields.MessageChallengeFields
        elif MessageType == NTLM_MESSAGE_TYPE.NtLmAuthenticate.const:
            return self.MessageDependentFields.MessageAuthenticateFields
        else:
            raise ValueError("Unknown MessageType %r" % (MessageType,))
    MessageFields = property(get_message_fields)

    def get_version_field(self):
        """Gets the version field, if present"""
        if self.MessageFields.NegotiateFlags & NTLM_FLAGS.NTLMSSP_NEGOTIATE_VERSION:
            version_block = (ctypes.c_uint8*8)(*self.payload[0:8])
            version = ctypes.cast(version_block, ctypes.POINTER(NTLMVersionStructure)).contents
            return version
        else:
            return None

    def _add_version_information(self):
	major, minor, build, platform, text = sys.getwindowsversion()
	#TODO - Revision version MUST have one of the values below - work out which
	#NTLMSSP_REVISION_W2K3 		0x0F 	 Version 15 of the NTLMSSP is in use.
	#NTLMSSP_REVISION_W2K3_RC1 	0x0A	 Version 10 of the NTLMSSP is in use.
	version = self.get_version_field()
	version.ProductMajorVersion = major
	version.ProductMinorVersion = minor
	version.ProductBuild = build
	version.NTLMRevisionCurrent = 0xf #Just hardcode a value for now

    def get_optional_length(self):
        """Returns the length of optional Version and MIC fields"""
        # TODO: include MIC evaluation
        if self.MessageFields.NegotiateFlags & NTLM_FLAGS.NTLMSSP_NEGOTIATE_VERSION:
            return 8
        return 0

    def get_string_field(self, name):
        """Looks up a string field in the payload"""
        MessageFields = self.MessageFields
        FieldHeader = getattr(MessageFields, name)
        HeaderSize = ctypes.sizeof(self.Header) + ctypes.sizeof(MessageFields)
        return "".join(chr(i) for i in self.payload[FieldHeader.BufferOffset-HeaderSize:FieldHeader.BufferOffset+FieldHeader.Len-HeaderSize])

    def set_string_field(self, name, new_value):
        """Adjusts a string field in the payload"""
        current_fields = self.get_string_fields()
        current_fields[name] = new_value
        self.set_string_fields(current_fields)

    def del_string_field(self, name):
        """Clears a string field in the payload"""
        current_fields = self.get_string_fields()
        current_fields[name] = ""
        self.set_string_fields(current_fields)

    def set_string_fields(self, field_values, optional_length_change=0):
        """regenerates the payload with the field_values given"""
        MessageFields = self.MessageFields
        HeaderSize = ctypes.sizeof(self.Header) + ctypes.sizeof(MessageFields)
        optional_length = self.get_optional_length()
        new_payload_size = optional_length + sum(len(value or "") for value in field_values.values())
        new_payload = (ctypes.c_uint8*new_payload_size)()
        source_pos = copy_pos = optional_length

        #Check whether the NTLMSSP_NEGOTIATE_VERSION flag has been changed
        if optional_length_change == 0:
            new_payload[0:optional_length] = self.payload[0:optional_length]
        else:
            source_pos = source_pos - optional_length_change

        for field_name, value in field_values.items():
            value = value or ""
            FieldHeader = getattr(MessageFields, field_name)
            FieldHeader.Len = FieldHeader.MaxLen = field_len = len(value)
            FieldHeader.BufferOffset = HeaderSize + source_pos
            new_pos = copy_pos + field_len
            new_payload[copy_pos:new_pos] = (ctypes.c_uint8*field_len)(*[ord(b) for b in value])
            copy_pos = new_pos
            source_pos = source_pos + field_len
        self.payload = new_payload

    def get_string_fields(self):
        """Gets a dictionary of all available string fields in the payload"""
        MessageFields = self.MessageFields
        string_fields = {}
        for name in MessageFields.get_string_fields():
            string_fields[name] = self.get_string_field(name)
        return string_fields

    def verify(self):
        """verifies that the structure is valid"""
        self.Header.verify()
        self.MessageFields.verify()
        return True

    def get_message_contents(self):
        """gets the message contents as a c-type array"""
        MessageFields = self.MessageFields
        header_size = ctypes.sizeof(self.Header)
        field_size = ctypes.sizeof(MessageFields)
        payload_size = max(self.get_optional_length(), MessageFields.get_max_payload() - header_size - field_size)
        message_len = header_size + field_size + payload_size
        contents = (ctypes.c_uint8*message_len)()
        position = 0
        contents[0:header_size] = ctypes.cast(ctypes.pointer(self.Header), ctypes.POINTER(ctypes.c_uint8*header_size)).contents
        position += header_size
        contents[position:position + field_size] = ctypes.cast(ctypes.pointer(MessageFields), ctypes.POINTER(ctypes.c_uint8*field_size)).contents
        position += field_size
        contents[position:position + payload_size] = self.payload[0:payload_size]
        return contents

    def set_negotiate_flag(self, flag_bit, value):
        """Sets the given negotiate flag on or off depending on if value evaluates to True or False"""
        optional_length_old = self.get_optional_length()
        if value:
            self.MessageFields.NegotiateFlags |= flag_bit
        else:
            self.MessageFields.NegotiateFlags &= ~flag_bit
        optional_length_new = self.get_optional_length()
        if optional_length_new != optional_length_old:
            self.set_string_fields(self.get_string_fields(), optional_length_new - optional_length_old)

    def set_negotiate_flags(self, NegFlg):
        """ NegotiateFlags should not be set directly, because some flags can affect the structure of the payload. Eg setting
            NTLMSSP_NEGOTIATE_VERSION directly will lead to a segmentation fault if the payload is not enlarged to make space for
            the version information
        """
        optional_length_old = self.get_optional_length()
        self.MessageFields.NegotiateFlags = NegFlg
        optional_length_new = self.get_optional_length()
        if optional_length_new != optional_length_old:
            self.set_string_fields(self.get_string_fields(), optional_length_new - optional_length_old)

    def get_negotiate_flag(self, flag_bit):
        """Returns whether the given negotiate flag bit is set"""
        return bool(self.MessageFields.NegotiateFlags & flag_bit)

    def set_string_field_with_flag(self, field_name, flag_bit, value):
        """sets the given field to the value, adjusting the flag depending on whether it's None or not"""
        if value is None:
            self.del_string_field_with_flag(field_name, flag_bit)
        else:
            self.set_string_field(field_name, value)
            self.set_negotiate_flag(flag_bit, True)

    def get_string_field_with_flag(self, field_name, flag_bit):
        """gets the value of the given field, if flag_bit indicates its presence"""
        if self.get_negotiate_flag(flag_bit):
            return self.get_string_field(field_name)
        else:
            return None

    def del_string_field_with_flag(self, field_name, flag_bit):
        """sets the value of the given field to None, and turns off its flag_bit"""
        self.set_string_field(field_name, "")
        self.set_negotiate_flag(flag_bit, False)

# flags that need to be managed across messages
# parameter control:
# * unicode/OEM character set: NEGOTIATE_UNICODE, NEGOTIATE_OEM
# * Request TargetName: REQUEST_TARGET
# * Whether TargetName is a domain, server or share: TARGET_TYPE_DOMAIN, TARGET_TYPE_SERVER, TARGET_TYPE_SHARE
# * Requesting extended information about the server authentication realm to be sent as AV_PAIR in the TargetInfo payload: NEGOTIATE_TARGET_INFO
# * Requesting the Protocol Version number: NEGOTIATE_VERSION
# protocol types:
# * connectionless authentication (NOT SUPPORTED): NEGOTIATE_DATAGRAM
# * NTLM version 1: NEGOTIATE_NTLM
# * Using only NT (not LM) authentication: NEGOTIATE_NT_ONLY
# * Anonymous connection: ANONYMOUS
# Security parameters:
# * session key negotiation for message signatures: NEGOTIATE_SIGN
# * session key negotiation for message confidentiality: NEGOTIATE_SEAL
# * the presence of a signature block on all messages: NEGOTIATE_ALWAYS_SIGN (overridden by NEGOTIATE_SIGN and NEGOTIATE_SEAL)
# * LAN Manager (LM) session key computation: NEGOTIATE_LM_KEY (incompatible with NEGOTIATE_EXTENDED_SESSIONSECURITY)
# * Using v2 session security within NTLM version 1 session: NEGOTIATE_EXTENDED_SESSIONSECURITY (incompatible with NEGOTIATE_LM_KEY)
# * Requesting an identify level token: NEGOTIATE_IDENTIFY
# Key negotiation:
# * 128-bit/56-bit session key negotiation: NEGOTIATE_128, NEGOTIATE_56 (interacts with NEGOTIATE_SIGN and NEGOTIATE_SEAL)
# * Explicit key exchange: NEGOTIATE_KEY_EXCH (interacts with NEGOTIATE_SIGN and NEGOTIATE_SEAL)
# other:
# * usage of the LMOWF: REQUEST_NON_NT_SESSION_KEY

#-----------------------------------------------------------------------------------------------
# StringProperty
#-----------------------------------------------------------------------------------------------

class StringProperty(property):
    """This represents a String field"""
    def __init__(self, field_name):
        self.field_name = field_name
        def fget(message):
            return message.get_string_field(self.field_name)
        def fset(message, value):
            return message.set_string_field(self.field_name, value)
        def fdel(message):
            return message.del_string_field(field_name)
        property.__init__(self, fget, fset, fdel)

#-----------------------------------------------------------------------------------------------
# BinaryProperty
#-----------------------------------------------------------------------------------------------

class BinaryProperty(property):
    """This represents a Binary field in the header"""
    def __init__(self, field_name):
        self.field_name = field_name
        def fget(message):
            return getattr(message.MessageFields, self.field_name)
        def fset(message, value):
            field_len = ctypes.sizeof(getattr(message.MessageFields, self.field_name))
            if value is None:
                value = (ctypes.c_uint8*field_len)(*[0 for i in range(field_len)])
            elif isinstance(value, str):
                value = (ctypes.c_uint8*field_len)(*[ord(value[i]) for i in range(field_len)])
            return setattr(message.MessageFields, self.field_name, value)
        property.__init__(self, fget, fset)

#-----------------------------------------------------------------------------------------------
# StringPropertyWithFlag
#-----------------------------------------------------------------------------------------------

class StringPropertyWithFlag(property):
    """This represents a String field that is only present if the flag bit is on"""
    def __init__(self, field_name, flag_bit):
        self.field_name = field_name
        self.flag_bit = flag_bit
        def fget(message):
            return message.get_string_field_with_flag(self.field_name, self.flag_bit)
        def fset(message, value):
            return message.set_string_field_with_flag(self.field_name, self.flag_bit, value)
        def fdel(message):
            return message.del_string_field_with_flag(field_name, flag_bit)
        property.__init__(self, fget, fset, fdel)

#-----------------------------------------------------------------------------------------------
# FlagProperty
#-----------------------------------------------------------------------------------------------

class FlagProperty(property):
    """This represents a flag in the Negotiate header"""
    def __init__(self, field_name):
        self.field_name = field_name
        def fget(message):
            return message.get_negotiate_flag(self.field_name)
        def fset(message, value):
            return message.set_negotiate_flag(self.field_name, value)
        property.__init__(self, fget, fset, fdel)

#-----------------------------------------------------------------------------------------------
# NTLMNegotiateMessage
#-----------------------------------------------------------------------------------------------

class NTLMNegotiateMessage(NTLMMessage):
    """NTLM Negotiate Message"""
    DEFAULT_FLAGS = NTLM_FLAGS.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NTLM | NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE
    def __init__(self, NegFlg=None, DomainName=None, Workstation=None):
        """Constructs a new NTLM Negotiate Message"""
        self.Header.Signature = NTLM_PROTOCOL_SIGNATURE
        self.Header.MessageType = NTLM_MESSAGE_TYPE.NtLmNegotiate.const
        if NegFlg is None:
            self.set_negotiate_flags(self.DEFAULT_FLAGS)
        else:
            self.set_negotiate_flags(NegFlg)
        self.DomainName = DomainName
        self.Workstation = Workstation

    @classmethod
    def create(cls, NegFlg, client_object):
        """Returns an NTLM negotiate message
	    NegFlg 		- If this value is not None, overwrite the default flags
	    client_object	- An object which implements ClientInterface. It should provide the folowing information:
		    domain	- If this value is not None, include domain in the message. Value should be an unencoded string.
		    workstation	- If this value is not None, include workstation in the message. Value should be an unencoded string.
	"""
	if not isinstance(client_object, ClientInterface):
	    raise NTLMException("The 'client_object' argument passed to 'create_negotiate_message' must be of type 'ClientInterface'")

	domain = client_object.get_domain()
	workstation = client_object.get_workstation()

	if NegFlg is None:
	    NegFlg = cls.DEFAULT_FLAGS

	#Negotiate message MUST set these flags - [MS-NLMP] pages 33 and 34
	NegFlg = NegFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NTLM

	#Filter the Negotiate Flags down to those which are actually supported. By default all flags are supported.
	NegFlg = cls.supported_flags(NegFlg)

	#Set any flags which are required by current flags. Eg Setting NTLMSSP_NEGOTIATE_SEAL requires that NTLMSSP_NEGOTIATE_56
	#gets set if it is supported. For now, just set all required flags and remove all unsupported flags later.
	if NegFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_SEAL:
	    NegFlg = NegFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_56
	    NegFlg = NegFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_128

	#Additional flags may have been added. Filter the Negotiate Flags down to those which are actually supported.
	NegFlg = cls.supported_flags(NegFlg)

	#Check that a choice of encoding can still be negotiated.
	if not NegFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM and not NegFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE:
	    if cls.supported_flags(NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE):
		NegFlg = NegFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE
	    elif cls.supported_flags(NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM):
		NegFlg = NegFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM
	    else:
		raise NTLM_Exception("Could not set NTLM_NEGOTIATE_OEM or NTLMSSP_NEGOTIATE_UNICODE flags")

	if workstation is not None and cls.supported_flags(NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED):
	    NegFlg = NegFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
	else:
	    workstation = None

	if domain is not None and cls.supported_flags(NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED):
	    NegFlg = NegFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
	else:
	    domain = None

	#Ready to create the negotiate message
	negotiate_message = cls(NegFlg, domain, workstation)

	#Prepare values for OS version information
	if NegFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_VERSION:
	    try:
		negotiate_message._add_version_information()
	    except:
		#TODO - log a warning - The version info could not be supplied
		negotiate_message.set_negotiate_flags(NegFlg ^ NTLM_FLAGS.NTLMSSP_NEGOTIATE_VERSION)

	return negotiate_message

    DomainName = StringPropertyWithFlag("DomainName", NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED)
    Workstation = StringPropertyWithFlag("Workstation", NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED)

#-----------------------------------------------------------------------------------------------
# NTLMChallengeMessage
#-----------------------------------------------------------------------------------------------

class NTLMChallengeMessage(NTLMMessage):
    """NTLM Challenge Message"""
    DEFAULT_FLAGS = NTLM_FLAGS.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NTLM | NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE
    def __init__(self, NegFlg=None, TargetName=None, ServerChallenge=None, TargetInfo=None):
        """Constructs a new NTLM Challenge Message"""
        self.Header.Signature = NTLM_PROTOCOL_SIGNATURE
        self.Header.MessageType = NTLM_MESSAGE_TYPE.NtLmChallenge.const
        if NegFlg is None:
            self.set_negotiate_flags(self.DEFAULT_FLAGS)
        else:
            self.set_negotiate_flags(NegFlg)
        self.TargetName = TargetName
        self.ServerChallenge = ServerChallenge
        self.TargetInfo = TargetInfo

    @classmethod
    def _get_challenge_flags(cls, ClientFlg, CfgFlg):
	"""Checks for specific flags in the client request. See [MS-NLMP] page 32-34 for more details
	    ClientFlg 		- If this value is not None, overwrite the default flags. This argument should contain the flags set by
				  the client negotiate message.
	    CfgFlg		- List of flags configured by the server
	"""
	if CfgFlg is None:
	    CfgFlg = cls.DEFAULT_FLAGS

	if ClientFlg is None:
	    raise NTLM_Exception("Challenge message could not be created as no negotiate flags were set.")
	validClientFlags = cls.supported_flags(ClientFlg)

	#Set flags which MUST be set
	CfgFlg = cls.supported_flags(CfgFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NTLM | NTLM_FLAGS.NTLMSSP_REQUEST_TARGET)

	#Handle mutually exclusive flags
	TargetName_options = NTLM_FLAGS.NTLMSSP_TARGET_TYPE_SHARE | NTLM_FLAGS.NTLMSSP_TARGET_TYPE_SERVER | NTLM_FLAGS.NTLMSSP_TARGET_TYPE_DOMAIN
	selected_option = CfgFlg & TargetName_options
	#If selected_option is non-zero and not equal to exaclty one option, then multiple options must have been set
	if selected_option and selected_option not in (NTLM_FLAGS.NTLMSSP_TARGET_TYPE_SHARE, NTLM_FLAGS.NTLMSSP_TARGET_TYPE_SERVER,
						       NTLM_FLAGS.NTLMSSP_TARGET_TYPE_DOMAIN):
	    raise NTLM_Exception("Challenge message could not be created as conflicting TargetName types were requested.")

#TODO:: In the list below I have marked some items with a ?. This is because I'm not 100% clear on the specified behaviour
#In these cases, I've done what seems most sensible but this should be checked none the less.
	# * If the client sets NTLMSSP_NEGOTIATE_56 and (NTLMSSP_NEGOTIATE_SIGN or NTLMSSP_NEGOTIATE_SEAL), it MUST be set
	# * If client requests, NTLMSSP_NEGOTIATE_KEY_EXCHANGE and and (NTLMSSP_NEGOTIATE_SIGN or NTLMSSP_NEGOTIATE_SEAL), it MUST be set
	# * If the client sets NTLMSSP_NEGOTIATE_128 and (NTLMSSP_NEGOTIATE_SIGN or NTLMSSP_NEGOTIATE_SEAL), it MUST be set
	# * Set NTLMSSP_NEGOTIATE_VERSION if requested and supported
	# * Set NTLMSSP_NEGOTIATE_TARGET_INFO if requested, this MUST be supported
	# ? Set NTLMSSP_REQUEST_NON_NT_SESSION_KEY if requested. I am assuming that this flag is set on request but only
	#   if it is supported (The spec does not say otherwise) - [MS-NLMP] page 33
	# ? Set NTLMSSP_NEGOTIATE_IDENTIFY if requested. I am assuming that this flag is set on request but only
	#   if it is supported (The spec does not say otherwise) - [MS-NLMP] page 33
	# ? It isn't entirely clear that NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY must be supported on request, but it appears to be the case
	# ? Assume that client or server can set NTLMSSP_NEGOTIATE_NT_ONLY and that once set this must be supported (not explicitl stated)

	#If, for any of the cases below, "MUST Add" is true but the flag isn't supported, an NTLMException will be raised
	negotiate_sign = validClientFlags & NTLM_FLAGS.NTLMSSP_NEGOTIATE_SIGN
	negotiate_seal = validClientFlags & NTLM_FLAGS.NTLMSSP_NEGOTIATE_SEAL
	flags_to_check = [
	#	FLAG				|		MUST Add		|	Set if supported and requested
	("NTLMSSP_NEGOTIATE_56",			negotiate_sign or negotiate_seal,	True),
	("NTLMSSP_NEGOTIATE_KEY_EXCHANGE",		negotiate_sign or negotiate_seal,	False),
	("NTLMSSP_NEGOTIATE_128",			negotiate_sign or negotiate_seal,	True),
	("NTLMSSP_NEGOTIATE_VERSION",			False,					True),
	("NTLMSSP_NEGOTIATE_TARGET_INFO",		True,					True),
	("NTLMSSP_REQUEST_NON_NT_SESSION_KEY",		False,					True),
	("NTLMSSP_NEGOTIATE_IDENTIFY",			False,					True),
	("NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY",	True,					True),
	("NTLMSSP_NEGOTIATE_NT_ONLY",			True,					True),
	("NTLMSSP_NEGOTIATE_LM_KEY",			False, not (validClientFlags & NTLM_FLAGS.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)),
	("NTLMSSP_NEGOTIATE_DATAGRAM",			False,					True),
	("NTLMSSP_NEGOTIATE_SEAL",			negotiate_seal,				False),
	("NTLMSSP_NEGOTIATE_SIGN",			negotiate_sign,				False),
	("NTLMSSP_NEGOTIATE_OEM",not validClientFlags&NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE, 	False),
	("NTLMSSP_NEGOTIATE_UNICODE",			True, 					True),
	]

	for AddFlagName, MustAddCondition, SetAnyway in flags_to_check:
	    CfgFlg = CfgFlg | cls._add_flag_if_required(ClientFlg, AddFlagName, MustAddCondition, SetAnyway)

	#setting NTLMSSP_NEGOTIATE_SEAL should result in setting NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 (if they are supported)
	if CfgFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_SEAL:
	    CfgFlg = CfgFlg | cls.supported_flags(NTLM_FLAGS.NTLMSSP_NEGOTIATE_56 | NTLM_FLAGS.NTLMSSP_NEGOTIATE_128)

	#If NTLMSSP_NEGOTIATE_DATAGRAM is set, then NTLMSSP_NEGOTIATE_KEY_EXCHANGE MUST be set
	if CfgFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_DATAGRAM:
	    if not cls.supported_flags(NTLM_FLAGS.NTLMSSP_NEGOTIATE_KEY_EXCHANGE):
		raise NTLM_Exception("NTLM message could not set required flag 'NTLMSSP_NEGOTIATE_KEY_EXCHANGE'. The flag is not supported.")
	    CfgFlg = CfgFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_KEY_EXCHANGE

	#If NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY is set, set NTLMSSP_NEGOTIATE_TARGET_INFO - [MS-NLMP] page 52
	if CfgFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
	    if not cls.supported_flags(NTLM_FLAGS.NTLMSSP_NEGOTIATE_TARGET_INFO):
		raise NTLM_Exception("NTLM message could not set required flag 'NTLMSSP_NEGOTIATE_TARGET_INFO'. The flag is not supported.")
	    CfgFlg = CfgFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_TARGET_INFO

	return CfgFlg

    @classmethod
    def _add_flag_if_required(cls, ClientFlg, AddFlagName, MustAddCondition=False, SetAnyway=True):
	AddFlag = getattr(NTLM_FLAGS, AddFlagName)
	if not ClientFlg & AddFlag:
	    return 0
	if MustAddCondition:
	    if not cls.supported_flags(AddFlag):
		#Can't set unsupported flag when the flag MUST be set
		raise NTLM_Exception("NTLM message could not set required flag '%s'. The flag is not supported."%AddFlagName)
	    else:
		return AddFlag
	#Even if the flag is not required, it mey get set on request. Usually this is because the flag can be overriden or overrides another flag.
	elif SetAnyway and cls.supported_flags(AddFlag):
	    return AddFlag
	return 0

    @classmethod
    def create(cls, ClientFlg, CfgFlg, server_object):
	"""Returns an NTLM challenge message
	    ClientFlg		- Set of flags requested by the client
	    CfgFlg		- Set of flags required by the server
	    server_object	- Provides information about the server
	"""
	if not isinstance(server_object, ServerInterface):
	    raise NTLMException("The 'server_object' argument passed to 'create_challenge_message' must be of type 'ServerInterface'")

	NegFlg = cls._get_challenge_flags(ClientFlg, CfgFlg)

	if not server_object.negotiated_security_ok(NegFlg):
	    #TODO: must return SEC_E_UNSUPPORTED_FUNCTION
	    raise NotImplementedError("NOT IMPLEMENTED:: Server must return SEC_E_UNSUPPORTED_FUNCTION")

	#If NTLM_NEGOTIATE_OEM is set in NegFlg, then use OEM encoding. The flag could not have been set if NTLMSSP_NEGOTIATE_UNICODE
	#was set. If NTLMSSP_NEGOTIATE_UNICODE is set in NegFlg, then use unicode encoding. If neither flag is set, return SEC_E_INVALID_TOKEN
	encoding = cls.unicode if NegFlg&NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE else cls.oem if NegFlg&NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM else None
	if encoding is None:
	    #TODO: must return SEC_E_INVALID_TOKEN
	    raise NotImplementedError("NOT IMPLEMENTED:: Server must return SEC_E_INVALID_TOKEN")

	#Get server details
	NetBIOS_name = server_object.get_NetBIOS_name()
	NetBIOS_domain = server_object.get_NetBIOS_domain()
	DNS_name = server_object.get_DNS_name()
	DNS_domain = server_object.get_DNS_domain()
	DNS_forest_name = server_object.get_DNS_forest_name()

	TargetName = None
	TargetInfo = None

	#If NTLMSSP_REQUEST_TARGET is set in NegFlg, TargetName field MUST be supplied. Set TargetName according to type flags.
	if NTLM_FLAGS.NTLMSSP_REQUEST_TARGET & NegFlg:
	    if NTLM_FLAGS.NTLMSSP_TARGET_TYPE_SERVER & NegFlg:
		TargetName = NetBIOS_name.encode(encoding)
	    elif NTLM_FLAGS.NTLMSSP_TARGET_TYPE_DOMAIN & NegFlg:
		TargetName = NetBIOS_domain.encode(encoding)
	    else:
		raise NTLMException("Found NTLMSSP_REQUEST_TARGET in negotiated flag but could not determine the TargetName type")
	    #TODO - handle NTLMSSP_TARGET_TYPE_SHARE

	#If NTLMSSP_NEGOTIATE_TARGET_INFO is set, add TargetInfo - [MS-NLMP] page 32 & [MS-NLMP] page 52
	if NTLM_FLAGS.NTLMSSP_NEGOTIATE_TARGET_INFO & NegFlg:
	    TargetInfo = AV_PAIR_Handler()

	    if NetBIOS_name and isinstance(NetBIOS_name, basestring):
		TargetInfo.add_av_pair(AV_TYPES.MsvAvNbComputerName, NetBIOS_name.encode(cls.unicode))

	    if NetBIOS_domain and isinstance(NetBIOS_domain, basestring):
		TargetInfo.add_av_pair(AV_TYPES.MsvAvNbDomainName, NetBIOS_domain.encode(cls.unicode))

	    if DNS_name and isinstance(DNS_name, basestring):
		TargetInfo.add_av_pair(AV_TYPES.MsvAvDnsComputerName, DNS_name.encode(cls.unicode))

	    if DNS_domain and isinstance(DNS_domain, basestring):
		TargetInfo.add_av_pair(AV_TYPES.MsvAvDnsDomainName, DNS_domain.encode(cls.unicode))

	    if DNS_forest_name and isinstance(DNS_forest_name, basestring):
		TargetInfo.add_av_pair(AV_TYPES.MsvAvDnsTreeName, DNS_forest_name.encode(cls.unicode))

	    TargetInfo = TargetInfo.to_byte_string()

	#Create the default challenge message
	challenge_message = cls(NegFlg, TargetName, cls._get_nonce(), TargetInfo)

	#If NTLMSSP_NEGOTIATE_VERSION is set, add version information
	if NegFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_VERSION:
	    try:
		challenge_message._add_version_information()
	    except:
		#TODO - log a warning - The version info could not be supplied
		challenge_message.set_negotiate_flags(NegFlg ^ NTLM_FLAGS.NTLMSSP_NEGOTIATE_VERSION)

	return challenge_message


    TargetName = StringProperty("TargetName")
    ServerChallenge = BinaryProperty("ServerChallenge")
    # TODO: handle AV_PAIRs here
    TargetInfo = StringPropertyWithFlag("TargetInfo", NTLM_FLAGS.NTLMSSP_NEGOTIATE_TARGET_INFO)

#-----------------------------------------------------------------------------------------------
# NTLMAuthenticateMessageBase
#-----------------------------------------------------------------------------------------------

class NTLMAuthenticateMessageBase(NTLMMessage):
    """NTLM Authenticate Message"""
    def __init__(self, NegFlg=None, LmChallengeResponse=None, NtChallengeResponse=None, DomainName=None, UserName=None, Workstation=None, EncryptedRandomSessionKey=None):
        """Constructs a new NTLM Challenge Message"""
        self.Header.Signature = NTLM_PROTOCOL_SIGNATURE
        self.Header.MessageType = NTLM_MESSAGE_TYPE.NtLmAuthenticate.const
        if NegFlg is not None:
            self.set_negotiate_flags(NegFlg)
        self.LmChallengeResponse = LmChallengeResponse
        self.NtChallengeResponse = NtChallengeResponse
        self.DomainName = DomainName
        self.UserName = UserName
        self.Workstation = Workstation
        self.EncryptedRandomSessionKey = EncryptedRandomSessionKey

    @classmethod
    def create(cls, NegFlg, client_object):
        """TODO - Implement this"""

    @classmethod
    @unimplemented
    def create_LM_hashed_password(cls, password, user, domain, encoding):
	"""Returns an LM hashed password based on the NTLM version implementation.
	   user and domain are required for v2 and can just be ignored for version 1"""

    @classmethod
    @unimplemented
    def create_NT_hashed_password(cls, password, user, domain, encoding):
	"""Returns a NT hashed password based on the NTLM version implementation.
	   user and domain are required for v2 and can just be ignored for version 1"""

    @classmethod
    @unimplemented
    def compute_response(cls, NegFlg, password, user, domain, ServerChallenge, ClientChallenge, Time, ServerName, encoding):
	"""Returns NTChallengeResponse and LmChallengeResponse values based on the NTLM version implementation.
	   Where either of these return values is none, its xChallengeResponseLen, xChallengeResponseMaxLen and
	   xChallengeResponseBufferOffset values should be set to 0 in the calling scope.
	   user and domain are required for v2 and can just be ignored for version 1"""

    LmChallengeResponse = StringProperty("LmChallengeResponse")
    NtChallengeResponse = StringProperty("NtChallengeResponse")
    DomainName = StringProperty("DomainName")
    UserName = StringProperty("UserName")
    Workstation = StringProperty("Workstation")
    EncryptedRandomSessionKey = StringProperty("EncryptedRandomSessionKey")

#-----------------------------------------------------------------------------------------------
# NTLMAuthenticateMessageV1
#-----------------------------------------------------------------------------------------------

class NTLMAuthenticateMessageV1(NTLMAuthenticateMessageBase):

    @classmethod
    def create_LM_hashed_password(cls, password, user, domain, encoding):
	"setup LanManager password"
        "create LanManager hashed password"
        #Code taken from the original python-ntlm implementation
        # fix the password length to 14 bytes
        password = password.upper()
        lm_pw = password + '\0' * (14 - len(password))
        lm_pw = password[0:14]

        # do hash
        magic_str = "KGS!@#$%" # page 57 in [MS-NLMP]

        res = ''
        dobj = des.DES(lm_pw[0:7])
        res = res + dobj.encrypt(magic_str)

        dobj = des.DES(lm_pw[7:14])
        res = res + dobj.encrypt(magic_str)

        return res

    @classmethod
    def create_NT_hashed_password(cls, password, user, domain, encoding):
	return hashlib.new('md4', password.encode(cls.unicode)).digest()

    @classmethod
    def compute_response(cls, NegFlg, password, user, domain, ServerChallenge, ClientChallenge, Time, ServerName, encoding):
	ResponseKeyNT = cls.create_NT_hashed_password(password, user, domain, encoding)
	ResponseKeyLM = cls.create_LM_hashed_password(password, user, domain, encoding)
	NTChallengeResponse=None
	LmChallengeResponse=None
	#TODO - the string below contains the logic for LM Authentication but it is not clear whether NTLM_FLAGS.NTLMSSP_NEGOTIATE_LM_KEY
	#means that LM Authentication is being used. Determine whether or not this code is correct
	"""if NegFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_LM_KEY and not NegFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
	    #Leave NTChallengeResponse=None
	    #TODO - make sure that NtChallengeResponseLen, NtChallengeResponseMaxLen and NtChallengeResponseBufferOffset are set to 0
	    #by the calling function
	    LmChallengeResponse = desl(ResponseKeyLM, ServerChallenge)
	elif NegFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:"""
	if NegFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
	    challenge = hashlib.md5(ServerChallenge+ClientChallenge).digest()
	    NTChallengeResponse = desl(ResponseKeyNT, challenge[0:8])
	    LmChallengeResponse = ClientChallenge + '\0' * 16
	else:
	    NTChallengeResponse = desl(ResponseKeyNT, ServerChallenge)

	    if NegFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_NT_ONLY:
		LmChallengeResponse = NTChallengeResponse
	    else:
		LmChallengeResponse = desl(ResponseKeyLM, ServerChallenge)

	return ResponseData(ResponseKeyNT,
			    ResponseKeyLM,
			    NTChallengeResponse,
			    LmChallengeResponse,
			    hashlib.new('md4', ResponseKeyNT).digest())

#-----------------------------------------------------------------------------------------------
# NTLMAuthenticateMessageV2
#-----------------------------------------------------------------------------------------------

class NTLMAuthenticateMessageV2(NTLMAuthenticateMessageBase):

    @classmethod
    def create_LM_hashed_password(cls, password, user, domain, encoding):
	return cls.create_NT_hashed_password(password, user, domain, encoding)

    @classmethod
    def create_NT_hashed_password(cls, password, user, domain, encoding):
	digest = hashlib.new('md4', password.encode(cls.unicode)).digest()
	return hmac.new(digest, (user.upper()+domain).encode(encoding)).digest()

    @classmethod
    def compute_response(cls, NegFlg, password, user, domain, ServerChallenge, ClientChallenge, Time, ServerName, encoding):
	ResponseKeyNT = cls.create_NT_hashed_password(password, user, domain, encoding)
	ResponseKeyLM = cls.create_LM_hashed_password(password, user, domain, encoding)
	NTChallengeResponse=None
	LmChallengeResponse=None

	#TODO get proper values for the hardcoded values Responserversion and HiResponserversion
	HiResponserversion = Responserversion = "\x01"
	temp = cls._temp(Responserversion, HiResponserversion, Time, ClientChallenge, ServerName)

	NTProofStr = cls._nt_proof_str(ResponseKeyNT, ServerChallenge, temp)
	SessionBaseKey = hmac.new(ResponseKeyNT, NTProofStr).digest()

	NTChallengeResponse = NTProofStr + temp
	LmChallengeResponse = hmac.new(ResponseKeyLM, ServerChallenge + ClientChallenge).digest() + ClientChallenge


	return ResponseData(ResponseKeyNT,
			    ResponseKeyLM,
			    NTChallengeResponse,
			    LmChallengeResponse,
			    SessionBaseKey)

    @classmethod
    def _nt_proof_str(cls, ResponseKeyNT, ServerChallenge, temp):
	return hmac.new(ResponseKeyNT, ServerChallenge+temp).digest()

    @classmethod
    def _temp(cls, Responserversion, HiResponserversion, Time, ClientChallenge, ServerName):
	return Responserversion + HiResponserversion + '\x00'*6 + Time + ClientChallenge + '\x00'*4 + ServerName + '\x00'*4
