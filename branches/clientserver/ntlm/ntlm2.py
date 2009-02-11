#!/usr/bin/env python

import ctypes
import pprint

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

class FieldType:
    def __init__(self, name, const, comment):
        self.name, self.const, self.comment = name, const, comment

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

class NTLM_MESSAGE_TYPE(EnumType):
    NtLmNegotiate = FieldType("NtLmNegotiate", 0x1, "The message is a NEGOTIATE_MESSAGE.")
    NtLmChallenge = FieldType("NtLmChallenge", 0x2, "The message is a CHALLENGE_MESSAGE.")
    NtLmAuthenticate = FieldType("NtLmAuthenticate", 0x3, "The message is an AUTHENTICATE_MESSAGE.")

class NTLM_REVISION_TYPE(EnumType):
    NTLMSSP_REVISION_W2K3 = FieldType("NTLMSSP_REVISION_W2K3", 0x0F, "Version 15 of the NTLMSSP is in use.")
    NTLMSSP_REVISION_W2K3_RC1 = FieldType("NTLMSSP_REVISION_W2K3_RC1", 0x0A, "Version 10 of the NTLMSSP is in use.")

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

class NTLMMessageDependentFieldsHandler(ctypes.LittleEndianStructure, FileStructure):
    def get_string_fields(self):
        return [field_name for field_name, field_type in self._fields_ if field_type == StringHeader]

    def get_max_payload(self):
        return max(getattr(self, field_name).get_max_offset() for field_name in self.get_string_fields())

    def read_payload(self, f):
        size = self.get_max_payload()
        disk_block = (ctypes.c_uint8*size)(*[ord(b) for b in f.read(size)])
        return disk_block

class NTLMVersionStructure(ctypes.LittleEndianStructure, FileStructure):
    _pack_ = 1
    _fields_ = [("ProductMajorVersion", ctypes.c_uint8),
                ("ProductMinorVersion", ctypes.c_uint8),
                ("ProductBuild", ctypes.c_uint16),
                ("Reserved", ctypes.c_uint8*3),
                ("NTLMRevisionCurrent", ctypes.c_uint8),
               ]

class AV_PAIR(ctypes.LittleEndianStructure, FileStructure):
    _pack_ = 1
    _fields_ = [("AvId", ctypes.c_uint16),
                ("AvLen", ctypes.c_uint16),
                ("Value", ctypes.POINTER(ctypes.c_uint8)),
               ]

    @classmethod
    def create(cls, AvId, Value):
        disk_block = (ctypes.c_uint8*4)(*[0,0,0,0])
        s = ctypes.cast(disk_block, ctypes.POINTER(cls)).contents
        s.AvId = AvId
        s.AvLen = len(Value)
        s.Value = (ctypes.c_uint8*s.AvLen)(*[ord(b) for b in Value])
        s.verify()
        return s

    @classmethod
    def read(cls, f):
        disk_block = (ctypes.c_uint8*4)(*[ord(b) for b in f.read(4)])
        s = ctypes.cast(disk_block, ctypes.POINTER(cls)).contents
        s.Value = (ctypes.c_uint8*s.AvLen)(*[ord(b) for b in f.read(s.AvLen)])
        s.verify()
        return s

    def value_byte_string(self):
        return "".join([chr(x) for x in self.Value[0:self.AvLen]])


class NTLMMessageNegotiateFields(NTLMMessageDependentFieldsHandler):
    _pack_ = 1
    _fields_ = [("NegotiateFlags", ctypes.c_uint32),
                ("DomainName", StringHeader),
                ("Workstation", StringHeader),
               ]

class NTLMMessageChallengeFields(NTLMMessageDependentFieldsHandler):
    _pack_ = 1
    _fields_ = [("TargetName", StringHeader),
                ("NegotiateFlags", ctypes.c_uint32),
                ("ServerChallenge", ctypes.c_uint8 * 8),
                ("Reserved", ctypes.c_uint8 * 8),
                ("TargetInfo", StringHeader),
               ]

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

class NTLMOptionalFields(ctypes.LittleEndianStructure, FileStructure):
    _pack_ = 1
    _fields_ = [("Version", NTLMVersionStructure),
                ("MIC", ctypes.c_uint8*16),
               ]

class NTLMMessage(ctypes.LittleEndianStructure, FileStructure):
    _pack_ = 1
    _fields_ = [("Header", NTLMMessageHeader),
                ("MessageDependentFields", NTLMMessageDependentFields),
                ("payload", ctypes.POINTER(ctypes.c_uint8)),
               ]

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

class FlagProperty(property):
    """This represents a flag in the Negotiate header"""
    def __init__(self, field_name):
        self.field_name = field_name
        def fget(message):
            return message.get_negotiate_flag(self.field_name)
        def fset(message, value):
            return message.set_negotiate_flag(self.field_name, value)
        property.__init__(self, fget, fset, fdel)

class NTLMNegotiateMessage(NTLMMessage):
    """NTLM Negotiate Message"""
    DEFAULT_FLAGS = NTLM_FLAGS.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NTLM | NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE
    def __init__(self, DomainName=None, Workstation=None):
        """Constructs a new NTLM Negotiate Message"""
        self.Header.Signature = NTLM_PROTOCOL_SIGNATURE
        self.Header.MessageType = NTLM_MESSAGE_TYPE.NtLmNegotiate.const
        self.set_negotiate_flags(self.DEFAULT_FLAGS)
        self.DomainName = DomainName
        self.Workstation = Workstation

    DomainName = StringPropertyWithFlag("DomainName", NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED)
    Workstation = StringPropertyWithFlag("Workstation", NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED)

class NTLMChallengeMessage(NTLMMessage):
    """NTLM Challenge Message"""
    DEFAULT_FLAGS = NTLM_FLAGS.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NTLM | NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE
    def __init__(self, TargetName=None, ServerChallenge=None, TargetInfo=None):
        """Constructs a new NTLM Challenge Message"""
        self.Header.Signature = NTLM_PROTOCOL_SIGNATURE
        self.Header.MessageType = NTLM_MESSAGE_TYPE.NtLmChallenge.const
        self.set_negotiate_flags(self.DEFAULT_FLAGS)
        self.TargetName = TargetName
        self.ServerChallenge = ServerChallenge
        self.TargetInfo = TargetInfo

    TargetName = StringProperty("TargetName")
    ServerChallenge = BinaryProperty("ServerChallenge")
    # TODO: handle AV_PAIRs here
    TargetInfo = StringPropertyWithFlag("TargetInfo", NTLM_FLAGS.NTLMSSP_NEGOTIATE_TARGET_INFO)
