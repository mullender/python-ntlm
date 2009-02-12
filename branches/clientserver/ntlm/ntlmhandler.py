#!/usr/bin/env python

import sys
import ntlm
import ntlm2
from ntlm2 import NTLM_FLAGS, AV_TYPES
import des
import hashlib
import hmac
import StringIO

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
		self._AV_PAIRS.append(ntlm2.AV_PAIR.create(pair[0], pair[1]))

    def _set_av_pairs_from_bytes(self, bytes):
	self._AV_PAIRS = []
	stringio = StringIO.StringIO(bytes)
	while True:
	    current = ntlm2.AV_PAIR.read(stringio)
	    if current.Header.AvId == AV_TYPES.MsvAvEOL:
		break
	    if isinstance(current, ntlm2.AV_PAIR):
		#Don't bother to read the Terminating AV pair as it is not needed
		self._AV_PAIRS.append(current)

    def add_av_pair(self, AvId, Value):
	#Assumes that Value is already encoded as a "utf-16le" Byte String
	self._AV_PAIRS.append((AvId, Value))

    def to_byte_string(self):
	"""Convert List of AV_PAIRs to an encoded ByteString, which can be used in an NTLM message"""
	result = ""
	for pair in self._AV_PAIRS:
	    result += pair.to_byte_string()
	#Add terminating AV_PAIR
	result += ntlm2.AV_PAIR.create(AV_TYPES.MsvAvEOL, "").to_byte_string()
	return result

#-----------------------------------------------------------------------------------------------
# BaseHandler
#-----------------------------------------------------------------------------------------------

class BaseHandler(object):
    """Base class for a set of NTLM helpers which encapsulate the logic used to encode NTLM messages.
       This should make it easy to switch between versions of NTLM."""

    unicode = 'utf-16le'

    #List of flags that do not have to be supported
    optional_flags = (NTLM_FLAGS.NTLMSSP_NEGOTIATE_56 | NTLM_FLAGSNTLMSSP_NEGOTIATE_KEY_EXCH | NTLM_FLAGS.NTLMSSP_NEGOTIATE_128
		     |NTLM_FLAGS.NTLMSSP_NEGOTIATE_VERSION | NTLM_FLAGS.NTLMSSP_REQUEST_NON_NT_SESSION_KEY | NTLM_FLAGS.NTLMSSP_NEGOTIATE_IDENTIFY
		     |NTLM_FLAGS.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
		     |NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NT_ONLY | NTLM_FLAGS.NTLMSSP_NEGOTIATE_LM_KEY
		     |NTLM_FLAGS.NTLMSSP_NEGOTIATE_DATAGRAM | NTLM_FLAGS.NTLMSSP_NEGOTIATE_SEAL | NTLM_FLAGS.NTLMSSP_NEGOTIATE_SIGN
		     |NTLM_FLAGS.NTLM_NEGOTIATE_OEM | NTLM_FLAGS.NTLMSSP_TARGET_TYPE_SHARE | NTLM_FLAGS.NTLMSSP_TARGET_TYPE_SERVER
		     |NTLM_FLAGS.NTLMSSP_TARGET_TYPE_DOMAIN)

    def __init__(self, encoding='utf-16le', unsupported_flags=0):
	""" encoding determines the default format in which to encode data. In some cases the specification explicitly defines the
	    format to be used in which case the default encoding is ignored.
	    supported_flags contains a series of bits indicating which flags are supported by the client/server. If this value is
	    None, then all flags are assumed to be supported
	"""
	self.encoding = encoding
	self.unsupported_flags = unsupported_flags & self.optional_flags

    def create_negotiate_message(self, NegFlg=None, domain=None, workstation=None):
	"""Returns an NTLM negotiate message
	    NegFlg 		- If this value is not None, overwrite the default flags
	    domain 		- If this value is not None, include domain in the message. Value should be an unencoded string.
	    workstation 	- If this value is not None, include workstation in the message. Value should be an unencoded string.
	"""
	if NegFlg is None:
	    NegFlg = ntlm2.NTLMNegotiateMessage.DEFAULT_FLAGS

	#Negotiate message MUST set these flags - [MS-NLMP] pages 33 and 34
	NegFlg = NegFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NTLM

	#Filter the Negotiate Flags down to those which are actually supported. By default all flags are supported.
	NegFlg = self.supported_flags(NegFlg)

	#Set any flags which are required by current flags. Eg Setting NTLMSSP_NEGOTIATE_SEAL requires that NTLMSSP_NEGOTIATE_56
	#gets set if it is supported. For now, just set all required flags and remove all unsupported flags later.
	if NegFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_SEAL:
	    NegFlg = NegFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_56
	    NegFlg = NegFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_128

	#Additional flags may have been added. Filter the Negotiate Flags down to those which are actually supported.
	NegFlg = self.supported_flags(NegFlg)

	#Check that a choice of encoding can still be negotiated.
	if not NegFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM and not NegFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE:
	    if self.supported_flags(NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE):
		NegFlg = NegFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE
	    elif self.supported_flags(NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM):
		NegFlg = NegFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM
	    else:
		raise NTLM_Exception("Could not set NTLM_NEGOTIATE_OEM or NTLMSSP_NEGOTIATE_UNICODE flags")

	#Ready to create the negotiate message
	negotiate_message = ntlm2.NTLMMessage()
	negotiate_message.Header.Signature = ntlm2.NTLM_PROTOCOL_SIGNATURE
        negotiate_message.Header.MessageType = ntlm2.NTLM_MESSAGE_TYPE.NtLmNegotiate.const

	if workstation is not None and self.supported_flags(NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED):
	    NegFlg = NegFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
	    negotiate_message.set_string_field("Workstation", workstation)

	if domain is not None and self.supported_flags(NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED):
	    NegFlg = NegFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
	    negotiate_message.set_string_field("DomainName", domain)

	#Prepare values for OS version information
	if NegFlg & NTLM_FLAGS.NTLMSSP_NEGOTIATE_VERSION:
	    try:
		major, minor, build, platform, text = sys.getwindowsversion()
		#TODO - Revision version MUST have one of the values below - work out which
		#NTLMSSP_REVISION_W2K3 		0x0F 	 Version 15 of the NTLMSSP is in use.
		#NTLMSSP_REVISION_W2K3_RC1 	0x0A	 Version 10 of the NTLMSSP is in use.
		version = negotiate_message.get_version_field()
		version.ProductMajorVersion = major
		version.ProductMinorVersion = minor
		version.ProductBuild = build
		version.NTLMRevisionCurrent = 0xf #Just hardcode a value for now
	    except:
		#TODO - log a warning - The version info could not be supplied
		NegFlg = NegFlg ^ NTLM_FLAGS.NTLMSSP_NEGOTIATE_VERSION

	negotiate_message.set_negotiate_flags(NegFlg)
	return negotiate_message.get_message_contents()

    def _get_challenge_flags(self, ClientFlg, NegFlg):
	"""Checks for specific flags in the client request. See [MS-NLMP] page 32-34 for more details"""
	if ClientFlg is None:
	    raise NTLM_Exception("Challenge message could not be created as no negotiate flags were set.")
	validClientFlags = self.supported_flags(ClientFlg)

	#Set flags which MUST be set
	NegFlg = NegFlg | NTLM_FLAGS.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLM_FLAGS.NTLMSSP_NEGOTIATE_NTLM

	#Handle mutually exclusive flags
	TargetName_options = NTLM_FLAGS.NTLMSSP_TARGET_TYPE_SHARE | NTLM_FLAGS.NTLMSSP_TARGET_TYPE_SERVER | NTLM_FLAGS.NTLMSSP_TARGET_TYPE_DOMAIN
	selected_option = NegFlg & TargetName_options
	#If selected_option is non-zero and not equal to exaclty one option, then multiple options must have been set
	if selected_option and selected_option not in (NTLM_FLAGS.NTLMSSP_TARGET_TYPE_SHARE, NTLM_FLAGS.NTLMSSP_TARGET_TYPE_SERVER,
						       NTLM_FLAGS.NTLMSSP_TARGET_TYPE_DOMAIN):
	    raise NTLM_Exception("Challenge message could not be created as conflicting TargetName types were requested.")

#TODO:: In the list below I have marked some items with a ?. This is because I'm not 100% clear on the specified behaviour
#In these cases, I've done what seems most sensible but this should be checked none the less.
	# * If the client sets NTLMSSP_NEGOTIATE_56 and (NTLMSSP_NEGOTIATE_SIGN or NTLMSSP_NEGOTIATE_SEAL), it MUST be set
	# * If client requests, NTLMSSP_NEGOTIATE_KEY_EXCH and and (NTLMSSP_NEGOTIATE_SIGN or NTLMSSP_NEGOTIATE_SEAL), it MUST be set
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
	("NTLMSSP_NEGOTIATE_KEY_EXCH",			negotiate_sign or negotiate_seal,	False),
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
	("NTLM_NEGOTIATE_OEM",	not validClientFlags&NTLM_FLAGS.NTLMSSP_NEGOTIATE_UNICODE, 	False),
	("NTLMSSP_NEGOTIATE_UNICODE",			True, 					True),
	]

	for AddFlagName, MustAddCondition, SetAnyway in flags_to_check:
	    NegFlg = NegFlg | self._add_flag_if_required(ClientFlg, AddFlagName, MustAddCondition, SetAnyway)

	return NegFlg

    def create_challenge_message(self, ClientFlg, NegFlg=None, target_name=None, target_info=None, server_challenge=None):
	"""Returns an NTLM challenge message
	    ClientFlg 		- If this value is not None, overwrite the default flags. This argument should contain the flags set by
				  the client negotiate message.
	    NegFlg		- Desired settings for server related flags
	    target_name 	- If this value is not None, include target_name in the message. Value should be an unencoded string.
	    target_info 	- If this value is not None, include target_info in the message. Value should be a list. Each element in
				  the list should be a tuple containing an AvId and Value. Values should be unencoded strings.
	    server_challenge 	- If this value is not None, include server_challenge in the message. Value should be an unencoded string.
	"""
	if NegFlg is None:
	    NegFlg = ntlm2.NTLMChallengeMessage.DEFAULT_FLAGS
	#Determine the correct flag settings
	NegFlg = self._get_challenge_flags(ClientFlg, self.supported_flags(NegFlg))

	#TODO - setting NTLMSSP_NEGOTIATE_SEAL should result in setting NTLMSSP_NEGOTIATE_56 (if it is supported)
	#TODO - setting NTLMSSP_NEGOTIATE_SEAL should result in setting NTLMSSP_NEGOTIATE_128 (if it is supported)

	#TODO - If NTLMSSP_NEGOTIATE_VERSION is set, add version information

	#TODO - If NTLMSSP_NEGOTIATE_TARGET_INFO is set, add TargetInfo - [MS-NLMP] page 32

	#TODO - If NTLMSSP_REQUEST_NON_NT_SESSION_KEY is set, use LMOWF - [MS-NLMP] page 33

	#TODO - Set TargetName according to type flags - NTLMSSP_TARGET_TYPE_SHARE, NTLMSSP_TARGET_TYPE_SERVER or is NTLMSSP_TARGET_TYPE_DOMAIN

	#TODO - If NTLMSSP_NEGOTIATE_LM_KEY is set, provide LAN Manager (LM) session key

	#TODO - If NTLMSSP_NEGOTIATE_DATAGRAM is set, then NTLMSSP_NEGOTIATE_KEY_EXCH MUST be set

	#TODO - If NTLMSSP_NEGOTIATE_SEAL is set, handle session key negotiation for message confidentiality

	#TODO - If NTLMSSP_NEGOTIATE_SIGN is set, handle session key negotiation for message signatures

	#TODO - If NTLMSSP_REQUEST_TARGET is set in ClientFlg, TargetName field MUST be supplied

	#TODO - If NTLM_NEGOTIATE_OEM is set in NegFlg, then use OEM encoding. The flag could not have been set if NTLMSSP_NEGOTIATE_UNICODE
	#was set. If NTLMSSP_NEGOTIATE_UNICODE is set in NegFlg, then use unicode encoding. If neither flag is set, return SEC_E_INVALID_TOKEN

	#Create the default challenge message
	challenge_message = ntlm2.NTLMChallengeMessage()


    def create_authenticate_message(self):
	"""Still need to decide what arguments this should take"""

    def create_LM_hashed_password(self, password, user, domain):
	"""Returns an LM hashed password based on the NTLM version implementation.
	   user and domain are required for v2 and can just be ignored for version 1"""
	raise NotImplementedError("%s.%s needs a \"create_LM_hashed_password\" function"%(self.__class__.__module__, self.__class__.__name__))

    def create_NT_hashed_password(self, password, user, domain):
	"""Returns a NT hashed password based on the NTLM version implementation.
	   user and domain are required for v2 and can just be ignored for version 1"""
	raise NotImplementedError("%s.%s needs a \"create_NT_hashed_password\" function"%(self.__class__.__module__, self.__class__.__name__))

    def compute_response(self, NegFlg, password, user, domain, ServerChallenge, ClientChallenge, Time, ServerName):
	"""Returns NTChallengeResponse and LmChallengeResponse values based on the NTLM version implementation.
	   Where either of these return values is none, its xChallengeResponseLen, xChallengeResponseMaxLen and
	   xChallengeResponseBufferOffset values should be set to 0 in the calling scope.
	   user and domain are required for v2 and can just be ignored for version 1"""
	raise NotImplementedError("%s.%s needs a \"compute_response\" function"%(self.__class__.__module__, self.__class__.__name__))

    def supported_flags(self, flags):
	"""Function filters out any flags not supported by client/server"""
	temp = flags | self.unsupported_flags
	return temp ^ self.unsupported_flags

    def _add_flag_if_required(self, ClientFlg, AddFlagName, MustAddCondition=False, SetAnyway=True):
	AddFlag = getattr(NTLM_FLAGS, AddFlagName)
	if not ClientFlg & AddFlag:
	    return 0
	if MustAddCondition:
	    if not self.supported_flags(AddFlag):
		#Can't set unsupported flag when the flag MUST be set
		raise NTLM_Exception("NTLM message could not set required flag '%s'. The flag is not supported."%AddFlagName)
	    else:
		return AddFlag
	#Even if the flag is not required, it mey get set on request. Usually this is because the flag can be overriden or overrides another flag.
	elif SetAnyway and self.supported_flags(AddFlag):
	    return AddFlag
	return 0

#TODO - FLAGS TO RESOLVE
#NTLMSSP_NEGOTIATE_IDENTIFY - [MS-NLMP] page 33 - Has this been handled. Which messages should take account of this flag?
#NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY must be supported by NTLM v1 handler
#If NTLMSSP_NEGOTIATE_DATAGRAM is set, the use connectionless authentication. Make sure connectionless authentication is supported.

#-----------------------------------------------------------------------------------------------
# NTLMHandler_v1
#-----------------------------------------------------------------------------------------------

#TODO :: Enable support of Version 2 session security in NTLMv1Handler
#Note: NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY is used to request version 2 session security for a version 1 client/server
#This requires NTLMHandler_v1 but with access to version 2 security.

class NTLMHandler_v1(BaseHandler):

    def __init__(self, encoding='utf-16le', unsupported_flags=0):
	super(NTLMHandler_v1, self).__init__(encoding,unsupported_flags)
	#Mark NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY as unsupported, since NTLM v2 security features must be supported
	#in order to support this flag
	self.unsupported_flags = self.unsupported_flags | NTLM_FLAGS.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY

    def create_LM_hashed_password(self, password, user, domain):
	return ntlm.create_LM_hashed_password_v1(password)

    def create_NT_hashed_password(self, password, user, domain):
	return hashlib.new('md4', password.encode(self.unicode)).digest()

    def compute_response(self, NegFlg, password, user, domain, ServerChallenge, ClientChallenge, Time, ServerName):
	ResponseKeyNT = self.create_NT_hashed_password(password, user, domain)
	ResponseKeyLM = self.create_LM_hashed_password(password, user, domain)
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
# NTLMHandler_v2
#-----------------------------------------------------------------------------------------------

class NTLMHandler_v2(BaseHandler):

    def create_LM_hashed_password(self, password, user, domain):
	return self.create_NT_hashed_password(password, user, domain)

    def create_NT_hashed_password(self, password, user, domain):
	digest = hashlib.new('md4', password.encode(self.unicode)).digest()
	return hmac.new(digest, (user.upper()+domain).encode(self.encoding)).digest()

    def compute_response(self, NegFlg, password, user, domain, ServerChallenge, ClientChallenge, Time, ServerName):
	ResponseKeyNT = self.create_NT_hashed_password(password, user, domain)
	ResponseKeyLM = self.create_LM_hashed_password(password, user, domain)
	NTChallengeResponse=None
	LmChallengeResponse=None

	#TODO get proper values for the hardcoded values Responserversion and HiResponserversion
	HiResponserversion = Responserversion = "\x01"
	temp = self._temp(Responserversion, HiResponserversion, Time, ClientChallenge, ServerName)

	NTProofStr = self._nt_proof_str(ResponseKeyNT, ServerChallenge, temp)
	SessionBaseKey = hmac.new(ResponseKeyNT, NTProofStr).digest()

	NTChallengeResponse = NTProofStr + temp
	LmChallengeResponse = hmac.new(ResponseKeyLM, ServerChallenge + ClientChallenge).digest() + ClientChallenge


	return ResponseData(ResponseKeyNT,
			    ResponseKeyLM,
			    NTChallengeResponse,
			    LmChallengeResponse,
			    SessionBaseKey)

    def _nt_proof_str(self, ResponseKeyNT, ServerChallenge, temp):
	return hmac.new(ResponseKeyNT, ServerChallenge+temp).digest()

    def _temp(self, Responserversion, HiResponserversion, Time, ClientChallenge, ServerName):
	return Responserversion + HiResponserversion + '\x00'*6 + Time + ClientChallenge + '\x00'*4 + ServerName + '\x00'*4
