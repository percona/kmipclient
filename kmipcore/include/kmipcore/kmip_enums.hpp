/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 *
 * C++20 version of KMIP enumerations and constants.
 */

#ifndef KMIPCORE_KMIP_ENUMS_HPP
#define KMIPCORE_KMIP_ENUMS_HPP

#include <cstddef>
#include <cstdint>
#include <ostream>

namespace kmipcore {

  // ---------------------------------------------------------------------------
  // Constants
  // ---------------------------------------------------------------------------

  /**
   * Default maximum encoded KMIP message size used by helpers.
   *
   * KMIP specification defines Maximum Response Size as an optional header
   * field and does not mandate a fixed global cap; this value is an
   * implementation default.
   */
  inline constexpr std::size_t KMIP_MAX_MESSAGE_SIZE = 1024 * 1024;
  /**
   * Absolute response-size guard applied on receive path.
   *
   * This hard cap prevents unbounded memory growth even if a caller passes an
   * excessively large Maximum Response Size hint.
   */
  inline constexpr std::size_t KMIP_MAX_MESSAGE_HARD_LIMIT = 16 * 1024 * 1024;
  /**
   * Maximum nesting depth accepted when deserializing a TTLV structure tree.
   *
   * The wire format allows arbitrarily deep nesting, which would otherwise
   * let a malicious peer drive unbounded recursion in the parser and exhaust
   * the call stack. Real KMIP messages are only a handful of levels deep
   * (Response Message -> Batch Item -> Payload -> Key Block -> Key Value ->
   * Attributes -> Attribute -> Attribute Value), so this cap leaves ample
   * headroom for valid traffic while bounding stack usage.
   */
  inline constexpr unsigned KMIP_MAX_STRUCTURE_DEPTH = 64;
  /** Suggested buffer size for human-readable error messages. */
  inline constexpr std::size_t KMIP_ERROR_MESSAGE_SIZE = 200;

  /** Canonical KMIP boolean true value. */
  inline constexpr bool KMIP_TRUE = true;
  /** Canonical KMIP boolean false value. */
  inline constexpr bool KMIP_FALSE = false;

  /** Generic sentinel value representing unset enum/int fields. */
  inline constexpr std::int32_t KMIP_UNSET = -1;

  inline constexpr std::int32_t KMIP_OK = 0;
  inline constexpr std::int32_t KMIP_NOT_IMPLEMENTED = -1;
  inline constexpr std::int32_t KMIP_ERROR_BUFFER_FULL = -2;
  inline constexpr std::int32_t KMIP_ERROR_ATTR_UNSUPPORTED = -3;
  inline constexpr std::int32_t KMIP_TAG_MISMATCH = -4;
  inline constexpr std::int32_t KMIP_TYPE_MISMATCH = -5;
  inline constexpr std::int32_t KMIP_LENGTH_MISMATCH = -6;
  inline constexpr std::int32_t KMIP_PADDING_MISMATCH = -7;
  inline constexpr std::int32_t KMIP_BOOLEAN_MISMATCH = -8;
  inline constexpr std::int32_t KMIP_ENUM_MISMATCH = -9;
  inline constexpr std::int32_t KMIP_ENUM_UNSUPPORTED = -10;
  inline constexpr std::int32_t KMIP_INVALID_FOR_VERSION = -11;
  inline constexpr std::int32_t KMIP_MEMORY_ALLOC_FAILED = -12;
  inline constexpr std::int32_t KMIP_IO_FAILURE = -13;
  inline constexpr std::int32_t KMIP_EXCEED_MAX_MESSAGE_SIZE = -14;
  inline constexpr std::int32_t KMIP_MALFORMED_RESPONSE = -15;
  inline constexpr std::int32_t KMIP_OBJECT_MISMATCH = -16;
  inline constexpr std::int32_t KMIP_ARG_INVALID = -17;
  inline constexpr std::int32_t KMIP_ERROR_BUFFER_UNDERFULL = -18;
  inline constexpr std::int32_t KMIP_INVALID_ENCODING = -19;
  inline constexpr std::int32_t KMIP_INVALID_FIELD = -20;
  inline constexpr std::int32_t KMIP_INVALID_LENGTH = -21;

  // ---------------------------------------------------------------------------
  // Enumerations
  // ---------------------------------------------------------------------------

  enum class attestation_type : std::uint32_t {
    // KMIP 1.2
    KMIP_ATTEST_TPM_QUOTE = 0x01,
    KMIP_ATTEST_TCG_INTEGRITY_REPORT = 0x02,
    KMIP_ATTEST_SAML_ASSERTION = 0x03
  };

  enum class attribute_type : std::uint32_t {
    // KMIP 1.0
    KMIP_ATTR_UNIQUE_IDENTIFIER = 0,
    KMIP_ATTR_NAME = 1,
    KMIP_ATTR_OBJECT_TYPE = 2,
    KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM = 3,
    KMIP_ATTR_CRYPTOGRAPHIC_LENGTH = 4,
    KMIP_ATTR_OPERATION_POLICY_NAME = 5,
    KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK = 6,
    KMIP_ATTR_STATE = 7,
    KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION = 8,
    KMIP_ATTR_OBJECT_GROUP = 9,
    KMIP_ATTR_ACTIVATION_DATE = 10,
    KMIP_ATTR_DEACTIVATION_DATE = 11,
    KMIP_ATTR_PROCESS_START_DATE = 12,
    KMIP_ATTR_PROTECT_STOP_DATE = 13,
    KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS = 14
  };

  enum class batch_error_continuation_option : std::uint32_t {
    // KMIP 1.0
    KMIP_BATCH_CONTINUE = 0x01,
    KMIP_BATCH_STOP = 0x02,
    KMIP_BATCH_UNDO = 0x03
  };

  enum class block_cipher_mode : std::uint32_t {
    // KMIP 1.0
    KMIP_BLOCK_CBC = 0x01,
    KMIP_BLOCK_ECB = 0x02,
    KMIP_BLOCK_PCBC = 0x03,
    KMIP_BLOCK_CFB = 0x04,
    KMIP_BLOCK_OFB = 0x05,
    KMIP_BLOCK_CTR = 0x06,
    KMIP_BLOCK_CMAC = 0x07,
    KMIP_BLOCK_CCM = 0x08,
    KMIP_BLOCK_GCM = 0x09,
    KMIP_BLOCK_CBC_MAC = 0x0A,
    KMIP_BLOCK_XTS = 0x0B,
    KMIP_BLOCK_AES_KEY_WRAP_PADDING = 0x0C,
    KMIP_BLOCK_NIST_KEY_WRAP = 0x0D,
    KMIP_BLOCK_X9102_AESKW = 0x0E,
    KMIP_BLOCK_X9102_TDKW = 0x0F,
    KMIP_BLOCK_X9102_AKW1 = 0x10,
    KMIP_BLOCK_X9102_AKW2 = 0x11,
    // KMIP 1.4
    KMIP_BLOCK_AEAD = 0x12
  };

  enum class credential_type : std::uint32_t {
    // KMIP 1.0
    KMIP_CRED_USERNAME_AND_PASSWORD = 0x01,
    // KMIP 1.1
    KMIP_CRED_DEVICE = 0x02,
    // KMIP 1.2
    KMIP_CRED_ATTESTATION = 0x03,
    // KMIP 2.0
    KMIP_CRED_ONE_TIME_PASSWORD = 0x04,
    KMIP_CRED_HASHED_PASSWORD = 0x05,
    KMIP_CRED_TICKET = 0x06
  };

  enum class cryptographic_algorithm : std::uint32_t {
    KMIP_CRYPTOALG_UNSET = 0x00,
    // KMIP 1.0
    KMIP_CRYPTOALG_DES = 0x01,
    KMIP_CRYPTOALG_TRIPLE_DES = 0x02,
    KMIP_CRYPTOALG_AES = 0x03,
    KMIP_CRYPTOALG_RSA = 0x04,
    KMIP_CRYPTOALG_DSA = 0x05,
    KMIP_CRYPTOALG_ECDSA = 0x06,
    KMIP_CRYPTOALG_HMAC_SHA1 = 0x07,
    KMIP_CRYPTOALG_HMAC_SHA224 = 0x08,
    KMIP_CRYPTOALG_HMAC_SHA256 = 0x09,
    KMIP_CRYPTOALG_HMAC_SHA384 = 0x0A,
    KMIP_CRYPTOALG_HMAC_SHA512 = 0x0B,
    KMIP_CRYPTOALG_HMAC_MD5 = 0x0C,
    KMIP_CRYPTOALG_DH = 0x0D,
    KMIP_CRYPTOALG_ECDH = 0x0E,
    KMIP_CRYPTOALG_ECMQV = 0x0F,
    KMIP_CRYPTOALG_BLOWFISH = 0x10,
    KMIP_CRYPTOALG_CAMELLIA = 0x11,
    KMIP_CRYPTOALG_CAST5 = 0x12,
    KMIP_CRYPTOALG_IDEA = 0x13,
    KMIP_CRYPTOALG_MARS = 0x14,
    KMIP_CRYPTOALG_RC2 = 0x15,
    KMIP_CRYPTOALG_RC4 = 0x16,
    KMIP_CRYPTOALG_RC5 = 0x17,
    KMIP_CRYPTOALG_SKIPJACK = 0x18,
    KMIP_CRYPTOALG_TWOFISH = 0x19,
    // KMIP 1.2
    KMIP_CRYPTOALG_EC = 0x1A,
    // KMIP 1.3
    KMIP_CRYPTOALG_ONE_TIME_PAD = 0x1B,
    // KMIP 1.4
    KMIP_CRYPTOALG_CHACHA20 = 0x1C,
    KMIP_CRYPTOALG_POLY1305 = 0x1D,
    KMIP_CRYPTOALG_CHACHA20_POLY1305 = 0x1E,
    KMIP_CRYPTOALG_SHA3_224 = 0x1F,
    KMIP_CRYPTOALG_SHA3_256 = 0x20,
    KMIP_CRYPTOALG_SHA3_384 = 0x21,
    KMIP_CRYPTOALG_SHA3_512 = 0x22,
    KMIP_CRYPTOALG_HMAC_SHA3_224 = 0x23,
    KMIP_CRYPTOALG_HMAC_SHA3_256 = 0x24,
    KMIP_CRYPTOALG_HMAC_SHA3_384 = 0x25,
    KMIP_CRYPTOALG_HMAC_SHA3_512 = 0x26,
    KMIP_CRYPTOALG_SHAKE_128 = 0x27,
    KMIP_CRYPTOALG_SHAKE_256 = 0x28,
    // KMIP 2.0
    KMIP_CRYPTOALG_ARIA = 0x29,
    KMIP_CRYPTOALG_SEED = 0x2A,
    KMIP_CRYPTOALG_SM2 = 0x2B,
    KMIP_CRYPTOALG_SM3 = 0x2C,
    KMIP_CRYPTOALG_SM4 = 0x2D,
    KMIP_CRYPTOALG_GOST_R_34_10_2012 = 0x2E,
    KMIP_CRYPTOALG_GOST_R_34_11_2012 = 0x2F,
    KMIP_CRYPTOALG_GOST_R_34_13_2015 = 0x30,
    KMIP_CRYPTOALG_GOST_28147_89 = 0x31,
    KMIP_CRYPTOALG_XMSS = 0x32,
    KMIP_CRYPTOALG_SPHINCS_256 = 0x33,
    KMIP_CRYPTOALG_MCELIECE = 0x34,
    KMIP_CRYPTOALG_MCELIECE_6960119 = 0x35,
    KMIP_CRYPTOALG_MCELIECE_8192128 = 0x36,
    KMIP_CRYPTOALG_ED25519 = 0x37,
    KMIP_CRYPTOALG_ED448 = 0x38
  };

  enum class cryptographic_usage_mask : std::uint32_t {
    KMIP_CRYPTOMASK_UNSET = 0x00000000,
    // KMIP 1.0
    KMIP_CRYPTOMASK_SIGN = 0x00000001,
    KMIP_CRYPTOMASK_VERIFY = 0x00000002,
    KMIP_CRYPTOMASK_ENCRYPT = 0x00000004,
    KMIP_CRYPTOMASK_DECRYPT = 0x00000008,
    KMIP_CRYPTOMASK_WRAP_KEY = 0x00000010,
    KMIP_CRYPTOMASK_UNWRAP_KEY = 0x00000020,
    KMIP_CRYPTOMASK_EXPORT = 0x00000040,
    KMIP_CRYPTOMASK_MAC_GENERATE = 0x00000080,
    KMIP_CRYPTOMASK_MAC_VERIFY = 0x00000100,
    KMIP_CRYPTOMASK_DERIVE_KEY = 0x00000200,
    KMIP_CRYPTOMASK_CONTENT_COMMITMENT = 0x00000400,
    KMIP_CRYPTOMASK_KEY_AGREEMENT = 0x00000800,
    KMIP_CRYPTOMASK_CERTIFICATE_SIGN = 0x00001000,
    KMIP_CRYPTOMASK_CRL_SIGN = 0x00002000,
    KMIP_CRYPTOMASK_GENERATE_CRYPTOGRAM = 0x00004000,
    KMIP_CRYPTOMASK_VALIDATE_CRYPTOGRAM = 0x00008000,
    KMIP_CRYPTOMASK_TRANSLATE_ENCRYPT = 0x00010000,
    KMIP_CRYPTOMASK_TRANSLATE_DECRYPT = 0x00020000,
    KMIP_CRYPTOMASK_TRANSLATE_WRAP = 0x00040000,
    KMIP_CRYPTOMASK_TRANSLATE_UNWRAP = 0x00080000,
    // KMIP 2.0
    KMIP_CRYPTOMASK_AUTHENTICATE = 0x00100000,
    KMIP_CRYPTOMASK_UNRESTRICTED = 0x00200000,
    KMIP_CRYPTOMASK_FPE_ENCRYPT = 0x00400000,
    KMIP_CRYPTOMASK_FPE_DECRYPT = 0x00800000
  };

  enum class digital_signature_algorithm : std::uint32_t {
    // KMIP 1.1
    KMIP_DIGITAL_MD2_WITH_RSA = 0x01,
    KMIP_DIGITAL_MD5_WITH_RSA = 0x02,
    KMIP_DIGITAL_SHA1_WITH_RSA = 0x03,
    KMIP_DIGITAL_SHA224_WITH_RSA = 0x04,
    KMIP_DIGITAL_SHA256_WITH_RSA = 0x05,
    KMIP_DIGITAL_SHA384_WITH_RSA = 0x06,
    KMIP_DIGITAL_SHA512_WITH_RSA = 0x07,
    KMIP_DIGITAL_RSASSA_PSS = 0x08,
    KMIP_DIGITAL_DSA_WITH_SHA1 = 0x09,
    KMIP_DIGITAL_DSA_WITH_SHA224 = 0x0A,
    KMIP_DIGITAL_DSA_WITH_SHA256 = 0x0B,
    KMIP_DIGITAL_ECDSA_WITH_SHA1 = 0x0C,
    KMIP_DIGITAL_ECDSA_WITH_SHA224 = 0x0D,
    KMIP_DIGITAL_ECDSA_WITH_SHA256 = 0x0E,
    KMIP_DIGITAL_ECDSA_WITH_SHA384 = 0x0F,
    KMIP_DIGITAL_ECDSA_WITH_SHA512 = 0x10,
    // KMIP 1.4
    KMIP_DIGITAL_SHA3_256_WITH_RSA = 0x11,
    KMIP_DIGITAL_SHA3_384_WITH_RSA = 0x12,
    KMIP_DIGITAL_SHA3_512_WITH_RSA = 0x13
  };

  enum class encoding_option : std::uint32_t {
    // KMIP 1.1
    KMIP_ENCODE_NO_ENCODING = 0x01,
    KMIP_ENCODE_TTLV_ENCODING = 0x02
  };

  enum class hashing_algorithm : std::uint32_t {
    // KMIP 1.0
    KMIP_HASH_MD2 = 0x01,
    KMIP_HASH_MD4 = 0x02,
    KMIP_HASH_MD5 = 0x03,
    KMIP_HASH_SHA1 = 0x04,
    KMIP_HASH_SHA224 = 0x05,
    KMIP_HASH_SHA256 = 0x06,
    KMIP_HASH_SHA384 = 0x07,
    KMIP_HASH_SHA512 = 0x08,
    KMIP_HASH_RIPEMD160 = 0x09,
    KMIP_HASH_TIGER = 0x0A,
    KMIP_HASH_WHIRLPOOL = 0x0B,
    // KMIP 1.2
    KMIP_HASH_SHA512_224 = 0x0C,
    KMIP_HASH_SHA512_256 = 0x0D,
    // KMIP 1.4
    KMIP_HASH_SHA3_224 = 0x0E,
    KMIP_HASH_SHA3_256 = 0x0F,
    KMIP_HASH_SHA3_384 = 0x10,
    KMIP_HASH_SHA3_512 = 0x11
  };

  enum class key_compression_type : std::uint32_t {
    // KMIP 1.0
    KMIP_KEYCOMP_EC_PUB_UNCOMPRESSED = 0x01,
    KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_PRIME = 0x02,
    KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_CHAR2 = 0x03,
    KMIP_KEYCOMP_EC_PUB_X962_HYBRID = 0x04
  };

  enum class key_format_type : std::uint32_t {
    // KMIP 1.0
    KMIP_KEYFORMAT_RAW = 0x01,
    KMIP_KEYFORMAT_OPAQUE = 0x02,
    KMIP_KEYFORMAT_PKCS1 = 0x03,
    KMIP_KEYFORMAT_PKCS8 = 0x04,
    KMIP_KEYFORMAT_X509 = 0x05,
    KMIP_KEYFORMAT_EC_PRIVATE_KEY = 0x06,
    KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY = 0x07,
    KMIP_KEYFORMAT_TRANS_DSA_PRIVATE_KEY = 0x08,
    KMIP_KEYFORMAT_TRANS_DSA_PUBLIC_KEY = 0x09,
    KMIP_KEYFORMAT_TRANS_RSA_PRIVATE_KEY = 0x0A,
    KMIP_KEYFORMAT_TRANS_RSA_PUBLIC_KEY = 0x0B,
    KMIP_KEYFORMAT_TRANS_DH_PRIVATE_KEY = 0x0C,
    KMIP_KEYFORMAT_TRANS_DH_PUBLIC_KEY = 0x0D,
    KMIP_KEYFORMAT_TRANS_ECDSA_PRIVATE_KEY = 0x0E,  // Deprecated as of KMIP 1.3
    KMIP_KEYFORMAT_TRANS_ECDSA_PUBLIC_KEY = 0x0F,   // Deprecated as of KMIP 1.3
    KMIP_KEYFORMAT_TRANS_ECDH_PRIVATE_KEY = 0x10,   // Deprecated as of KMIP 1.3
    KMIP_KEYFORMAT_TRANS_ECDH_PUBLIC_KEY = 0x11,    // Deprecated as of KMIP 1.3
    KMIP_KEYFORMAT_TRANS_ECMQV_PRIVATE_KEY = 0x12,  // Deprecated as of KMIP 1.3
    KMIP_KEYFORMAT_TRANS_ECMQV_PUBLIC_KEY = 0x13,   // Deprecated as of KMIP 1.3
    // KMIP 1.3
    KMIP_KEYFORMAT_TRANS_EC_PRIVATE_KEY = 0x14,
    KMIP_KEYFORMAT_TRANS_EC_PUBLIC_KEY = 0x15,
    // KMIP 1.4
    KMIP_KEYFORMAT_PKCS12 = 0x16,
    // KMIP 2.0
    KMIP_KEYFORMAT_PKCS10 = 0x17
  };

  enum class key_role_type : std::uint32_t {
    // KMIP 1.0
    KMIP_ROLE_BDK = 0x01,
    KMIP_ROLE_CVK = 0x02,
    KMIP_ROLE_DEK = 0x03,
    KMIP_ROLE_MKAC = 0x04,
    KMIP_ROLE_MKSMC = 0x05,
    KMIP_ROLE_MKSMI = 0x06,
    KMIP_ROLE_MKDAC = 0x07,
    KMIP_ROLE_MKDN = 0x08,
    KMIP_ROLE_MKCP = 0x09,
    KMIP_ROLE_MKOTH = 0x0A,
    KMIP_ROLE_KEK = 0x0B,
    KMIP_ROLE_MAC16609 = 0x0C,
    KMIP_ROLE_MAC97971 = 0x0D,
    KMIP_ROLE_MAC97972 = 0x0E,
    KMIP_ROLE_MAC97973 = 0x0F,
    KMIP_ROLE_MAC97974 = 0x10,
    KMIP_ROLE_MAC97975 = 0x11,
    KMIP_ROLE_ZPK = 0x12,
    KMIP_ROLE_PVKIBM = 0x13,
    KMIP_ROLE_PVKPVV = 0x14,
    KMIP_ROLE_PVKOTH = 0x15,
    // KMIP 1.4
    KMIP_ROLE_DUKPT = 0x16,
    KMIP_ROLE_IV = 0x17,
    KMIP_ROLE_TRKBK = 0x18
  };

  enum class key_wrap_type : std::uint32_t {
    // KMIP 1.4
    KMIP_WRAPTYPE_NOT_WRAPPED = 0x01,
    KMIP_WRAPTYPE_AS_REGISTERED = 0x02
  };

  enum class mask_generator : std::uint32_t {
    // KMIP 1.4
    KMIP_MASKGEN_MGF1 = 0x01
  };

  enum class name_type : std::uint32_t {
    // KMIP 1.0
    KMIP_NAME_UNINTERPRETED_TEXT_STRING = 0x01,
    KMIP_NAME_URI = 0x02
  };

  enum class object_type : std::uint32_t {
    // KMIP 1.0
    KMIP_OBJTYPE_CERTIFICATE = 0x01,
    KMIP_OBJTYPE_SYMMETRIC_KEY = 0x02,
    KMIP_OBJTYPE_PUBLIC_KEY = 0x03,
    KMIP_OBJTYPE_PRIVATE_KEY = 0x04,
    KMIP_OBJTYPE_SPLIT_KEY = 0x05,
    KMIP_OBJTYPE_TEMPLATE = 0x06,  // Deprecated as of KMIP 1.3
    KMIP_OBJTYPE_SECRET_DATA = 0x07,
    KMIP_OBJTYPE_OPAQUE_OBJECT = 0x08,
    // KMIP 1.2
    KMIP_OBJTYPE_PGP_KEY = 0x09,
    // KMIP 2.0
    KMIP_OBJTYPE_CERTIFICATE_REQUEST = 0x0A
  };

  enum class operation : std::uint32_t {
    // KMIP 1.0
    KMIP_OP_CREATE = 0x01,
    KMIP_OP_CREATE_KEY_PAIR = 0x02,
    KMIP_OP_REGISTER = 0x03,
    KMIP_OP_REKEY = 0x04,
    KMIP_OP_DERIVE_KEY = 0x05,
    KMIP_OP_CERTIFY = 0x06,
    KMIP_OP_RECERTIFY = 0x07,
    KMIP_OP_LOCATE = 0x08,
    KMIP_OP_CHECK = 0x09,
    KMIP_OP_GET = 0x0A,
    KMIP_OP_GET_ATTRIBUTES = 0x0B,
    KMIP_OP_GET_ATTRIBUTE_LIST = 0x0C,
    KMIP_OP_ADD_ATTRIBUTE = 0x0D,
    KMIP_OP_MODIFY_ATTRIBUTE = 0x0E,
    KMIP_OP_DELETE_ATTRIBUTE = 0x0F,
    KMIP_OP_OBTAIN_LEASE = 0x10,
    KMIP_OP_GET_USAGE_ALLOCATION = 0x11,
    KMIP_OP_ACTIVATE = 0x12,
    KMIP_OP_REVOKE = 0x13,
    KMIP_OP_DESTROY = 0x14,
    KMIP_OP_ARCHIVE = 0x15,
    KMIP_OP_RECOVER = 0x16,
    KMIP_OP_VALIDATE = 0x17,
    KMIP_OP_QUERY = 0x18,
    KMIP_OP_CANCEL = 0x19,
    KMIP_OP_POLL = 0x1A,
    KMIP_OP_NOTIFY = 0x1B,
    KMIP_OP_PUT = 0x1C,
    // KMIP 1.1
    KMIP_OP_REKEY_KEY_PAIR = 0x1D,
    KMIP_OP_DISCOVER_VERSIONS = 0x1E,
    // KMIP 1.2
    KMIP_OP_ENCRYPT = 0x1F,
    KMIP_OP_DECRYPT = 0x20,
    KMIP_OP_SIGN = 0x21,
    KMIP_OP_SIGNATURE_VERIFY = 0x22,
    KMIP_OP_MAC = 0x23,
    KMIP_OP_MAC_VERIFY = 0x24,
    KMIP_OP_RNG_RETRIEVE = 0x25,
    KMIP_OP_RNG_SEED = 0x26,
    KMIP_OP_HASH = 0x27,
    KMIP_OP_CREATE_SPLIT_KEY = 0x28,
    KMIP_OP_JOIN_SPLIT_KEY = 0x29,
    // KMIP 1.4
    KMIP_OP_IMPORT = 0x2A,
    KMIP_OP_EXPORT = 0x2B,
    // KMIP 2.0
    KMIP_OP_LOG = 0x2C,
    KMIP_OP_LOGIN = 0x2D,
    KMIP_OP_LOGOUT = 0x2E,
    KMIP_OP_DELEGATED_LOGIN = 0x2F,
    KMIP_OP_ADJUST_ATTRIBUTE = 0x30,
    KMIP_OP_SET_ATTRIBUTE = 0x31,
    KMIP_OP_SET_ENDPOINT_ROLE = 0x32,
    KMIP_OP_PKCS_11 = 0x33,
    KMIP_OP_INTEROP = 0x34,
    KMIP_OP_REPROVISION = 0x35
  };

  enum class padding_method : std::uint32_t {
    // KMIP 1.0
    KMIP_PAD_NONE = 0x01,
    KMIP_PAD_OAEP = 0x02,
    KMIP_PAD_PKCS5 = 0x03,
    KMIP_PAD_SSL3 = 0x04,
    KMIP_PAD_ZEROS = 0x05,
    KMIP_PAD_ANSI_X923 = 0x06,
    KMIP_PAD_ISO_10126 = 0x07,
    KMIP_PAD_PKCS1v15 = 0x08,
    KMIP_PAD_X931 = 0x09,
    KMIP_PAD_PSS = 0x0A
  };

  enum class protection_storage_mask : std::uint32_t {
    // KMIP 2.0
    KMIP_PROTECT_SOFTWARE = 0x00000001,
    KMIP_PROTECT_HARDWARE = 0x00000002,
    KMIP_PROTECT_ON_PROCESSOR = 0x00000004,
    KMIP_PROTECT_ON_SYSTEM = 0x00000008,
    KMIP_PROTECT_OFF_SYSTEM = 0x00000010,
    KMIP_PROTECT_HYPERVISOR = 0x00000020,
    KMIP_PROTECT_OPERATING_SYSTEM = 0x00000040,
    KMIP_PROTECT_CONTAINER = 0x00000080,
    KMIP_PROTECT_ON_PREMISES = 0x00000100,
    KMIP_PROTECT_OFF_PREMISES = 0x00000200,
    KMIP_PROTECT_SELF_MANAGED = 0x00000400,
    KMIP_PROTECT_OUTSOURCED = 0x00000800,
    KMIP_PROTECT_VALIDATED = 0x00001000,
    KMIP_PROTECT_SAME_JURISDICTION = 0x00002000
  };

  enum class query_function : std::uint32_t {
    // KMIP 1.0
    KMIP_QUERY_OPERATIONS = 0x0001,
    KMIP_QUERY_OBJECTS = 0x0002,
    KMIP_QUERY_SERVER_INFORMATION = 0x0003,
    KMIP_QUERY_APPLICATION_NAMESPACES = 0x0004,
    // KMIP 1.1
    KMIP_QUERY_EXTENSION_LIST = 0x0005,
    KMIP_QUERY_EXTENSION_MAP = 0x0006,
    // KMIP 1.2
    KMIP_QUERY_ATTESTATION_TYPES = 0x0007,
    // KMIP 1.3
    KMIP_QUERY_RNGS = 0x0008,
    KMIP_QUERY_VALIDATIONS = 0x0009,
    KMIP_QUERY_PROFILES = 0x000A,
    KMIP_QUERY_CAPABILITIES = 0x000B,
    KMIP_QUERY_CLIENT_REGISTRATION_METHODS = 0x000C,
    // KMIP 2.0
    KMIP_QUERY_DEFAULTS_INFORMATION = 0x000D,
    KMIP_QUERY_STORAGE_PROTECTION_MASKS = 0x000E
  };

  enum class result_reason : std::uint32_t {
    // KMIP 1.0
    KMIP_REASON_GENERAL_FAILURE = 0x0100,
    KMIP_REASON_ITEM_NOT_FOUND = 0x0001,
    KMIP_REASON_RESPONSE_TOO_LARGE = 0x0002,
    KMIP_REASON_AUTHENTICATION_NOT_SUCCESSFUL = 0x0003,
    KMIP_REASON_INVALID_MESSAGE = 0x0004,
    KMIP_REASON_OPERATION_NOT_SUPPORTED = 0x0005,
    KMIP_REASON_MISSING_DATA = 0x0006,
    KMIP_REASON_INVALID_FIELD = 0x0007,
    KMIP_REASON_FEATURE_NOT_SUPPORTED = 0x0008,
    KMIP_REASON_OPERATION_CANCELED_BY_REQUESTER = 0x0009,
    KMIP_REASON_CRYPTOGRAPHIC_FAILURE = 0x000A,
    KMIP_REASON_ILLEGAL_OPERATION = 0x000B,
    KMIP_REASON_PERMISSION_DENIED = 0x000C,
    KMIP_REASON_OBJECT_ARCHIVED = 0x000D,
    KMIP_REASON_INDEX_OUT_OF_BOUNDS = 0x000E,
    KMIP_REASON_APPLICATION_NAMESPACE_NOT_SUPPORTED = 0x000F,
    KMIP_REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED = 0x0010,
    KMIP_REASON_KEY_COMPRESSION_TYPE_NOT_SUPPORTED = 0x0011,
    // KMIP 1.1
    KMIP_REASON_ENCODING_OPTION_FAILURE = 0x0012,
    // KMIP 1.2
    KMIP_REASON_KEY_VALUE_NOT_PRESENT = 0x0013,
    KMIP_REASON_ATTESTATION_REQUIRED = 0x0014,
    KMIP_REASON_ATTESTATION_FAILED = 0x0015,
    // KMIP 1.4
    KMIP_REASON_SENSITIVE = 0x0016,
    KMIP_REASON_NOT_EXTRACTABLE = 0x0017,
    KMIP_REASON_OBJECT_ALREADY_EXISTS = 0x0018,
    // KMIP 2.0
    KMIP_REASON_INVALID_TICKET = 0x0019,
    KMIP_REASON_USAGE_LIMIT_EXCEEDED = 0x001A,
    KMIP_REASON_NUMERIC_RANGE = 0x001B,
    KMIP_REASON_INVALID_DATA_TYPE = 0x001C,
    KMIP_REASON_READ_ONLY_ATTRIBUTE = 0x001D,
    KMIP_REASON_MULTI_VALUED_ATTRIBUTE = 0x001E,
    KMIP_REASON_UNSUPPORTED_ATTRIBUTE = 0x001F,
    KMIP_REASON_ATTRIBUTE_INSTANCE_NOT_FOUND = 0x0020,
    KMIP_REASON_ATTRIBUTE_NOT_FOUND = 0x0021,
    KMIP_REASON_ATTRIBUTE_READ_ONLY = 0x0022,
    KMIP_REASON_ATTRIBUTE_SINGLE_VALUED = 0x0023,
    KMIP_REASON_BAD_CRYPTOGRAPHIC_PARAMETERS = 0x0024,
    KMIP_REASON_BAD_PASSWORD = 0x0025,
    KMIP_REASON_CODEC_ERROR = 0x0026,
    KMIP_REASON_ILLEGAL_OBJECT_TYPE = 0x0028,
    KMIP_REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK = 0x0029,
    KMIP_REASON_INTERNAL_SERVER_ERROR = 0x002A,
    KMIP_REASON_INVALID_ASYNCHRONOUS_CORRELATION_VALUE = 0x002B,
    KMIP_REASON_INVALID_ATTRIBUTE = 0x002C,
    KMIP_REASON_INVALID_ATTRIBUTE_VALUE = 0x002D,
    KMIP_REASON_INVALID_CORRELATION_VALUE = 0x002E,
    KMIP_REASON_INVALID_CSR = 0x002F,
    KMIP_REASON_INVALID_OBJECT_TYPE = 0x0030,
    KMIP_REASON_KEY_WRAP_TYPE_NOT_SUPPORTED = 0x0032,
    KMIP_REASON_MISSING_INITIALIZATION_VECTOR = 0x0034,
    KMIP_REASON_NON_UNIQUE_NAME_ATTRIBUTE = 0x0035,
    KMIP_REASON_OBJECT_DESTROYED = 0x0036,
    KMIP_REASON_OBJECT_NOT_FOUND = 0x0037,
    KMIP_REASON_NOT_AUTHORISED = 0x0039,
    KMIP_REASON_SERVER_LIMIT_EXCEEDED = 0x003A,
    KMIP_REASON_UNKNOWN_ENUMERATION = 0x003B,
    KMIP_REASON_UNKNOWN_MESSAGE_EXTENSION = 0x003C,
    KMIP_REASON_UNKNOWN_TAG = 0x003D,
    KMIP_REASON_UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS = 0x003E,
    KMIP_REASON_UNSUPPORTED_PROTOCOL_VERSION = 0x003F,
    KMIP_REASON_WRAPPING_OBJECT_ARCHIVED = 0x0040,
    KMIP_REASON_WRAPPING_OBJECT_DESTROYED = 0x0041,
    KMIP_REASON_WRAPPING_OBJECT_NOT_FOUND = 0x0042,
    KMIP_REASON_WRONG_KEY_LIFECYCLE_STATE = 0x0043,
    KMIP_REASON_PROTECTION_STORAGE_UNAVAILABLE = 0x0044,
    KMIP_REASON_PKCS11_CODEC_ERROR = 0x0045,
    KMIP_REASON_PKCS11_INVALID_FUNCTION = 0x0046,
    KMIP_REASON_PKCS11_INVALID_INTERFACE = 0x0047,
    KMIP_REASON_PRIVATE_PROTECTION_STORAGE_UNAVAILABLE = 0x0048,
    KMIP_REASON_PUBLIC_PROTECTION_STORAGE_UNAVAILABLE = 0x0049
  };

  enum class result_status : std::uint32_t {
    // KMIP 1.0
    KMIP_STATUS_SUCCESS = 0x00,
    KMIP_STATUS_OPERATION_FAILED = 0x01,
    KMIP_STATUS_OPERATION_PENDING = 0x02,
    KMIP_STATUS_OPERATION_UNDONE = 0x03
  };

  enum class state : std::uint32_t {
    // KMIP 1.0
    KMIP_STATE_PRE_ACTIVE = 0x01,
    KMIP_STATE_ACTIVE = 0x02,
    KMIP_STATE_DEACTIVATED = 0x03,
    KMIP_STATE_COMPROMISED = 0x04,
    KMIP_STATE_DESTROYED = 0x05,
    KMIP_STATE_DESTROYED_COMPROMISED = 0x06
  };

  /** Convert a KMIP state enum value to a human-readable string. */
  inline const char *state_to_string(state value) {
    switch (value) {
      case state::KMIP_STATE_PRE_ACTIVE:
        return "KMIP_STATE_PRE_ACTIVE";
      case state::KMIP_STATE_ACTIVE:
        return "KMIP_STATE_ACTIVE";
      case state::KMIP_STATE_DEACTIVATED:
        return "KMIP_STATE_DEACTIVATED";
      case state::KMIP_STATE_COMPROMISED:
        return "KMIP_STATE_COMPROMISED";
      case state::KMIP_STATE_DESTROYED:
        return "KMIP_STATE_DESTROYED";
      case state::KMIP_STATE_DESTROYED_COMPROMISED:
        return "KMIP_STATE_DESTROYED_COMPROMISED";
      default:
        return "UNKNOWN_KMIP_STATE";
    }
  }

  /** Stream formatter for KMIP lifecycle state values. */
  inline std::ostream &operator<<(std::ostream &out, const state value) {
    return out << state_to_string(value);
  }

  /** Convert a KMIP operation code to a human-readable string. */
  inline const char *operation_to_string(int32_t value) {
    switch (static_cast<operation>(value)) {
      case operation::KMIP_OP_CREATE:
        return "Create";
      case operation::KMIP_OP_CREATE_KEY_PAIR:
        return "Create Key Pair";
      case operation::KMIP_OP_REGISTER:
        return "Register";
      case operation::KMIP_OP_REKEY:
        return "Rekey";
      case operation::KMIP_OP_DERIVE_KEY:
        return "Derive Key";
      case operation::KMIP_OP_CERTIFY:
        return "Certify";
      case operation::KMIP_OP_RECERTIFY:
        return "Recertify";
      case operation::KMIP_OP_LOCATE:
        return "Locate";
      case operation::KMIP_OP_CHECK:
        return "Check";
      case operation::KMIP_OP_GET:
        return "Get";
      case operation::KMIP_OP_GET_ATTRIBUTES:
        return "Get Attributes";
      case operation::KMIP_OP_GET_ATTRIBUTE_LIST:
        return "Get Attribute List";
      case operation::KMIP_OP_ADD_ATTRIBUTE:
        return "Add Attribute";
      case operation::KMIP_OP_MODIFY_ATTRIBUTE:
        return "Modify Attribute";
      case operation::KMIP_OP_DELETE_ATTRIBUTE:
        return "Delete Attribute";
      case operation::KMIP_OP_OBTAIN_LEASE:
        return "Obtain Lease";
      case operation::KMIP_OP_GET_USAGE_ALLOCATION:
        return "Get Usage Allocation";
      case operation::KMIP_OP_ACTIVATE:
        return "Activate";
      case operation::KMIP_OP_REVOKE:
        return "Revoke";
      case operation::KMIP_OP_DESTROY:
        return "Destroy";
      case operation::KMIP_OP_ARCHIVE:
        return "Archive";
      case operation::KMIP_OP_RECOVER:
        return "Recover";
      case operation::KMIP_OP_VALIDATE:
        return "Validate";
      case operation::KMIP_OP_QUERY:
        return "Query";
      case operation::KMIP_OP_CANCEL:
        return "Cancel";
      case operation::KMIP_OP_POLL:
        return "Poll";
      case operation::KMIP_OP_NOTIFY:
        return "Notify";
      case operation::KMIP_OP_PUT:
        return "Put";
      case operation::KMIP_OP_REKEY_KEY_PAIR:
        return "Rekey Key Pair";
      case operation::KMIP_OP_DISCOVER_VERSIONS:
        return "Discover Versions";
      case operation::KMIP_OP_ENCRYPT:
        return "Encrypt";
      case operation::KMIP_OP_DECRYPT:
        return "Decrypt";
      case operation::KMIP_OP_SIGN:
        return "Sign";
      case operation::KMIP_OP_SIGNATURE_VERIFY:
        return "Signature Verify";
      case operation::KMIP_OP_MAC:
        return "MAC";
      case operation::KMIP_OP_MAC_VERIFY:
        return "MAC Verify";
      case operation::KMIP_OP_RNG_RETRIEVE:
        return "RNG Retrieve";
      case operation::KMIP_OP_RNG_SEED:
        return "RNG Seed";
      case operation::KMIP_OP_HASH:
        return "Hash";
      case operation::KMIP_OP_CREATE_SPLIT_KEY:
        return "Create Split Key";
      case operation::KMIP_OP_JOIN_SPLIT_KEY:
        return "Join Split Key";
      case operation::KMIP_OP_IMPORT:
        return "Import";
      case operation::KMIP_OP_EXPORT:
        return "Export";
      case operation::KMIP_OP_LOG:
        return "Log";
      case operation::KMIP_OP_LOGIN:
        return "Login";
      case operation::KMIP_OP_LOGOUT:
        return "Logout";
      case operation::KMIP_OP_DELEGATED_LOGIN:
        return "Delegated Login";
      case operation::KMIP_OP_ADJUST_ATTRIBUTE:
        return "Adjust Attribute";
      case operation::KMIP_OP_SET_ATTRIBUTE:
        return "Set Attribute";
      case operation::KMIP_OP_SET_ENDPOINT_ROLE:
        return "Set Endpoint Role";
      case operation::KMIP_OP_PKCS_11:
        return "PKCS#11";
      case operation::KMIP_OP_INTEROP:
        return "Interop";
      case operation::KMIP_OP_REPROVISION:
        return "Reprovision";
      default:
        return "Unknown Operation";
    }
  }

  /** Convert a KMIP object type code to a human-readable string. */
  inline const char *object_type_to_string(int32_t value) {
    switch (static_cast<object_type>(value)) {
      case object_type::KMIP_OBJTYPE_CERTIFICATE:
        return "Certificate";
      case object_type::KMIP_OBJTYPE_SYMMETRIC_KEY:
        return "Symmetric Key";
      case object_type::KMIP_OBJTYPE_PUBLIC_KEY:
        return "Public Key";
      case object_type::KMIP_OBJTYPE_PRIVATE_KEY:
        return "Private Key";
      case object_type::KMIP_OBJTYPE_SPLIT_KEY:
        return "Split Key";
      case object_type::KMIP_OBJTYPE_TEMPLATE:
        return "Template";
      case object_type::KMIP_OBJTYPE_SECRET_DATA:
        return "Secret Data";
      case object_type::KMIP_OBJTYPE_OPAQUE_OBJECT:
        return "Opaque Object";
      case object_type::KMIP_OBJTYPE_PGP_KEY:
        return "PGP Key";
      case object_type::KMIP_OBJTYPE_CERTIFICATE_REQUEST:
        return "Certificate Request";
      default:
        return "Unknown Object Type";
    }
  }

  enum class tag : std::uint32_t {
    KMIP_TAG_TAG = 0x000000,
    KMIP_TAG_TYPE = 0x000001,
    KMIP_TAG_DEFAULT = 0x420000,
    // KMIP 1.0
    KMIP_TAG_ACTIVATION_DATE = 0x420001,
    KMIP_TAG_APPLICATION_DATA = 0x420002,
    KMIP_TAG_APPLICATION_NAMESPACE = 0x420003,
    KMIP_TAG_APPLICATION_SPECIFIC_INFORMATION = 0x420004,
    KMIP_TAG_ATTRIBUTE_REFERENCE = 0x420005,
    KMIP_TAG_ASYNCHRONOUS_CORRELATION_VALUE = 0x420006,
    KMIP_TAG_ASYNCHRONOUS_INDICATOR = 0x420007,
    KMIP_TAG_ATTRIBUTE = 0x420008,
    KMIP_TAG_ATTRIBUTE_INDEX = 0x420009,
    KMIP_TAG_ATTRIBUTE_NAME = 0x42000A,
    KMIP_TAG_ATTRIBUTE_VALUE = 0x42000B,
    KMIP_TAG_AUTHENTICATION = 0x42000C,
    KMIP_TAG_BATCH_COUNT = 0x42000D,
    KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION = 0x42000E,
    KMIP_TAG_BATCH_ITEM = 0x42000F,
    KMIP_TAG_BATCH_ORDER_OPTION = 0x420010,
    KMIP_TAG_BLOCK_CIPHER_MODE = 0x420011,
    KMIP_TAG_COMPROMISE_OCCURRANCE_DATE = 0x420021,
    KMIP_TAG_CREDENTIAL = 0x420023,
    KMIP_TAG_CREDENTIAL_TYPE = 0x420024,
    KMIP_TAG_CREDENTIAL_VALUE = 0x420025,
    KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM = 0x420028,
    KMIP_TAG_CRYPTOGRAPHIC_LENGTH = 0x42002A,
    KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS = 0x42002B,
    KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK = 0x42002C,
    KMIP_TAG_DEACTIVATION_DATE = 0x42002F,
    KMIP_TAG_ENCRYPTION_KEY_INFORMATION = 0x420036,
    KMIP_TAG_HASHING_ALGORITHM = 0x420038,
    KMIP_TAG_IV_COUNTER_NONCE = 0x42003D,
    KMIP_TAG_KEY = 0x42003F,
    KMIP_TAG_KEY_BLOCK = 0x420040,
    KMIP_TAG_KEY_COMPRESSION_TYPE = 0x420041,
    KMIP_TAG_KEY_FORMAT_TYPE = 0x420042,
    KMIP_TAG_KEY_MATERIAL = 0x420043,
    KMIP_TAG_KEY_VALUE = 0x420045,
    KMIP_TAG_KEY_WRAPPING_DATA = 0x420046,
    KMIP_TAG_KEY_WRAPPING_SPECIFICATION = 0x420047,
    KMIP_TAG_MAC_SIGNATURE = 0x42004D,
    KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION = 0x42004E,
    KMIP_TAG_MAXIMUM_ITEMS = 0x42004F,
    KMIP_TAG_MAXIMUM_RESPONSE_SIZE = 0x420050,
    KMIP_TAG_NAME = 0x420053,
    KMIP_TAG_NAME_TYPE = 0x420054,
    KMIP_TAG_NAME_VALUE = 0x420055,
    KMIP_TAG_OBJECT_GROUP = 0x420056,
    KMIP_TAG_OBJECT_TYPE = 0x420057,
    KMIP_TAG_OPERATION = 0x42005C,
    KMIP_TAG_OPERATION_POLICY_NAME = 0x42005D,
    KMIP_TAG_PADDING_METHOD = 0x42005F,
    KMIP_TAG_PRIVATE_KEY = 0x420064,
    KMIP_TAG_PROCESS_START_DATE = 0x420067,
    KMIP_TAG_PROTECT_STOP_DATE = 0x420068,
    KMIP_TAG_PROTOCOL_VERSION = 0x420069,
    KMIP_TAG_PROTOCOL_VERSION_MAJOR = 0x42006A,
    KMIP_TAG_PROTOCOL_VERSION_MINOR = 0x42006B,
    KMIP_TAG_PUBLIC_KEY = 0x42006D,
    KMIP_TAG_QUERY_FUNCTION = 0x420074,
    KMIP_TAG_REQUEST_HEADER = 0x420077,
    KMIP_TAG_REQUEST_MESSAGE = 0x420078,
    KMIP_TAG_REQUEST_PAYLOAD = 0x420079,
    KMIP_TAG_RESPONSE_HEADER = 0x42007A,
    KMIP_TAG_RESPONSE_MESSAGE = 0x42007B,
    KMIP_TAG_RESPONSE_PAYLOAD = 0x42007C,
    KMIP_TAG_RESULT_MESSAGE = 0x42007D,
    KMIP_TAG_RESULT_REASON = 0x42007E,
    KMIP_TAG_RESULT_STATUS = 0x42007F,
    KMIP_TAG_REVOKATION_MESSAGE = 0x420080,
    KMIP_TAG_REVOCATION_REASON = 0x420081,
    KMIP_TAG_REVOCATION_REASON_CODE = 0x420082,
    KMIP_TAG_KEY_ROLE_TYPE = 0x420083,
    KMIP_TAG_SALT = 0x420084,
    KMIP_TAG_SECRET_DATA = 0x420085,
    KMIP_TAG_SECRET_DATA_TYPE = 0x420086,
    KMIP_TAG_SERVER_INFORMATION = 0x420088,
    KMIP_TAG_STATE = 0x42008D,
    KMIP_TAG_STORAGE_STATUS_MASK = 0x42008E,
    KMIP_TAG_SYMMETRIC_KEY = 0x42008F,
    KMIP_TAG_TEMPLATE_ATTRIBUTE = 0x420091,
    KMIP_TAG_TIME_STAMP = 0x420092,
    KMIP_TAG_UNIQUE_BATCH_ITEM_ID = 0x420093,
    KMIP_TAG_UNIQUE_IDENTIFIER = 0x420094,
    KMIP_TAG_USERNAME = 0x420099,
    KMIP_TAG_VENDOR_IDENTIFICATION = 0x42009D,
    KMIP_TAG_WRAPPING_METHOD = 0x42009E,
    KMIP_TAG_PASSWORD = 0x4200A1,
    // KMIP 1.1
    KMIP_TAG_DEVICE_IDENTIFIER = 0x4200A2,
    KMIP_TAG_ENCODING_OPTION = 0x4200A3,
    KMIP_TAG_MACHINE_IDENTIFIER = 0x4200A9,
    KMIP_TAG_MEDIA_IDENTIFIER = 0x4200AA,
    KMIP_TAG_NETWORK_IDENTIFIER = 0x4200AB,
    KMIP_TAG_OBJECT_GROUP_MEMBER = 0x4200AC,
    KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM = 0x4200AE,
    KMIP_TAG_DEVICE_SERIAL_NUMBER = 0x4200B0,
    // KMIP 1.2
    KMIP_TAG_RANDOM_IV = 0x4200C5,
    KMIP_TAG_ATTESTATION_TYPE = 0x4200C7,
    KMIP_TAG_NONCE = 0x4200C8,
    KMIP_TAG_NONCE_ID = 0x4200C9,
    KMIP_TAG_NONCE_VALUE = 0x4200CA,
    KMIP_TAG_ATTESTATION_MEASUREMENT = 0x4200CB,
    KMIP_TAG_ATTESTATION_ASSERTION = 0x4200CC,
    KMIP_TAG_IV_LENGTH = 0x4200CD,
    KMIP_TAG_TAG_LENGTH = 0x4200CE,
    KMIP_TAG_FIXED_FIELD_LENGTH = 0x4200CF,
    KMIP_TAG_COUNTER_LENGTH = 0x4200D0,
    KMIP_TAG_INITIAL_COUNTER_VALUE = 0x4200D1,
    KMIP_TAG_INVOCATION_FIELD_LENGTH = 0x4200D2,
    KMIP_TAG_ATTESTATION_CAPABLE_INDICATOR = 0x4200D3,
    KMIP_TAG_OFFSET_ITEMS = 0x4200D4,
    KMIP_TAG_LOCATED_ITEMS = 0x4200D5,
    // KMIP 1.4
    KMIP_TAG_KEY_WRAP_TYPE = 0x4200F8,
    KMIP_TAG_SALT_LENGTH = 0x420100,
    KMIP_TAG_MASK_GENERATOR = 0x420101,
    KMIP_TAG_MASK_GENERATOR_HASHING_ALGORITHM = 0x420102,
    KMIP_TAG_P_SOURCE = 0x420103,
    KMIP_TAG_TRAILER_FIELD = 0x420104,
    KMIP_TAG_CLIENT_CORRELATION_VALUE = 0x420105,
    KMIP_TAG_SERVER_CORRELATION_VALUE = 0x420106,
    // KMIP 2.0
    KMIP_TAG_ATTRIBUTES = 0x420125,
    KMIP_TAG_SERVER_NAME = 0x42012D,
    KMIP_TAG_SERVER_SERIAL_NUMBER = 0x42012E,
    KMIP_TAG_SERVER_VERSION = 0x42012F,
    KMIP_TAG_SERVER_LOAD = 0x420130,
    KMIP_TAG_PRODUCT_NAME = 0x420131,
    KMIP_TAG_BUILD_LEVEL = 0x420132,
    KMIP_TAG_BUILD_DATE = 0x420133,
    KMIP_TAG_CLUSTER_INFO = 0x420134,
    KMIP_TAG_ALTERNATE_FAILOVER_ENDPOINTS = 0x420135,
    KMIP_TAG_EPHEMERAL = 0x420154,
    KMIP_TAG_SERVER_HASHED_PASSWORD = 0x420155,
    KMIP_TAG_PROTECTION_STORAGE_MASK = 0x42015E,
    KMIP_TAG_PROTECTION_STORAGE_MASKS = 0x42015F,
    KMIP_TAG_COMMON_PROTECTION_STORAGE_MASKS = 0x420163,
    KMIP_TAG_PRIVATE_PROTECTION_STORAGE_MASKS = 0x420164,
    KMIP_TAG_PUBLIC_PROTECTION_STORAGE_MASKS = 0x420165
  };

  enum class type : std::uint32_t {
    // KMIP 1.0
    KMIP_TYPE_STRUCTURE = 0x01,
    KMIP_TYPE_INTEGER = 0x02,
    KMIP_TYPE_LONG_INTEGER = 0x03,
    KMIP_TYPE_BIG_INTEGER = 0x04,
    KMIP_TYPE_ENUMERATION = 0x05,
    KMIP_TYPE_BOOLEAN = 0x06,
    KMIP_TYPE_TEXT_STRING = 0x07,
    KMIP_TYPE_BYTE_STRING = 0x08,
    KMIP_TYPE_DATE_TIME = 0x09,
    KMIP_TYPE_INTERVAL = 0x0A,
    // KMIP 2.0
    KMIP_TYPE_DATE_TIME_EXTENDED = 0x0B
  };

  enum class wrapping_method : std::uint32_t {
    // KMIP 1.0
    KMIP_WRAP_ENCRYPT = 0x01,
    KMIP_WRAP_MAC_SIGN = 0x02,
    KMIP_WRAP_ENCRYPT_MAC_SIGN = 0x03,
    KMIP_WRAP_MAC_SIGN_ENCRYPT = 0x04,
    KMIP_WRAP_TR31 = 0x05
  };

  /** @brief KMIP revocation reason codes used by Revoke operations. */
  enum class revocation_reason_type : std::uint32_t {
    // KMIP 1.0
    KMIP_REVOKE_UNSPECIFIED = 0x01,
    KMIP_REVOKE_KEY_COMPROMISE = 0x02,
    KMIP_REVOKE_CA_COMPROMISE = 0x03,
    KMIP_REVOKE_AFFILIATION_CHANGED = 0x04,
    KMIP_REVOKE_SUSPENDED = 0x05,
    KMIP_REVOKE_CESSATION_OF_OPERATION = 0x06,
    KMIP_REVOKE_PRIVILEDGE_WITHDRAWN = 0x07,
    KMIP_REVOKE_EXTENSIONS = static_cast<std::uint32_t>(0x80000000u)
  };

  /** @brief KMIP secret payload data type identifiers. */
  enum class secret_data_type : std::uint32_t {
    // KMIP 1.0
    KMIP_SECDATA_PASSWORD = 0x01,
    KMIP_SECDATA_SEED = 0x02,
    KMIP_SECDATA_EXTENSIONS = static_cast<std::uint32_t>(0x80000000u)
  };

  // ---------------------------------------------------------------------------
  // Validation of attacker-controlled enumeration values.
  //
  // Enumerations on the wire are unconstrained 4-byte values. Before a parsed
  // value is cast into one of the scoped enums that drive key-handling
  // decisions, callers validate it against the known KMIP value tables so a
  // malicious server cannot inject undefined codes. Values in the Extensions
  // range are accepted: other software may legitimately store objects that
  // use them. They are kept as received; code that acts on a value matches
  // the defined codes it handles and treats any other value as unknown.
  //
  // The Cryptographic Usage Mask is not validated. KMIP 1.4 §9.1.3.3.1
  // Table 325 defines bits 0x00000001..0x00080000; KMIP 2.0 §12.1 Table 455
  // marks some of those (0x00000400, 0x00004000..0x00080000) Reserved and
  // defines 0x00100000..0x00800000. Both reserve XXX00000 for Extensions. So
  // every bit is a flag in at least one version or an extension bit, and the
  // parser cannot tell which version the object's attributes were set under.
  // ---------------------------------------------------------------------------

  /**
   * @brief Whether @p value is in the Extensions range of an enumeration.
   *
   * Extensions "contain the value 8 hex in the first nibble of the first byte"
   * (KMIP 1.4 §9.1.1.4, KMIP 2.0 §10.1.2), i.e. 0x80000000..0x8FFFFFFF.
   */
  [[nodiscard]] inline bool
      is_enumeration_extension(std::int32_t value) noexcept {
    return (static_cast<std::uint32_t>(value) & 0xF0000000u) == 0x80000000u;
  }

  /**
   * @brief Whether @p value is a defined or extension Cryptographic Algorithm
   *        code (KMIP 1.4 §9.1.3.2.13 Table 301, KMIP 2.0 §11.12 Table 405).
   */
  [[nodiscard]] inline bool
      is_valid_cryptographic_algorithm(std::int32_t value) noexcept {
    return (value >= static_cast<std::int32_t>(
                         cryptographic_algorithm::KMIP_CRYPTOALG_DES
                     ) &&
            value <= static_cast<std::int32_t>(
                         cryptographic_algorithm::KMIP_CRYPTOALG_ED448
                     )) ||
           is_enumeration_extension(value);
  }

  /**
   * @brief Whether @p value is a defined or extension lifecycle State code
   *        (KMIP 1.4 §9.1.3.2.18 Table 306, KMIP 2.0 §11.53 Table 445).
   */
  [[nodiscard]] inline bool is_valid_state(std::int32_t value) noexcept {
    return (value >= static_cast<std::int32_t>(state::KMIP_STATE_PRE_ACTIVE) &&
            value <= static_cast<std::int32_t>(
                         state::KMIP_STATE_DESTROYED_COMPROMISED
                     )) ||
           is_enumeration_extension(value);
  }

  /**
   * @brief Whether @p value is a defined or extension Secret Data Type code
   *        (KMIP 1.4 §9.1.3.2.9 Table 297, KMIP 2.0 §11.50 Table 443).
   */
  [[nodiscard]] inline bool
      is_valid_secret_data_type(std::int32_t value) noexcept {
    const auto raw = static_cast<std::uint32_t>(value);
    return raw == static_cast<std::uint32_t>(
                      secret_data_type::KMIP_SECDATA_PASSWORD
                  ) ||
           raw == static_cast<std::uint32_t>(
                      secret_data_type::KMIP_SECDATA_SEED
                  ) ||
           is_enumeration_extension(value);
  }

  /** @deprecated Every Cryptographic Usage Mask is valid; see above. */
  [[deprecated("every Cryptographic Usage Mask value is valid")]] [[nodiscard]]
  inline bool
      is_valid_cryptographic_usage_mask(std::int32_t /*value*/) noexcept {
    return true;
  }

  // ---------------------------------------------------------------------------
  // Compatibility constants for legacy unqualified enumerator usage.
  // These preserve existing integer-based call sites while the codebase is
  // migrated to explicit scoped-enum references.
  // ---------------------------------------------------------------------------

  inline constexpr std::uint32_t KMIP_ATTEST_TPM_QUOTE =
      static_cast<std::uint32_t>(attestation_type::KMIP_ATTEST_TPM_QUOTE);
  inline constexpr std::uint32_t KMIP_ATTEST_TCG_INTEGRITY_REPORT =
      static_cast<std::uint32_t>(
          attestation_type::KMIP_ATTEST_TCG_INTEGRITY_REPORT
      );
  inline constexpr std::uint32_t KMIP_ATTEST_SAML_ASSERTION =
      static_cast<std::uint32_t>(attestation_type::KMIP_ATTEST_SAML_ASSERTION);
  inline constexpr std::uint32_t KMIP_ATTR_UNIQUE_IDENTIFIER =
      static_cast<std::uint32_t>(attribute_type::KMIP_ATTR_UNIQUE_IDENTIFIER);
  inline constexpr std::uint32_t KMIP_ATTR_NAME =
      static_cast<std::uint32_t>(attribute_type::KMIP_ATTR_NAME);
  inline constexpr std::uint32_t KMIP_ATTR_OBJECT_TYPE =
      static_cast<std::uint32_t>(attribute_type::KMIP_ATTR_OBJECT_TYPE);
  inline constexpr std::uint32_t KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM =
      static_cast<std::uint32_t>(
          attribute_type::KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM
      );
  inline constexpr std::uint32_t KMIP_ATTR_CRYPTOGRAPHIC_LENGTH =
      static_cast<std::uint32_t>(
          attribute_type::KMIP_ATTR_CRYPTOGRAPHIC_LENGTH
      );
  inline constexpr std::uint32_t KMIP_ATTR_OPERATION_POLICY_NAME =
      static_cast<std::uint32_t>(
          attribute_type::KMIP_ATTR_OPERATION_POLICY_NAME
      );
  inline constexpr std::uint32_t KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK =
      static_cast<std::uint32_t>(
          attribute_type::KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK
      );
  inline constexpr std::uint32_t KMIP_ATTR_STATE =
      static_cast<std::uint32_t>(attribute_type::KMIP_ATTR_STATE);
  inline constexpr std::uint32_t KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION =
      static_cast<std::uint32_t>(
          attribute_type::KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION
      );
  inline constexpr std::uint32_t KMIP_ATTR_OBJECT_GROUP =
      static_cast<std::uint32_t>(attribute_type::KMIP_ATTR_OBJECT_GROUP);
  inline constexpr std::uint32_t KMIP_ATTR_ACTIVATION_DATE =
      static_cast<std::uint32_t>(attribute_type::KMIP_ATTR_ACTIVATION_DATE);
  inline constexpr std::uint32_t KMIP_ATTR_DEACTIVATION_DATE =
      static_cast<std::uint32_t>(attribute_type::KMIP_ATTR_DEACTIVATION_DATE);
  inline constexpr std::uint32_t KMIP_ATTR_PROCESS_START_DATE =
      static_cast<std::uint32_t>(attribute_type::KMIP_ATTR_PROCESS_START_DATE);
  inline constexpr std::uint32_t KMIP_ATTR_PROTECT_STOP_DATE =
      static_cast<std::uint32_t>(attribute_type::KMIP_ATTR_PROTECT_STOP_DATE);
  inline constexpr std::uint32_t KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS =
      static_cast<std::uint32_t>(
          attribute_type::KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS
      );
  inline constexpr std::uint32_t KMIP_BATCH_CONTINUE =
      static_cast<std::uint32_t>(
          batch_error_continuation_option::KMIP_BATCH_CONTINUE
      );
  inline constexpr std::uint32_t KMIP_BATCH_STOP = static_cast<std::uint32_t>(
      batch_error_continuation_option::KMIP_BATCH_STOP
  );
  inline constexpr std::uint32_t KMIP_BATCH_UNDO = static_cast<std::uint32_t>(
      batch_error_continuation_option::KMIP_BATCH_UNDO
  );
  inline constexpr std::uint32_t KMIP_BLOCK_CBC =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_CBC);
  inline constexpr std::uint32_t KMIP_BLOCK_ECB =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_ECB);
  inline constexpr std::uint32_t KMIP_BLOCK_PCBC =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_PCBC);
  inline constexpr std::uint32_t KMIP_BLOCK_CFB =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_CFB);
  inline constexpr std::uint32_t KMIP_BLOCK_OFB =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_OFB);
  inline constexpr std::uint32_t KMIP_BLOCK_CTR =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_CTR);
  inline constexpr std::uint32_t KMIP_BLOCK_CMAC =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_CMAC);
  inline constexpr std::uint32_t KMIP_BLOCK_CCM =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_CCM);
  inline constexpr std::uint32_t KMIP_BLOCK_GCM =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_GCM);
  inline constexpr std::uint32_t KMIP_BLOCK_CBC_MAC =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_CBC_MAC);
  inline constexpr std::uint32_t KMIP_BLOCK_XTS =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_XTS);
  inline constexpr std::uint32_t KMIP_BLOCK_AES_KEY_WRAP_PADDING =
      static_cast<std::uint32_t>(
          block_cipher_mode::KMIP_BLOCK_AES_KEY_WRAP_PADDING
      );
  inline constexpr std::uint32_t KMIP_BLOCK_NIST_KEY_WRAP =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_NIST_KEY_WRAP);
  inline constexpr std::uint32_t KMIP_BLOCK_X9102_AESKW =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_X9102_AESKW);
  inline constexpr std::uint32_t KMIP_BLOCK_X9102_TDKW =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_X9102_TDKW);
  inline constexpr std::uint32_t KMIP_BLOCK_X9102_AKW1 =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_X9102_AKW1);
  inline constexpr std::uint32_t KMIP_BLOCK_X9102_AKW2 =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_X9102_AKW2);
  inline constexpr std::uint32_t KMIP_BLOCK_AEAD =
      static_cast<std::uint32_t>(block_cipher_mode::KMIP_BLOCK_AEAD);
  inline constexpr std::uint32_t KMIP_CRED_USERNAME_AND_PASSWORD =
      static_cast<std::uint32_t>(
          credential_type::KMIP_CRED_USERNAME_AND_PASSWORD
      );
  inline constexpr std::uint32_t KMIP_CRED_DEVICE =
      static_cast<std::uint32_t>(credential_type::KMIP_CRED_DEVICE);
  inline constexpr std::uint32_t KMIP_CRED_ATTESTATION =
      static_cast<std::uint32_t>(credential_type::KMIP_CRED_ATTESTATION);
  inline constexpr std::uint32_t KMIP_CRED_ONE_TIME_PASSWORD =
      static_cast<std::uint32_t>(credential_type::KMIP_CRED_ONE_TIME_PASSWORD);
  inline constexpr std::uint32_t KMIP_CRED_HASHED_PASSWORD =
      static_cast<std::uint32_t>(credential_type::KMIP_CRED_HASHED_PASSWORD);
  inline constexpr std::uint32_t KMIP_CRED_TICKET =
      static_cast<std::uint32_t>(credential_type::KMIP_CRED_TICKET);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_UNSET =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_UNSET);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_DES =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_DES);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_TRIPLE_DES =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_TRIPLE_DES
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_AES =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_AES);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_RSA =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_RSA);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_DSA =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_DSA);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_ECDSA =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_ECDSA);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_HMAC_SHA1 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_HMAC_SHA1
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_HMAC_SHA224 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_HMAC_SHA224
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_HMAC_SHA256 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_HMAC_SHA256
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_HMAC_SHA384 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_HMAC_SHA384
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_HMAC_SHA512 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_HMAC_SHA512
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_HMAC_MD5 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_HMAC_MD5
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_DH =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_DH);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_ECDH =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_ECDH);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_ECMQV =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_ECMQV);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_BLOWFISH =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_BLOWFISH
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_CAMELLIA =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_CAMELLIA
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_CAST5 =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_CAST5);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_IDEA =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_IDEA);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_MARS =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_MARS);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_RC2 =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_RC2);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_RC4 =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_RC4);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_RC5 =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_RC5);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_SKIPJACK =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_SKIPJACK
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_TWOFISH =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_TWOFISH
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_EC =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_EC);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_ONE_TIME_PAD =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_ONE_TIME_PAD
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_CHACHA20 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_CHACHA20
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_POLY1305 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_POLY1305
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_CHACHA20_POLY1305 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_CHACHA20_POLY1305
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_SHA3_224 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_SHA3_224
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_SHA3_256 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_SHA3_256
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_SHA3_384 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_SHA3_384
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_SHA3_512 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_SHA3_512
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_HMAC_SHA3_224 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_HMAC_SHA3_224
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_HMAC_SHA3_256 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_HMAC_SHA3_256
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_HMAC_SHA3_384 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_HMAC_SHA3_384
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_HMAC_SHA3_512 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_HMAC_SHA3_512
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_SHAKE_128 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_SHAKE_128
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_SHAKE_256 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_SHAKE_256
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_ARIA =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_ARIA);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_SEED =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_SEED);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_SM2 =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_SM2);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_SM3 =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_SM3);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_SM4 =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_SM4);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_GOST_R_34_10_2012 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_GOST_R_34_10_2012
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_GOST_R_34_11_2012 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_GOST_R_34_11_2012
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_GOST_R_34_13_2015 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_GOST_R_34_13_2015
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_GOST_28147_89 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_GOST_28147_89
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_XMSS =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_XMSS);
  inline constexpr std::uint32_t KMIP_CRYPTOALG_SPHINCS_256 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_SPHINCS_256
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_MCELIECE =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_MCELIECE
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_MCELIECE_6960119 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_MCELIECE_6960119
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_MCELIECE_8192128 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_MCELIECE_8192128
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_ED25519 =
      static_cast<std::uint32_t>(
          cryptographic_algorithm::KMIP_CRYPTOALG_ED25519
      );
  inline constexpr std::uint32_t KMIP_CRYPTOALG_ED448 =
      static_cast<std::uint32_t>(cryptographic_algorithm::KMIP_CRYPTOALG_ED448);
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_UNSET =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_UNSET
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_SIGN =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_SIGN
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_VERIFY =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_VERIFY
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_ENCRYPT =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_ENCRYPT
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_DECRYPT =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_DECRYPT
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_WRAP_KEY =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_WRAP_KEY
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_UNWRAP_KEY =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_UNWRAP_KEY
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_EXPORT =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_EXPORT
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_MAC_GENERATE =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_MAC_GENERATE
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_MAC_VERIFY =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_MAC_VERIFY
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_DERIVE_KEY =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_DERIVE_KEY
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_CONTENT_COMMITMENT =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_CONTENT_COMMITMENT
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_KEY_AGREEMENT =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_KEY_AGREEMENT
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_CERTIFICATE_SIGN =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_CERTIFICATE_SIGN
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_CRL_SIGN =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_CRL_SIGN
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_GENERATE_CRYPTOGRAM =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_GENERATE_CRYPTOGRAM
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_VALIDATE_CRYPTOGRAM =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_VALIDATE_CRYPTOGRAM
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_TRANSLATE_ENCRYPT =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_TRANSLATE_ENCRYPT
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_TRANSLATE_DECRYPT =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_TRANSLATE_DECRYPT
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_TRANSLATE_WRAP =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_TRANSLATE_WRAP
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_TRANSLATE_UNWRAP =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_TRANSLATE_UNWRAP
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_AUTHENTICATE =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_AUTHENTICATE
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_UNRESTRICTED =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_UNRESTRICTED
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_FPE_ENCRYPT =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_FPE_ENCRYPT
      );
  inline constexpr std::uint32_t KMIP_CRYPTOMASK_FPE_DECRYPT =
      static_cast<std::uint32_t>(
          cryptographic_usage_mask::KMIP_CRYPTOMASK_FPE_DECRYPT
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_MD2_WITH_RSA =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_MD2_WITH_RSA
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_MD5_WITH_RSA =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_MD5_WITH_RSA
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_SHA1_WITH_RSA =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_SHA1_WITH_RSA
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_SHA224_WITH_RSA =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_SHA224_WITH_RSA
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_SHA256_WITH_RSA =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_SHA256_WITH_RSA
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_SHA384_WITH_RSA =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_SHA384_WITH_RSA
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_SHA512_WITH_RSA =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_SHA512_WITH_RSA
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_RSASSA_PSS =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_RSASSA_PSS
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_DSA_WITH_SHA1 =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_DSA_WITH_SHA1
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_DSA_WITH_SHA224 =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_DSA_WITH_SHA224
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_DSA_WITH_SHA256 =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_DSA_WITH_SHA256
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_ECDSA_WITH_SHA1 =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_ECDSA_WITH_SHA1
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_ECDSA_WITH_SHA224 =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_ECDSA_WITH_SHA224
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_ECDSA_WITH_SHA256 =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_ECDSA_WITH_SHA256
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_ECDSA_WITH_SHA384 =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_ECDSA_WITH_SHA384
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_ECDSA_WITH_SHA512 =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_ECDSA_WITH_SHA512
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_SHA3_256_WITH_RSA =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_SHA3_256_WITH_RSA
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_SHA3_384_WITH_RSA =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_SHA3_384_WITH_RSA
      );
  inline constexpr std::uint32_t KMIP_DIGITAL_SHA3_512_WITH_RSA =
      static_cast<std::uint32_t>(
          digital_signature_algorithm::KMIP_DIGITAL_SHA3_512_WITH_RSA
      );
  inline constexpr std::uint32_t KMIP_ENCODE_NO_ENCODING =
      static_cast<std::uint32_t>(encoding_option::KMIP_ENCODE_NO_ENCODING);
  inline constexpr std::uint32_t KMIP_ENCODE_TTLV_ENCODING =
      static_cast<std::uint32_t>(encoding_option::KMIP_ENCODE_TTLV_ENCODING);
  inline constexpr std::uint32_t KMIP_HASH_MD2 =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_MD2);
  inline constexpr std::uint32_t KMIP_HASH_MD4 =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_MD4);
  inline constexpr std::uint32_t KMIP_HASH_MD5 =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_MD5);
  inline constexpr std::uint32_t KMIP_HASH_SHA1 =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_SHA1);
  inline constexpr std::uint32_t KMIP_HASH_SHA224 =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_SHA224);
  inline constexpr std::uint32_t KMIP_HASH_SHA256 =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_SHA256);
  inline constexpr std::uint32_t KMIP_HASH_SHA384 =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_SHA384);
  inline constexpr std::uint32_t KMIP_HASH_SHA512 =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_SHA512);
  inline constexpr std::uint32_t KMIP_HASH_RIPEMD160 =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_RIPEMD160);
  inline constexpr std::uint32_t KMIP_HASH_TIGER =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_TIGER);
  inline constexpr std::uint32_t KMIP_HASH_WHIRLPOOL =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_WHIRLPOOL);
  inline constexpr std::uint32_t KMIP_HASH_SHA512_224 =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_SHA512_224);
  inline constexpr std::uint32_t KMIP_HASH_SHA512_256 =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_SHA512_256);
  inline constexpr std::uint32_t KMIP_HASH_SHA3_224 =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_SHA3_224);
  inline constexpr std::uint32_t KMIP_HASH_SHA3_256 =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_SHA3_256);
  inline constexpr std::uint32_t KMIP_HASH_SHA3_384 =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_SHA3_384);
  inline constexpr std::uint32_t KMIP_HASH_SHA3_512 =
      static_cast<std::uint32_t>(hashing_algorithm::KMIP_HASH_SHA3_512);
  inline constexpr std::uint32_t KMIP_KEYCOMP_EC_PUB_UNCOMPRESSED =
      static_cast<std::uint32_t>(
          key_compression_type::KMIP_KEYCOMP_EC_PUB_UNCOMPRESSED
      );
  inline constexpr std::uint32_t KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_PRIME =
      static_cast<std::uint32_t>(
          key_compression_type::KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_PRIME
      );
  inline constexpr std::uint32_t KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_CHAR2 =
      static_cast<std::uint32_t>(
          key_compression_type::KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_CHAR2
      );
  inline constexpr std::uint32_t KMIP_KEYCOMP_EC_PUB_X962_HYBRID =
      static_cast<std::uint32_t>(
          key_compression_type::KMIP_KEYCOMP_EC_PUB_X962_HYBRID
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_RAW =
      static_cast<std::uint32_t>(key_format_type::KMIP_KEYFORMAT_RAW);
  inline constexpr std::uint32_t KMIP_KEYFORMAT_OPAQUE =
      static_cast<std::uint32_t>(key_format_type::KMIP_KEYFORMAT_OPAQUE);
  inline constexpr std::uint32_t KMIP_KEYFORMAT_PKCS1 =
      static_cast<std::uint32_t>(key_format_type::KMIP_KEYFORMAT_PKCS1);
  inline constexpr std::uint32_t KMIP_KEYFORMAT_PKCS8 =
      static_cast<std::uint32_t>(key_format_type::KMIP_KEYFORMAT_PKCS8);
  inline constexpr std::uint32_t KMIP_KEYFORMAT_X509 =
      static_cast<std::uint32_t>(key_format_type::KMIP_KEYFORMAT_X509);
  inline constexpr std::uint32_t KMIP_KEYFORMAT_EC_PRIVATE_KEY =
      static_cast<std::uint32_t>(
          key_format_type::KMIP_KEYFORMAT_EC_PRIVATE_KEY
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY =
      static_cast<std::uint32_t>(
          key_format_type::KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_TRANS_DSA_PRIVATE_KEY =
      static_cast<std::uint32_t>(
          key_format_type::KMIP_KEYFORMAT_TRANS_DSA_PRIVATE_KEY
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_TRANS_DSA_PUBLIC_KEY =
      static_cast<std::uint32_t>(
          key_format_type::KMIP_KEYFORMAT_TRANS_DSA_PUBLIC_KEY
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_TRANS_RSA_PRIVATE_KEY =
      static_cast<std::uint32_t>(
          key_format_type::KMIP_KEYFORMAT_TRANS_RSA_PRIVATE_KEY
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_TRANS_RSA_PUBLIC_KEY =
      static_cast<std::uint32_t>(
          key_format_type::KMIP_KEYFORMAT_TRANS_RSA_PUBLIC_KEY
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_TRANS_DH_PRIVATE_KEY =
      static_cast<std::uint32_t>(
          key_format_type::KMIP_KEYFORMAT_TRANS_DH_PRIVATE_KEY
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_TRANS_DH_PUBLIC_KEY =
      static_cast<std::uint32_t>(
          key_format_type::KMIP_KEYFORMAT_TRANS_DH_PUBLIC_KEY
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_TRANS_ECDSA_PRIVATE_KEY =
      static_cast<std::uint32_t>(
          key_format_type::KMIP_KEYFORMAT_TRANS_ECDSA_PRIVATE_KEY
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_TRANS_ECDSA_PUBLIC_KEY =
      static_cast<std::uint32_t>(
          key_format_type::KMIP_KEYFORMAT_TRANS_ECDSA_PUBLIC_KEY
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_TRANS_ECDH_PRIVATE_KEY =
      static_cast<std::uint32_t>(
          key_format_type::KMIP_KEYFORMAT_TRANS_ECDH_PRIVATE_KEY
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_TRANS_ECDH_PUBLIC_KEY =
      static_cast<std::uint32_t>(
          key_format_type::KMIP_KEYFORMAT_TRANS_ECDH_PUBLIC_KEY
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_TRANS_ECMQV_PRIVATE_KEY =
      static_cast<std::uint32_t>(
          key_format_type::KMIP_KEYFORMAT_TRANS_ECMQV_PRIVATE_KEY
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_TRANS_ECMQV_PUBLIC_KEY =
      static_cast<std::uint32_t>(
          key_format_type::KMIP_KEYFORMAT_TRANS_ECMQV_PUBLIC_KEY
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_TRANS_EC_PRIVATE_KEY =
      static_cast<std::uint32_t>(
          key_format_type::KMIP_KEYFORMAT_TRANS_EC_PRIVATE_KEY
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_TRANS_EC_PUBLIC_KEY =
      static_cast<std::uint32_t>(
          key_format_type::KMIP_KEYFORMAT_TRANS_EC_PUBLIC_KEY
      );
  inline constexpr std::uint32_t KMIP_KEYFORMAT_PKCS12 =
      static_cast<std::uint32_t>(key_format_type::KMIP_KEYFORMAT_PKCS12);
  inline constexpr std::uint32_t KMIP_KEYFORMAT_PKCS10 =
      static_cast<std::uint32_t>(key_format_type::KMIP_KEYFORMAT_PKCS10);
  inline constexpr std::uint32_t KMIP_ROLE_BDK =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_BDK);
  inline constexpr std::uint32_t KMIP_ROLE_CVK =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_CVK);
  inline constexpr std::uint32_t KMIP_ROLE_DEK =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_DEK);
  inline constexpr std::uint32_t KMIP_ROLE_MKAC =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_MKAC);
  inline constexpr std::uint32_t KMIP_ROLE_MKSMC =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_MKSMC);
  inline constexpr std::uint32_t KMIP_ROLE_MKSMI =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_MKSMI);
  inline constexpr std::uint32_t KMIP_ROLE_MKDAC =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_MKDAC);
  inline constexpr std::uint32_t KMIP_ROLE_MKDN =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_MKDN);
  inline constexpr std::uint32_t KMIP_ROLE_MKCP =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_MKCP);
  inline constexpr std::uint32_t KMIP_ROLE_MKOTH =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_MKOTH);
  inline constexpr std::uint32_t KMIP_ROLE_KEK =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_KEK);
  inline constexpr std::uint32_t KMIP_ROLE_MAC16609 =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_MAC16609);
  inline constexpr std::uint32_t KMIP_ROLE_MAC97971 =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_MAC97971);
  inline constexpr std::uint32_t KMIP_ROLE_MAC97972 =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_MAC97972);
  inline constexpr std::uint32_t KMIP_ROLE_MAC97973 =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_MAC97973);
  inline constexpr std::uint32_t KMIP_ROLE_MAC97974 =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_MAC97974);
  inline constexpr std::uint32_t KMIP_ROLE_MAC97975 =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_MAC97975);
  inline constexpr std::uint32_t KMIP_ROLE_ZPK =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_ZPK);
  inline constexpr std::uint32_t KMIP_ROLE_PVKIBM =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_PVKIBM);
  inline constexpr std::uint32_t KMIP_ROLE_PVKPVV =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_PVKPVV);
  inline constexpr std::uint32_t KMIP_ROLE_PVKOTH =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_PVKOTH);
  inline constexpr std::uint32_t KMIP_ROLE_DUKPT =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_DUKPT);
  inline constexpr std::uint32_t KMIP_ROLE_IV =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_IV);
  inline constexpr std::uint32_t KMIP_ROLE_TRKBK =
      static_cast<std::uint32_t>(key_role_type::KMIP_ROLE_TRKBK);
  inline constexpr std::uint32_t KMIP_WRAPTYPE_NOT_WRAPPED =
      static_cast<std::uint32_t>(key_wrap_type::KMIP_WRAPTYPE_NOT_WRAPPED);
  inline constexpr std::uint32_t KMIP_WRAPTYPE_AS_REGISTERED =
      static_cast<std::uint32_t>(key_wrap_type::KMIP_WRAPTYPE_AS_REGISTERED);
  inline constexpr std::uint32_t KMIP_MASKGEN_MGF1 =
      static_cast<std::uint32_t>(mask_generator::KMIP_MASKGEN_MGF1);
  inline constexpr std::uint32_t KMIP_NAME_UNINTERPRETED_TEXT_STRING =
      static_cast<std::uint32_t>(
          name_type::KMIP_NAME_UNINTERPRETED_TEXT_STRING
      );
  inline constexpr std::uint32_t KMIP_NAME_URI =
      static_cast<std::uint32_t>(name_type::KMIP_NAME_URI);
  inline constexpr std::uint32_t KMIP_OBJTYPE_CERTIFICATE =
      static_cast<std::uint32_t>(object_type::KMIP_OBJTYPE_CERTIFICATE);
  inline constexpr std::uint32_t KMIP_OBJTYPE_SYMMETRIC_KEY =
      static_cast<std::uint32_t>(object_type::KMIP_OBJTYPE_SYMMETRIC_KEY);
  inline constexpr std::uint32_t KMIP_OBJTYPE_PUBLIC_KEY =
      static_cast<std::uint32_t>(object_type::KMIP_OBJTYPE_PUBLIC_KEY);
  inline constexpr std::uint32_t KMIP_OBJTYPE_PRIVATE_KEY =
      static_cast<std::uint32_t>(object_type::KMIP_OBJTYPE_PRIVATE_KEY);
  inline constexpr std::uint32_t KMIP_OBJTYPE_SPLIT_KEY =
      static_cast<std::uint32_t>(object_type::KMIP_OBJTYPE_SPLIT_KEY);
  inline constexpr std::uint32_t KMIP_OBJTYPE_TEMPLATE =
      static_cast<std::uint32_t>(object_type::KMIP_OBJTYPE_TEMPLATE);
  inline constexpr std::uint32_t KMIP_OBJTYPE_SECRET_DATA =
      static_cast<std::uint32_t>(object_type::KMIP_OBJTYPE_SECRET_DATA);
  inline constexpr std::uint32_t KMIP_OBJTYPE_OPAQUE_OBJECT =
      static_cast<std::uint32_t>(object_type::KMIP_OBJTYPE_OPAQUE_OBJECT);
  inline constexpr std::uint32_t KMIP_OBJTYPE_PGP_KEY =
      static_cast<std::uint32_t>(object_type::KMIP_OBJTYPE_PGP_KEY);
  inline constexpr std::uint32_t KMIP_OBJTYPE_CERTIFICATE_REQUEST =
      static_cast<std::uint32_t>(object_type::KMIP_OBJTYPE_CERTIFICATE_REQUEST);
  inline constexpr std::uint32_t KMIP_OP_CREATE =
      static_cast<std::uint32_t>(operation::KMIP_OP_CREATE);
  inline constexpr std::uint32_t KMIP_OP_CREATE_KEY_PAIR =
      static_cast<std::uint32_t>(operation::KMIP_OP_CREATE_KEY_PAIR);
  inline constexpr std::uint32_t KMIP_OP_REGISTER =
      static_cast<std::uint32_t>(operation::KMIP_OP_REGISTER);
  inline constexpr std::uint32_t KMIP_OP_REKEY =
      static_cast<std::uint32_t>(operation::KMIP_OP_REKEY);
  inline constexpr std::uint32_t KMIP_OP_DERIVE_KEY =
      static_cast<std::uint32_t>(operation::KMIP_OP_DERIVE_KEY);
  inline constexpr std::uint32_t KMIP_OP_CERTIFY =
      static_cast<std::uint32_t>(operation::KMIP_OP_CERTIFY);
  inline constexpr std::uint32_t KMIP_OP_RECERTIFY =
      static_cast<std::uint32_t>(operation::KMIP_OP_RECERTIFY);
  inline constexpr std::uint32_t KMIP_OP_LOCATE =
      static_cast<std::uint32_t>(operation::KMIP_OP_LOCATE);
  inline constexpr std::uint32_t KMIP_OP_CHECK =
      static_cast<std::uint32_t>(operation::KMIP_OP_CHECK);
  inline constexpr std::uint32_t KMIP_OP_GET =
      static_cast<std::uint32_t>(operation::KMIP_OP_GET);
  inline constexpr std::uint32_t KMIP_OP_GET_ATTRIBUTES =
      static_cast<std::uint32_t>(operation::KMIP_OP_GET_ATTRIBUTES);
  inline constexpr std::uint32_t KMIP_OP_GET_ATTRIBUTE_LIST =
      static_cast<std::uint32_t>(operation::KMIP_OP_GET_ATTRIBUTE_LIST);
  inline constexpr std::uint32_t KMIP_OP_ADD_ATTRIBUTE =
      static_cast<std::uint32_t>(operation::KMIP_OP_ADD_ATTRIBUTE);
  inline constexpr std::uint32_t KMIP_OP_MODIFY_ATTRIBUTE =
      static_cast<std::uint32_t>(operation::KMIP_OP_MODIFY_ATTRIBUTE);
  inline constexpr std::uint32_t KMIP_OP_DELETE_ATTRIBUTE =
      static_cast<std::uint32_t>(operation::KMIP_OP_DELETE_ATTRIBUTE);
  inline constexpr std::uint32_t KMIP_OP_OBTAIN_LEASE =
      static_cast<std::uint32_t>(operation::KMIP_OP_OBTAIN_LEASE);
  inline constexpr std::uint32_t KMIP_OP_GET_USAGE_ALLOCATION =
      static_cast<std::uint32_t>(operation::KMIP_OP_GET_USAGE_ALLOCATION);
  inline constexpr std::uint32_t KMIP_OP_ACTIVATE =
      static_cast<std::uint32_t>(operation::KMIP_OP_ACTIVATE);
  inline constexpr std::uint32_t KMIP_OP_REVOKE =
      static_cast<std::uint32_t>(operation::KMIP_OP_REVOKE);
  inline constexpr std::uint32_t KMIP_OP_DESTROY =
      static_cast<std::uint32_t>(operation::KMIP_OP_DESTROY);
  inline constexpr std::uint32_t KMIP_OP_ARCHIVE =
      static_cast<std::uint32_t>(operation::KMIP_OP_ARCHIVE);
  inline constexpr std::uint32_t KMIP_OP_RECOVER =
      static_cast<std::uint32_t>(operation::KMIP_OP_RECOVER);
  inline constexpr std::uint32_t KMIP_OP_VALIDATE =
      static_cast<std::uint32_t>(operation::KMIP_OP_VALIDATE);
  inline constexpr std::uint32_t KMIP_OP_QUERY =
      static_cast<std::uint32_t>(operation::KMIP_OP_QUERY);
  inline constexpr std::uint32_t KMIP_OP_CANCEL =
      static_cast<std::uint32_t>(operation::KMIP_OP_CANCEL);
  inline constexpr std::uint32_t KMIP_OP_POLL =
      static_cast<std::uint32_t>(operation::KMIP_OP_POLL);
  inline constexpr std::uint32_t KMIP_OP_NOTIFY =
      static_cast<std::uint32_t>(operation::KMIP_OP_NOTIFY);
  inline constexpr std::uint32_t KMIP_OP_PUT =
      static_cast<std::uint32_t>(operation::KMIP_OP_PUT);
  inline constexpr std::uint32_t KMIP_OP_REKEY_KEY_PAIR =
      static_cast<std::uint32_t>(operation::KMIP_OP_REKEY_KEY_PAIR);
  inline constexpr std::uint32_t KMIP_OP_DISCOVER_VERSIONS =
      static_cast<std::uint32_t>(operation::KMIP_OP_DISCOVER_VERSIONS);
  inline constexpr std::uint32_t KMIP_OP_ENCRYPT =
      static_cast<std::uint32_t>(operation::KMIP_OP_ENCRYPT);
  inline constexpr std::uint32_t KMIP_OP_DECRYPT =
      static_cast<std::uint32_t>(operation::KMIP_OP_DECRYPT);
  inline constexpr std::uint32_t KMIP_OP_SIGN =
      static_cast<std::uint32_t>(operation::KMIP_OP_SIGN);
  inline constexpr std::uint32_t KMIP_OP_SIGNATURE_VERIFY =
      static_cast<std::uint32_t>(operation::KMIP_OP_SIGNATURE_VERIFY);
  inline constexpr std::uint32_t KMIP_OP_MAC =
      static_cast<std::uint32_t>(operation::KMIP_OP_MAC);
  inline constexpr std::uint32_t KMIP_OP_MAC_VERIFY =
      static_cast<std::uint32_t>(operation::KMIP_OP_MAC_VERIFY);
  inline constexpr std::uint32_t KMIP_OP_RNG_RETRIEVE =
      static_cast<std::uint32_t>(operation::KMIP_OP_RNG_RETRIEVE);
  inline constexpr std::uint32_t KMIP_OP_RNG_SEED =
      static_cast<std::uint32_t>(operation::KMIP_OP_RNG_SEED);
  inline constexpr std::uint32_t KMIP_OP_HASH =
      static_cast<std::uint32_t>(operation::KMIP_OP_HASH);
  inline constexpr std::uint32_t KMIP_OP_CREATE_SPLIT_KEY =
      static_cast<std::uint32_t>(operation::KMIP_OP_CREATE_SPLIT_KEY);
  inline constexpr std::uint32_t KMIP_OP_JOIN_SPLIT_KEY =
      static_cast<std::uint32_t>(operation::KMIP_OP_JOIN_SPLIT_KEY);
  inline constexpr std::uint32_t KMIP_OP_IMPORT =
      static_cast<std::uint32_t>(operation::KMIP_OP_IMPORT);
  inline constexpr std::uint32_t KMIP_OP_EXPORT =
      static_cast<std::uint32_t>(operation::KMIP_OP_EXPORT);
  inline constexpr std::uint32_t KMIP_OP_LOG =
      static_cast<std::uint32_t>(operation::KMIP_OP_LOG);
  inline constexpr std::uint32_t KMIP_OP_LOGIN =
      static_cast<std::uint32_t>(operation::KMIP_OP_LOGIN);
  inline constexpr std::uint32_t KMIP_OP_LOGOUT =
      static_cast<std::uint32_t>(operation::KMIP_OP_LOGOUT);
  inline constexpr std::uint32_t KMIP_OP_DELEGATED_LOGIN =
      static_cast<std::uint32_t>(operation::KMIP_OP_DELEGATED_LOGIN);
  inline constexpr std::uint32_t KMIP_OP_ADJUST_ATTRIBUTE =
      static_cast<std::uint32_t>(operation::KMIP_OP_ADJUST_ATTRIBUTE);
  inline constexpr std::uint32_t KMIP_OP_SET_ATTRIBUTE =
      static_cast<std::uint32_t>(operation::KMIP_OP_SET_ATTRIBUTE);
  inline constexpr std::uint32_t KMIP_OP_SET_ENDPOINT_ROLE =
      static_cast<std::uint32_t>(operation::KMIP_OP_SET_ENDPOINT_ROLE);
  inline constexpr std::uint32_t KMIP_OP_PKCS_11 =
      static_cast<std::uint32_t>(operation::KMIP_OP_PKCS_11);
  inline constexpr std::uint32_t KMIP_OP_INTEROP =
      static_cast<std::uint32_t>(operation::KMIP_OP_INTEROP);
  inline constexpr std::uint32_t KMIP_OP_REPROVISION =
      static_cast<std::uint32_t>(operation::KMIP_OP_REPROVISION);
  inline constexpr std::uint32_t KMIP_PAD_NONE =
      static_cast<std::uint32_t>(padding_method::KMIP_PAD_NONE);
  inline constexpr std::uint32_t KMIP_PAD_OAEP =
      static_cast<std::uint32_t>(padding_method::KMIP_PAD_OAEP);
  inline constexpr std::uint32_t KMIP_PAD_PKCS5 =
      static_cast<std::uint32_t>(padding_method::KMIP_PAD_PKCS5);
  inline constexpr std::uint32_t KMIP_PAD_SSL3 =
      static_cast<std::uint32_t>(padding_method::KMIP_PAD_SSL3);
  inline constexpr std::uint32_t KMIP_PAD_ZEROS =
      static_cast<std::uint32_t>(padding_method::KMIP_PAD_ZEROS);
  inline constexpr std::uint32_t KMIP_PAD_ANSI_X923 =
      static_cast<std::uint32_t>(padding_method::KMIP_PAD_ANSI_X923);
  inline constexpr std::uint32_t KMIP_PAD_ISO_10126 =
      static_cast<std::uint32_t>(padding_method::KMIP_PAD_ISO_10126);
  inline constexpr std::uint32_t KMIP_PAD_X931 =
      static_cast<std::uint32_t>(padding_method::KMIP_PAD_X931);
  inline constexpr std::uint32_t KMIP_PAD_PSS =
      static_cast<std::uint32_t>(padding_method::KMIP_PAD_PSS);
  inline constexpr std::uint32_t KMIP_PROTECT_SOFTWARE =
      static_cast<std::uint32_t>(
          protection_storage_mask::KMIP_PROTECT_SOFTWARE
      );
  inline constexpr std::uint32_t KMIP_PROTECT_HARDWARE =
      static_cast<std::uint32_t>(
          protection_storage_mask::KMIP_PROTECT_HARDWARE
      );
  inline constexpr std::uint32_t KMIP_PROTECT_ON_PROCESSOR =
      static_cast<std::uint32_t>(
          protection_storage_mask::KMIP_PROTECT_ON_PROCESSOR
      );
  inline constexpr std::uint32_t KMIP_PROTECT_ON_SYSTEM =
      static_cast<std::uint32_t>(
          protection_storage_mask::KMIP_PROTECT_ON_SYSTEM
      );
  inline constexpr std::uint32_t KMIP_PROTECT_OFF_SYSTEM =
      static_cast<std::uint32_t>(
          protection_storage_mask::KMIP_PROTECT_OFF_SYSTEM
      );
  inline constexpr std::uint32_t KMIP_PROTECT_HYPERVISOR =
      static_cast<std::uint32_t>(
          protection_storage_mask::KMIP_PROTECT_HYPERVISOR
      );
  inline constexpr std::uint32_t KMIP_PROTECT_OPERATING_SYSTEM =
      static_cast<std::uint32_t>(
          protection_storage_mask::KMIP_PROTECT_OPERATING_SYSTEM
      );
  inline constexpr std::uint32_t KMIP_PROTECT_CONTAINER =
      static_cast<std::uint32_t>(
          protection_storage_mask::KMIP_PROTECT_CONTAINER
      );
  inline constexpr std::uint32_t KMIP_PROTECT_ON_PREMISES =
      static_cast<std::uint32_t>(
          protection_storage_mask::KMIP_PROTECT_ON_PREMISES
      );
  inline constexpr std::uint32_t KMIP_PROTECT_OFF_PREMISES =
      static_cast<std::uint32_t>(
          protection_storage_mask::KMIP_PROTECT_OFF_PREMISES
      );
  inline constexpr std::uint32_t KMIP_PROTECT_SELF_MANAGED =
      static_cast<std::uint32_t>(
          protection_storage_mask::KMIP_PROTECT_SELF_MANAGED
      );
  inline constexpr std::uint32_t KMIP_PROTECT_OUTSOURCED =
      static_cast<std::uint32_t>(
          protection_storage_mask::KMIP_PROTECT_OUTSOURCED
      );
  inline constexpr std::uint32_t KMIP_PROTECT_VALIDATED =
      static_cast<std::uint32_t>(
          protection_storage_mask::KMIP_PROTECT_VALIDATED
      );
  inline constexpr std::uint32_t KMIP_PROTECT_SAME_JURISDICTION =
      static_cast<std::uint32_t>(
          protection_storage_mask::KMIP_PROTECT_SAME_JURISDICTION
      );
  inline constexpr std::uint32_t KMIP_QUERY_OPERATIONS =
      static_cast<std::uint32_t>(query_function::KMIP_QUERY_OPERATIONS);
  inline constexpr std::uint32_t KMIP_QUERY_OBJECTS =
      static_cast<std::uint32_t>(query_function::KMIP_QUERY_OBJECTS);
  inline constexpr std::uint32_t KMIP_QUERY_SERVER_INFORMATION =
      static_cast<std::uint32_t>(query_function::KMIP_QUERY_SERVER_INFORMATION);
  inline constexpr std::uint32_t KMIP_QUERY_APPLICATION_NAMESPACES =
      static_cast<std::uint32_t>(
          query_function::KMIP_QUERY_APPLICATION_NAMESPACES
      );
  inline constexpr std::uint32_t KMIP_QUERY_EXTENSION_LIST =
      static_cast<std::uint32_t>(query_function::KMIP_QUERY_EXTENSION_LIST);
  inline constexpr std::uint32_t KMIP_QUERY_EXTENSION_MAP =
      static_cast<std::uint32_t>(query_function::KMIP_QUERY_EXTENSION_MAP);
  inline constexpr std::uint32_t KMIP_QUERY_ATTESTATION_TYPES =
      static_cast<std::uint32_t>(query_function::KMIP_QUERY_ATTESTATION_TYPES);
  inline constexpr std::uint32_t KMIP_QUERY_RNGS =
      static_cast<std::uint32_t>(query_function::KMIP_QUERY_RNGS);
  inline constexpr std::uint32_t KMIP_QUERY_VALIDATIONS =
      static_cast<std::uint32_t>(query_function::KMIP_QUERY_VALIDATIONS);
  inline constexpr std::uint32_t KMIP_QUERY_PROFILES =
      static_cast<std::uint32_t>(query_function::KMIP_QUERY_PROFILES);
  inline constexpr std::uint32_t KMIP_QUERY_CAPABILITIES =
      static_cast<std::uint32_t>(query_function::KMIP_QUERY_CAPABILITIES);
  inline constexpr std::uint32_t KMIP_QUERY_CLIENT_REGISTRATION_METHODS =
      static_cast<std::uint32_t>(
          query_function::KMIP_QUERY_CLIENT_REGISTRATION_METHODS
      );
  inline constexpr std::uint32_t KMIP_QUERY_DEFAULTS_INFORMATION =
      static_cast<std::uint32_t>(
          query_function::KMIP_QUERY_DEFAULTS_INFORMATION
      );
  inline constexpr std::uint32_t KMIP_QUERY_STORAGE_PROTECTION_MASKS =
      static_cast<std::uint32_t>(
          query_function::KMIP_QUERY_STORAGE_PROTECTION_MASKS
      );
  inline constexpr std::uint32_t KMIP_REASON_GENERAL_FAILURE =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_GENERAL_FAILURE);
  inline constexpr std::uint32_t KMIP_REASON_ITEM_NOT_FOUND =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_ITEM_NOT_FOUND);
  inline constexpr std::uint32_t KMIP_REASON_RESPONSE_TOO_LARGE =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_RESPONSE_TOO_LARGE);
  inline constexpr std::uint32_t KMIP_REASON_AUTHENTICATION_NOT_SUCCESSFUL =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_AUTHENTICATION_NOT_SUCCESSFUL
      );
  inline constexpr std::uint32_t KMIP_REASON_INVALID_MESSAGE =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_INVALID_MESSAGE);
  inline constexpr std::uint32_t KMIP_REASON_OPERATION_NOT_SUPPORTED =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_OPERATION_NOT_SUPPORTED
      );
  inline constexpr std::uint32_t KMIP_REASON_MISSING_DATA =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_MISSING_DATA);
  inline constexpr std::uint32_t KMIP_REASON_INVALID_FIELD =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_INVALID_FIELD);
  inline constexpr std::uint32_t KMIP_REASON_FEATURE_NOT_SUPPORTED =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_FEATURE_NOT_SUPPORTED
      );
  inline constexpr std::uint32_t KMIP_REASON_OPERATION_CANCELED_BY_REQUESTER =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_OPERATION_CANCELED_BY_REQUESTER
      );
  inline constexpr std::uint32_t KMIP_REASON_CRYPTOGRAPHIC_FAILURE =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_CRYPTOGRAPHIC_FAILURE
      );
  inline constexpr std::uint32_t KMIP_REASON_ILLEGAL_OPERATION =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_ILLEGAL_OPERATION);
  inline constexpr std::uint32_t KMIP_REASON_PERMISSION_DENIED =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_PERMISSION_DENIED);
  inline constexpr std::uint32_t KMIP_REASON_OBJECT_ARCHIVED =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_OBJECT_ARCHIVED);
  inline constexpr std::uint32_t KMIP_REASON_INDEX_OUT_OF_BOUNDS =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_INDEX_OUT_OF_BOUNDS
      );
  inline constexpr std::uint32_t
      KMIP_REASON_APPLICATION_NAMESPACE_NOT_SUPPORTED =
          static_cast<std::uint32_t>(
              result_reason::KMIP_REASON_APPLICATION_NAMESPACE_NOT_SUPPORTED
          );
  inline constexpr std::uint32_t KMIP_REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED
      );
  inline constexpr std::uint32_t
      KMIP_REASON_KEY_COMPRESSION_TYPE_NOT_SUPPORTED =
          static_cast<std::uint32_t>(
              result_reason::KMIP_REASON_KEY_COMPRESSION_TYPE_NOT_SUPPORTED
          );
  inline constexpr std::uint32_t KMIP_REASON_ENCODING_OPTION_FAILURE =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_ENCODING_OPTION_FAILURE
      );
  inline constexpr std::uint32_t KMIP_REASON_KEY_VALUE_NOT_PRESENT =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_KEY_VALUE_NOT_PRESENT
      );
  inline constexpr std::uint32_t KMIP_REASON_ATTESTATION_REQUIRED =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_ATTESTATION_REQUIRED
      );
  inline constexpr std::uint32_t KMIP_REASON_ATTESTATION_FAILED =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_ATTESTATION_FAILED);
  inline constexpr std::uint32_t KMIP_REASON_SENSITIVE =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_SENSITIVE);
  inline constexpr std::uint32_t KMIP_REASON_NOT_EXTRACTABLE =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_NOT_EXTRACTABLE);
  inline constexpr std::uint32_t KMIP_REASON_OBJECT_ALREADY_EXISTS =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_OBJECT_ALREADY_EXISTS
      );
  inline constexpr std::uint32_t KMIP_REASON_INVALID_TICKET =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_INVALID_TICKET);
  inline constexpr std::uint32_t KMIP_REASON_USAGE_LIMIT_EXCEEDED =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_USAGE_LIMIT_EXCEEDED
      );
  inline constexpr std::uint32_t KMIP_REASON_NUMERIC_RANGE =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_NUMERIC_RANGE);
  inline constexpr std::uint32_t KMIP_REASON_INVALID_DATA_TYPE =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_INVALID_DATA_TYPE);
  inline constexpr std::uint32_t KMIP_REASON_READ_ONLY_ATTRIBUTE =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_READ_ONLY_ATTRIBUTE
      );
  inline constexpr std::uint32_t KMIP_REASON_MULTI_VALUED_ATTRIBUTE =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_MULTI_VALUED_ATTRIBUTE
      );
  inline constexpr std::uint32_t KMIP_REASON_UNSUPPORTED_ATTRIBUTE =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_UNSUPPORTED_ATTRIBUTE
      );
  inline constexpr std::uint32_t KMIP_REASON_ATTRIBUTE_INSTANCE_NOT_FOUND =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_ATTRIBUTE_INSTANCE_NOT_FOUND
      );
  inline constexpr std::uint32_t KMIP_REASON_ATTRIBUTE_NOT_FOUND =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_ATTRIBUTE_NOT_FOUND
      );
  inline constexpr std::uint32_t KMIP_REASON_ATTRIBUTE_READ_ONLY =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_ATTRIBUTE_READ_ONLY
      );
  inline constexpr std::uint32_t KMIP_REASON_ATTRIBUTE_SINGLE_VALUED =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_ATTRIBUTE_SINGLE_VALUED
      );
  inline constexpr std::uint32_t KMIP_REASON_BAD_CRYPTOGRAPHIC_PARAMETERS =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_BAD_CRYPTOGRAPHIC_PARAMETERS
      );
  inline constexpr std::uint32_t KMIP_REASON_BAD_PASSWORD =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_BAD_PASSWORD);
  inline constexpr std::uint32_t KMIP_REASON_CODEC_ERROR =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_CODEC_ERROR);
  inline constexpr std::uint32_t KMIP_REASON_ILLEGAL_OBJECT_TYPE =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_ILLEGAL_OBJECT_TYPE
      );
  inline constexpr std::uint32_t
      KMIP_REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK =
          static_cast<std::uint32_t>(
              result_reason::KMIP_REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK
          );
  inline constexpr std::uint32_t KMIP_REASON_INTERNAL_SERVER_ERROR =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_INTERNAL_SERVER_ERROR
      );
  inline constexpr std::uint32_t
      KMIP_REASON_INVALID_ASYNCHRONOUS_CORRELATION_VALUE =
          static_cast<std::uint32_t>(
              result_reason::KMIP_REASON_INVALID_ASYNCHRONOUS_CORRELATION_VALUE
          );
  inline constexpr std::uint32_t KMIP_REASON_INVALID_ATTRIBUTE =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_INVALID_ATTRIBUTE);
  inline constexpr std::uint32_t KMIP_REASON_INVALID_ATTRIBUTE_VALUE =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_INVALID_ATTRIBUTE_VALUE
      );
  inline constexpr std::uint32_t KMIP_REASON_INVALID_CORRELATION_VALUE =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_INVALID_CORRELATION_VALUE
      );
  inline constexpr std::uint32_t KMIP_REASON_INVALID_CSR =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_INVALID_CSR);
  inline constexpr std::uint32_t KMIP_REASON_INVALID_OBJECT_TYPE =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_INVALID_OBJECT_TYPE
      );
  inline constexpr std::uint32_t KMIP_REASON_KEY_WRAP_TYPE_NOT_SUPPORTED =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_KEY_WRAP_TYPE_NOT_SUPPORTED
      );
  inline constexpr std::uint32_t KMIP_REASON_MISSING_INITIALIZATION_VECTOR =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_MISSING_INITIALIZATION_VECTOR
      );
  inline constexpr std::uint32_t KMIP_REASON_NON_UNIQUE_NAME_ATTRIBUTE =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_NON_UNIQUE_NAME_ATTRIBUTE
      );
  inline constexpr std::uint32_t KMIP_REASON_OBJECT_DESTROYED =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_OBJECT_DESTROYED);
  inline constexpr std::uint32_t KMIP_REASON_OBJECT_NOT_FOUND =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_OBJECT_NOT_FOUND);
  inline constexpr std::uint32_t KMIP_REASON_NOT_AUTHORISED =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_NOT_AUTHORISED);
  inline constexpr std::uint32_t KMIP_REASON_SERVER_LIMIT_EXCEEDED =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_SERVER_LIMIT_EXCEEDED
      );
  inline constexpr std::uint32_t KMIP_REASON_UNKNOWN_ENUMERATION =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_UNKNOWN_ENUMERATION
      );
  inline constexpr std::uint32_t KMIP_REASON_UNKNOWN_MESSAGE_EXTENSION =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_UNKNOWN_MESSAGE_EXTENSION
      );
  inline constexpr std::uint32_t KMIP_REASON_UNKNOWN_TAG =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_UNKNOWN_TAG);
  inline constexpr std::uint32_t
      KMIP_REASON_UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS =
          static_cast<std::uint32_t>(
              result_reason::KMIP_REASON_UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS
          );
  inline constexpr std::uint32_t KMIP_REASON_UNSUPPORTED_PROTOCOL_VERSION =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_UNSUPPORTED_PROTOCOL_VERSION
      );
  inline constexpr std::uint32_t KMIP_REASON_WRAPPING_OBJECT_ARCHIVED =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_WRAPPING_OBJECT_ARCHIVED
      );
  inline constexpr std::uint32_t KMIP_REASON_WRAPPING_OBJECT_DESTROYED =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_WRAPPING_OBJECT_DESTROYED
      );
  inline constexpr std::uint32_t KMIP_REASON_WRAPPING_OBJECT_NOT_FOUND =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_WRAPPING_OBJECT_NOT_FOUND
      );
  inline constexpr std::uint32_t KMIP_REASON_WRONG_KEY_LIFECYCLE_STATE =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_WRONG_KEY_LIFECYCLE_STATE
      );
  inline constexpr std::uint32_t KMIP_REASON_PROTECTION_STORAGE_UNAVAILABLE =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_PROTECTION_STORAGE_UNAVAILABLE
      );
  inline constexpr std::uint32_t KMIP_REASON_PKCS11_CODEC_ERROR =
      static_cast<std::uint32_t>(result_reason::KMIP_REASON_PKCS11_CODEC_ERROR);
  inline constexpr std::uint32_t KMIP_REASON_PKCS11_INVALID_FUNCTION =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_PKCS11_INVALID_FUNCTION
      );
  inline constexpr std::uint32_t KMIP_REASON_PKCS11_INVALID_INTERFACE =
      static_cast<std::uint32_t>(
          result_reason::KMIP_REASON_PKCS11_INVALID_INTERFACE
      );
  inline constexpr std::uint32_t
      KMIP_REASON_PRIVATE_PROTECTION_STORAGE_UNAVAILABLE =
          static_cast<std::uint32_t>(
              result_reason::KMIP_REASON_PRIVATE_PROTECTION_STORAGE_UNAVAILABLE
          );
  inline constexpr std::uint32_t
      KMIP_REASON_PUBLIC_PROTECTION_STORAGE_UNAVAILABLE =
          static_cast<std::uint32_t>(
              result_reason::KMIP_REASON_PUBLIC_PROTECTION_STORAGE_UNAVAILABLE
          );
  inline constexpr std::uint32_t KMIP_STATUS_SUCCESS =
      static_cast<std::uint32_t>(result_status::KMIP_STATUS_SUCCESS);
  inline constexpr std::uint32_t KMIP_STATUS_OPERATION_FAILED =
      static_cast<std::uint32_t>(result_status::KMIP_STATUS_OPERATION_FAILED);
  inline constexpr std::uint32_t KMIP_STATUS_OPERATION_PENDING =
      static_cast<std::uint32_t>(result_status::KMIP_STATUS_OPERATION_PENDING);
  inline constexpr std::uint32_t KMIP_STATUS_OPERATION_UNDONE =
      static_cast<std::uint32_t>(result_status::KMIP_STATUS_OPERATION_UNDONE);
  inline constexpr std::uint32_t KMIP_STATE_PRE_ACTIVE =
      static_cast<std::uint32_t>(state::KMIP_STATE_PRE_ACTIVE);
  inline constexpr std::uint32_t KMIP_STATE_ACTIVE =
      static_cast<std::uint32_t>(state::KMIP_STATE_ACTIVE);
  inline constexpr std::uint32_t KMIP_STATE_DEACTIVATED =
      static_cast<std::uint32_t>(state::KMIP_STATE_DEACTIVATED);
  inline constexpr std::uint32_t KMIP_STATE_COMPROMISED =
      static_cast<std::uint32_t>(state::KMIP_STATE_COMPROMISED);
  inline constexpr std::uint32_t KMIP_STATE_DESTROYED =
      static_cast<std::uint32_t>(state::KMIP_STATE_DESTROYED);
  inline constexpr std::uint32_t KMIP_STATE_DESTROYED_COMPROMISED =
      static_cast<std::uint32_t>(state::KMIP_STATE_DESTROYED_COMPROMISED);
  inline constexpr std::uint32_t KMIP_TAG_TAG =
      static_cast<std::uint32_t>(tag::KMIP_TAG_TAG);
  inline constexpr std::uint32_t KMIP_TAG_TYPE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_TYPE);
  inline constexpr std::uint32_t KMIP_TAG_DEFAULT =
      static_cast<std::uint32_t>(tag::KMIP_TAG_DEFAULT);
  inline constexpr std::uint32_t KMIP_TAG_ACTIVATION_DATE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_ACTIVATION_DATE);
  inline constexpr std::uint32_t KMIP_TAG_APPLICATION_DATA =
      static_cast<std::uint32_t>(tag::KMIP_TAG_APPLICATION_DATA);
  inline constexpr std::uint32_t KMIP_TAG_APPLICATION_NAMESPACE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_APPLICATION_NAMESPACE);
  inline constexpr std::uint32_t KMIP_TAG_APPLICATION_SPECIFIC_INFORMATION =
      static_cast<std::uint32_t>(
          tag::KMIP_TAG_APPLICATION_SPECIFIC_INFORMATION
      );
  inline constexpr std::uint32_t KMIP_TAG_ATTRIBUTE_REFERENCE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_ATTRIBUTE_REFERENCE);
  inline constexpr std::uint32_t KMIP_TAG_ASYNCHRONOUS_CORRELATION_VALUE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_ASYNCHRONOUS_CORRELATION_VALUE);
  inline constexpr std::uint32_t KMIP_TAG_ASYNCHRONOUS_INDICATOR =
      static_cast<std::uint32_t>(tag::KMIP_TAG_ASYNCHRONOUS_INDICATOR);
  inline constexpr std::uint32_t KMIP_TAG_ATTRIBUTE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_ATTRIBUTE);
  inline constexpr std::uint32_t KMIP_TAG_ATTRIBUTE_INDEX =
      static_cast<std::uint32_t>(tag::KMIP_TAG_ATTRIBUTE_INDEX);
  inline constexpr std::uint32_t KMIP_TAG_ATTRIBUTE_NAME =
      static_cast<std::uint32_t>(tag::KMIP_TAG_ATTRIBUTE_NAME);
  inline constexpr std::uint32_t KMIP_TAG_ATTRIBUTE_VALUE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_ATTRIBUTE_VALUE);
  inline constexpr std::uint32_t KMIP_TAG_AUTHENTICATION =
      static_cast<std::uint32_t>(tag::KMIP_TAG_AUTHENTICATION);
  inline constexpr std::uint32_t KMIP_TAG_BATCH_COUNT =
      static_cast<std::uint32_t>(tag::KMIP_TAG_BATCH_COUNT);
  inline constexpr std::uint32_t KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION =
      static_cast<std::uint32_t>(tag::KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION);
  inline constexpr std::uint32_t KMIP_TAG_BATCH_ITEM =
      static_cast<std::uint32_t>(tag::KMIP_TAG_BATCH_ITEM);
  inline constexpr std::uint32_t KMIP_TAG_BATCH_ORDER_OPTION =
      static_cast<std::uint32_t>(tag::KMIP_TAG_BATCH_ORDER_OPTION);
  inline constexpr std::uint32_t KMIP_TAG_BLOCK_CIPHER_MODE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_BLOCK_CIPHER_MODE);
  inline constexpr std::uint32_t KMIP_TAG_COMPROMISE_OCCURRANCE_DATE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_COMPROMISE_OCCURRANCE_DATE);
  inline constexpr std::uint32_t KMIP_TAG_CREDENTIAL =
      static_cast<std::uint32_t>(tag::KMIP_TAG_CREDENTIAL);
  inline constexpr std::uint32_t KMIP_TAG_CREDENTIAL_TYPE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_CREDENTIAL_TYPE);
  inline constexpr std::uint32_t KMIP_TAG_CREDENTIAL_VALUE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_CREDENTIAL_VALUE);
  inline constexpr std::uint32_t KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM =
      static_cast<std::uint32_t>(tag::KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM);
  inline constexpr std::uint32_t KMIP_TAG_CRYPTOGRAPHIC_LENGTH =
      static_cast<std::uint32_t>(tag::KMIP_TAG_CRYPTOGRAPHIC_LENGTH);
  inline constexpr std::uint32_t KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS =
      static_cast<std::uint32_t>(tag::KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS);
  inline constexpr std::uint32_t KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK =
      static_cast<std::uint32_t>(tag::KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK);
  inline constexpr std::uint32_t KMIP_TAG_DEACTIVATION_DATE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_DEACTIVATION_DATE);
  inline constexpr std::uint32_t KMIP_TAG_ENCRYPTION_KEY_INFORMATION =
      static_cast<std::uint32_t>(tag::KMIP_TAG_ENCRYPTION_KEY_INFORMATION);
  inline constexpr std::uint32_t KMIP_TAG_HASHING_ALGORITHM =
      static_cast<std::uint32_t>(tag::KMIP_TAG_HASHING_ALGORITHM);
  inline constexpr std::uint32_t KMIP_TAG_IV_COUNTER_NONCE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_IV_COUNTER_NONCE);
  inline constexpr std::uint32_t KMIP_TAG_KEY =
      static_cast<std::uint32_t>(tag::KMIP_TAG_KEY);
  inline constexpr std::uint32_t KMIP_TAG_KEY_BLOCK =
      static_cast<std::uint32_t>(tag::KMIP_TAG_KEY_BLOCK);
  inline constexpr std::uint32_t KMIP_TAG_KEY_COMPRESSION_TYPE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_KEY_COMPRESSION_TYPE);
  inline constexpr std::uint32_t KMIP_TAG_KEY_FORMAT_TYPE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_KEY_FORMAT_TYPE);
  inline constexpr std::uint32_t KMIP_TAG_KEY_MATERIAL =
      static_cast<std::uint32_t>(tag::KMIP_TAG_KEY_MATERIAL);
  inline constexpr std::uint32_t KMIP_TAG_KEY_VALUE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_KEY_VALUE);
  inline constexpr std::uint32_t KMIP_TAG_KEY_WRAPPING_DATA =
      static_cast<std::uint32_t>(tag::KMIP_TAG_KEY_WRAPPING_DATA);
  inline constexpr std::uint32_t KMIP_TAG_KEY_WRAPPING_SPECIFICATION =
      static_cast<std::uint32_t>(tag::KMIP_TAG_KEY_WRAPPING_SPECIFICATION);
  inline constexpr std::uint32_t KMIP_TAG_MAC_SIGNATURE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_MAC_SIGNATURE);
  inline constexpr std::uint32_t KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION =
      static_cast<std::uint32_t>(tag::KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION);
  inline constexpr std::uint32_t KMIP_TAG_MAXIMUM_ITEMS =
      static_cast<std::uint32_t>(tag::KMIP_TAG_MAXIMUM_ITEMS);
  inline constexpr std::uint32_t KMIP_TAG_MAXIMUM_RESPONSE_SIZE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_MAXIMUM_RESPONSE_SIZE);
  inline constexpr std::uint32_t KMIP_TAG_NAME =
      static_cast<std::uint32_t>(tag::KMIP_TAG_NAME);
  inline constexpr std::uint32_t KMIP_TAG_NAME_TYPE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_NAME_TYPE);
  inline constexpr std::uint32_t KMIP_TAG_NAME_VALUE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_NAME_VALUE);
  inline constexpr std::uint32_t KMIP_TAG_OBJECT_GROUP =
      static_cast<std::uint32_t>(tag::KMIP_TAG_OBJECT_GROUP);
  inline constexpr std::uint32_t KMIP_TAG_OBJECT_TYPE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_OBJECT_TYPE);
  inline constexpr std::uint32_t KMIP_TAG_OPERATION =
      static_cast<std::uint32_t>(tag::KMIP_TAG_OPERATION);
  inline constexpr std::uint32_t KMIP_TAG_OPERATION_POLICY_NAME =
      static_cast<std::uint32_t>(tag::KMIP_TAG_OPERATION_POLICY_NAME);
  inline constexpr std::uint32_t KMIP_TAG_PADDING_METHOD =
      static_cast<std::uint32_t>(tag::KMIP_TAG_PADDING_METHOD);
  inline constexpr std::uint32_t KMIP_TAG_PRIVATE_KEY =
      static_cast<std::uint32_t>(tag::KMIP_TAG_PRIVATE_KEY);
  inline constexpr std::uint32_t KMIP_TAG_PROCESS_START_DATE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_PROCESS_START_DATE);
  inline constexpr std::uint32_t KMIP_TAG_PROTECT_STOP_DATE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_PROTECT_STOP_DATE);
  inline constexpr std::uint32_t KMIP_TAG_PROTOCOL_VERSION =
      static_cast<std::uint32_t>(tag::KMIP_TAG_PROTOCOL_VERSION);
  inline constexpr std::uint32_t KMIP_TAG_PROTOCOL_VERSION_MAJOR =
      static_cast<std::uint32_t>(tag::KMIP_TAG_PROTOCOL_VERSION_MAJOR);
  inline constexpr std::uint32_t KMIP_TAG_PROTOCOL_VERSION_MINOR =
      static_cast<std::uint32_t>(tag::KMIP_TAG_PROTOCOL_VERSION_MINOR);
  inline constexpr std::uint32_t KMIP_TAG_PUBLIC_KEY =
      static_cast<std::uint32_t>(tag::KMIP_TAG_PUBLIC_KEY);
  inline constexpr std::uint32_t KMIP_TAG_QUERY_FUNCTION =
      static_cast<std::uint32_t>(tag::KMIP_TAG_QUERY_FUNCTION);
  inline constexpr std::uint32_t KMIP_TAG_REQUEST_HEADER =
      static_cast<std::uint32_t>(tag::KMIP_TAG_REQUEST_HEADER);
  inline constexpr std::uint32_t KMIP_TAG_REQUEST_MESSAGE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_REQUEST_MESSAGE);
  inline constexpr std::uint32_t KMIP_TAG_REQUEST_PAYLOAD =
      static_cast<std::uint32_t>(tag::KMIP_TAG_REQUEST_PAYLOAD);
  inline constexpr std::uint32_t KMIP_TAG_RESPONSE_HEADER =
      static_cast<std::uint32_t>(tag::KMIP_TAG_RESPONSE_HEADER);
  inline constexpr std::uint32_t KMIP_TAG_RESPONSE_MESSAGE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_RESPONSE_MESSAGE);
  inline constexpr std::uint32_t KMIP_TAG_RESPONSE_PAYLOAD =
      static_cast<std::uint32_t>(tag::KMIP_TAG_RESPONSE_PAYLOAD);
  inline constexpr std::uint32_t KMIP_TAG_RESULT_MESSAGE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_RESULT_MESSAGE);
  inline constexpr std::uint32_t KMIP_TAG_RESULT_REASON =
      static_cast<std::uint32_t>(tag::KMIP_TAG_RESULT_REASON);
  inline constexpr std::uint32_t KMIP_TAG_RESULT_STATUS =
      static_cast<std::uint32_t>(tag::KMIP_TAG_RESULT_STATUS);
  inline constexpr std::uint32_t KMIP_TAG_REVOKATION_MESSAGE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_REVOKATION_MESSAGE);
  inline constexpr std::uint32_t KMIP_TAG_REVOCATION_REASON =
      static_cast<std::uint32_t>(tag::KMIP_TAG_REVOCATION_REASON);
  inline constexpr std::uint32_t KMIP_TAG_REVOCATION_REASON_CODE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_REVOCATION_REASON_CODE);
  inline constexpr std::uint32_t KMIP_TAG_KEY_ROLE_TYPE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_KEY_ROLE_TYPE);
  inline constexpr std::uint32_t KMIP_TAG_SALT =
      static_cast<std::uint32_t>(tag::KMIP_TAG_SALT);
  inline constexpr std::uint32_t KMIP_TAG_SECRET_DATA =
      static_cast<std::uint32_t>(tag::KMIP_TAG_SECRET_DATA);
  inline constexpr std::uint32_t KMIP_TAG_SECRET_DATA_TYPE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_SECRET_DATA_TYPE);
  inline constexpr std::uint32_t KMIP_TAG_SERVER_INFORMATION =
      static_cast<std::uint32_t>(tag::KMIP_TAG_SERVER_INFORMATION);
  inline constexpr std::uint32_t KMIP_TAG_STATE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_STATE);
  inline constexpr std::uint32_t KMIP_TAG_STORAGE_STATUS_MASK =
      static_cast<std::uint32_t>(tag::KMIP_TAG_STORAGE_STATUS_MASK);
  inline constexpr std::uint32_t KMIP_TAG_SYMMETRIC_KEY =
      static_cast<std::uint32_t>(tag::KMIP_TAG_SYMMETRIC_KEY);
  inline constexpr std::uint32_t KMIP_TAG_TEMPLATE_ATTRIBUTE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_TEMPLATE_ATTRIBUTE);
  inline constexpr std::uint32_t KMIP_TAG_TIME_STAMP =
      static_cast<std::uint32_t>(tag::KMIP_TAG_TIME_STAMP);
  inline constexpr std::uint32_t KMIP_TAG_UNIQUE_BATCH_ITEM_ID =
      static_cast<std::uint32_t>(tag::KMIP_TAG_UNIQUE_BATCH_ITEM_ID);
  inline constexpr std::uint32_t KMIP_TAG_UNIQUE_IDENTIFIER =
      static_cast<std::uint32_t>(tag::KMIP_TAG_UNIQUE_IDENTIFIER);
  inline constexpr std::uint32_t KMIP_TAG_USERNAME =
      static_cast<std::uint32_t>(tag::KMIP_TAG_USERNAME);
  inline constexpr std::uint32_t KMIP_TAG_VENDOR_IDENTIFICATION =
      static_cast<std::uint32_t>(tag::KMIP_TAG_VENDOR_IDENTIFICATION);
  inline constexpr std::uint32_t KMIP_TAG_WRAPPING_METHOD =
      static_cast<std::uint32_t>(tag::KMIP_TAG_WRAPPING_METHOD);
  inline constexpr std::uint32_t KMIP_TAG_PASSWORD =
      static_cast<std::uint32_t>(tag::KMIP_TAG_PASSWORD);
  inline constexpr std::uint32_t KMIP_TAG_DEVICE_IDENTIFIER =
      static_cast<std::uint32_t>(tag::KMIP_TAG_DEVICE_IDENTIFIER);
  inline constexpr std::uint32_t KMIP_TAG_ENCODING_OPTION =
      static_cast<std::uint32_t>(tag::KMIP_TAG_ENCODING_OPTION);
  inline constexpr std::uint32_t KMIP_TAG_MACHINE_IDENTIFIER =
      static_cast<std::uint32_t>(tag::KMIP_TAG_MACHINE_IDENTIFIER);
  inline constexpr std::uint32_t KMIP_TAG_MEDIA_IDENTIFIER =
      static_cast<std::uint32_t>(tag::KMIP_TAG_MEDIA_IDENTIFIER);
  inline constexpr std::uint32_t KMIP_TAG_NETWORK_IDENTIFIER =
      static_cast<std::uint32_t>(tag::KMIP_TAG_NETWORK_IDENTIFIER);
  inline constexpr std::uint32_t KMIP_TAG_OBJECT_GROUP_MEMBER =
      static_cast<std::uint32_t>(tag::KMIP_TAG_OBJECT_GROUP_MEMBER);
  inline constexpr std::uint32_t KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM =
      static_cast<std::uint32_t>(tag::KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM);
  inline constexpr std::uint32_t KMIP_TAG_DEVICE_SERIAL_NUMBER =
      static_cast<std::uint32_t>(tag::KMIP_TAG_DEVICE_SERIAL_NUMBER);
  inline constexpr std::uint32_t KMIP_TAG_RANDOM_IV =
      static_cast<std::uint32_t>(tag::KMIP_TAG_RANDOM_IV);
  inline constexpr std::uint32_t KMIP_TAG_ATTESTATION_TYPE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_ATTESTATION_TYPE);
  inline constexpr std::uint32_t KMIP_TAG_NONCE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_NONCE);
  inline constexpr std::uint32_t KMIP_TAG_NONCE_ID =
      static_cast<std::uint32_t>(tag::KMIP_TAG_NONCE_ID);
  inline constexpr std::uint32_t KMIP_TAG_NONCE_VALUE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_NONCE_VALUE);
  inline constexpr std::uint32_t KMIP_TAG_ATTESTATION_MEASUREMENT =
      static_cast<std::uint32_t>(tag::KMIP_TAG_ATTESTATION_MEASUREMENT);
  inline constexpr std::uint32_t KMIP_TAG_ATTESTATION_ASSERTION =
      static_cast<std::uint32_t>(tag::KMIP_TAG_ATTESTATION_ASSERTION);
  inline constexpr std::uint32_t KMIP_TAG_IV_LENGTH =
      static_cast<std::uint32_t>(tag::KMIP_TAG_IV_LENGTH);
  inline constexpr std::uint32_t KMIP_TAG_TAG_LENGTH =
      static_cast<std::uint32_t>(tag::KMIP_TAG_TAG_LENGTH);
  inline constexpr std::uint32_t KMIP_TAG_FIXED_FIELD_LENGTH =
      static_cast<std::uint32_t>(tag::KMIP_TAG_FIXED_FIELD_LENGTH);
  inline constexpr std::uint32_t KMIP_TAG_COUNTER_LENGTH =
      static_cast<std::uint32_t>(tag::KMIP_TAG_COUNTER_LENGTH);
  inline constexpr std::uint32_t KMIP_TAG_INITIAL_COUNTER_VALUE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_INITIAL_COUNTER_VALUE);
  inline constexpr std::uint32_t KMIP_TAG_INVOCATION_FIELD_LENGTH =
      static_cast<std::uint32_t>(tag::KMIP_TAG_INVOCATION_FIELD_LENGTH);
  inline constexpr std::uint32_t KMIP_TAG_ATTESTATION_CAPABLE_INDICATOR =
      static_cast<std::uint32_t>(tag::KMIP_TAG_ATTESTATION_CAPABLE_INDICATOR);
  inline constexpr std::uint32_t KMIP_TAG_OFFSET_ITEMS =
      static_cast<std::uint32_t>(tag::KMIP_TAG_OFFSET_ITEMS);
  inline constexpr std::uint32_t KMIP_TAG_LOCATED_ITEMS =
      static_cast<std::uint32_t>(tag::KMIP_TAG_LOCATED_ITEMS);
  inline constexpr std::uint32_t KMIP_TAG_KEY_WRAP_TYPE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_KEY_WRAP_TYPE);
  inline constexpr std::uint32_t KMIP_TAG_SALT_LENGTH =
      static_cast<std::uint32_t>(tag::KMIP_TAG_SALT_LENGTH);
  inline constexpr std::uint32_t KMIP_TAG_MASK_GENERATOR =
      static_cast<std::uint32_t>(tag::KMIP_TAG_MASK_GENERATOR);
  inline constexpr std::uint32_t KMIP_TAG_MASK_GENERATOR_HASHING_ALGORITHM =
      static_cast<std::uint32_t>(
          tag::KMIP_TAG_MASK_GENERATOR_HASHING_ALGORITHM
      );
  inline constexpr std::uint32_t KMIP_TAG_P_SOURCE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_P_SOURCE);
  inline constexpr std::uint32_t KMIP_TAG_TRAILER_FIELD =
      static_cast<std::uint32_t>(tag::KMIP_TAG_TRAILER_FIELD);
  inline constexpr std::uint32_t KMIP_TAG_CLIENT_CORRELATION_VALUE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_CLIENT_CORRELATION_VALUE);
  inline constexpr std::uint32_t KMIP_TAG_SERVER_CORRELATION_VALUE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_SERVER_CORRELATION_VALUE);
  inline constexpr std::uint32_t KMIP_TAG_ATTRIBUTES =
      static_cast<std::uint32_t>(tag::KMIP_TAG_ATTRIBUTES);
  inline constexpr std::uint32_t KMIP_TAG_SERVER_NAME =
      static_cast<std::uint32_t>(tag::KMIP_TAG_SERVER_NAME);
  inline constexpr std::uint32_t KMIP_TAG_SERVER_SERIAL_NUMBER =
      static_cast<std::uint32_t>(tag::KMIP_TAG_SERVER_SERIAL_NUMBER);
  inline constexpr std::uint32_t KMIP_TAG_SERVER_VERSION =
      static_cast<std::uint32_t>(tag::KMIP_TAG_SERVER_VERSION);
  inline constexpr std::uint32_t KMIP_TAG_SERVER_LOAD =
      static_cast<std::uint32_t>(tag::KMIP_TAG_SERVER_LOAD);
  inline constexpr std::uint32_t KMIP_TAG_PRODUCT_NAME =
      static_cast<std::uint32_t>(tag::KMIP_TAG_PRODUCT_NAME);
  inline constexpr std::uint32_t KMIP_TAG_BUILD_LEVEL =
      static_cast<std::uint32_t>(tag::KMIP_TAG_BUILD_LEVEL);
  inline constexpr std::uint32_t KMIP_TAG_BUILD_DATE =
      static_cast<std::uint32_t>(tag::KMIP_TAG_BUILD_DATE);
  inline constexpr std::uint32_t KMIP_TAG_CLUSTER_INFO =
      static_cast<std::uint32_t>(tag::KMIP_TAG_CLUSTER_INFO);
  inline constexpr std::uint32_t KMIP_TAG_ALTERNATE_FAILOVER_ENDPOINTS =
      static_cast<std::uint32_t>(tag::KMIP_TAG_ALTERNATE_FAILOVER_ENDPOINTS);
  inline constexpr std::uint32_t KMIP_TAG_EPHEMERAL =
      static_cast<std::uint32_t>(tag::KMIP_TAG_EPHEMERAL);
  inline constexpr std::uint32_t KMIP_TAG_SERVER_HASHED_PASSWORD =
      static_cast<std::uint32_t>(tag::KMIP_TAG_SERVER_HASHED_PASSWORD);
  inline constexpr std::uint32_t KMIP_TAG_PROTECTION_STORAGE_MASK =
      static_cast<std::uint32_t>(tag::KMIP_TAG_PROTECTION_STORAGE_MASK);
  inline constexpr std::uint32_t KMIP_TAG_PROTECTION_STORAGE_MASKS =
      static_cast<std::uint32_t>(tag::KMIP_TAG_PROTECTION_STORAGE_MASKS);
  inline constexpr std::uint32_t KMIP_TAG_COMMON_PROTECTION_STORAGE_MASKS =
      static_cast<std::uint32_t>(tag::KMIP_TAG_COMMON_PROTECTION_STORAGE_MASKS);
  inline constexpr std::uint32_t KMIP_TAG_PRIVATE_PROTECTION_STORAGE_MASKS =
      static_cast<std::uint32_t>(
          tag::KMIP_TAG_PRIVATE_PROTECTION_STORAGE_MASKS
      );
  inline constexpr std::uint32_t KMIP_TAG_PUBLIC_PROTECTION_STORAGE_MASKS =
      static_cast<std::uint32_t>(tag::KMIP_TAG_PUBLIC_PROTECTION_STORAGE_MASKS);
  inline constexpr std::uint32_t KMIP_TYPE_STRUCTURE =
      static_cast<std::uint32_t>(type::KMIP_TYPE_STRUCTURE);
  inline constexpr std::uint32_t KMIP_TYPE_INTEGER =
      static_cast<std::uint32_t>(type::KMIP_TYPE_INTEGER);
  inline constexpr std::uint32_t KMIP_TYPE_LONG_INTEGER =
      static_cast<std::uint32_t>(type::KMIP_TYPE_LONG_INTEGER);
  inline constexpr std::uint32_t KMIP_TYPE_BIG_INTEGER =
      static_cast<std::uint32_t>(type::KMIP_TYPE_BIG_INTEGER);
  inline constexpr std::uint32_t KMIP_TYPE_ENUMERATION =
      static_cast<std::uint32_t>(type::KMIP_TYPE_ENUMERATION);
  inline constexpr std::uint32_t KMIP_TYPE_BOOLEAN =
      static_cast<std::uint32_t>(type::KMIP_TYPE_BOOLEAN);
  inline constexpr std::uint32_t KMIP_TYPE_TEXT_STRING =
      static_cast<std::uint32_t>(type::KMIP_TYPE_TEXT_STRING);
  inline constexpr std::uint32_t KMIP_TYPE_BYTE_STRING =
      static_cast<std::uint32_t>(type::KMIP_TYPE_BYTE_STRING);
  inline constexpr std::uint32_t KMIP_TYPE_DATE_TIME =
      static_cast<std::uint32_t>(type::KMIP_TYPE_DATE_TIME);
  inline constexpr std::uint32_t KMIP_TYPE_INTERVAL =
      static_cast<std::uint32_t>(type::KMIP_TYPE_INTERVAL);
  inline constexpr std::uint32_t KMIP_TYPE_DATE_TIME_EXTENDED =
      static_cast<std::uint32_t>(type::KMIP_TYPE_DATE_TIME_EXTENDED);
  inline constexpr std::uint32_t KMIP_WRAP_ENCRYPT =
      static_cast<std::uint32_t>(wrapping_method::KMIP_WRAP_ENCRYPT);
  inline constexpr std::uint32_t KMIP_WRAP_MAC_SIGN =
      static_cast<std::uint32_t>(wrapping_method::KMIP_WRAP_MAC_SIGN);
  inline constexpr std::uint32_t KMIP_WRAP_ENCRYPT_MAC_SIGN =
      static_cast<std::uint32_t>(wrapping_method::KMIP_WRAP_ENCRYPT_MAC_SIGN);
  inline constexpr std::uint32_t KMIP_WRAP_MAC_SIGN_ENCRYPT =
      static_cast<std::uint32_t>(wrapping_method::KMIP_WRAP_MAC_SIGN_ENCRYPT);
  inline constexpr std::uint32_t KMIP_WRAP_TR31 =
      static_cast<std::uint32_t>(wrapping_method::KMIP_WRAP_TR31);
  inline constexpr std::uint32_t KMIP_REVOKE_UNSPECIFIED =
      static_cast<std::uint32_t>(
          revocation_reason_type::KMIP_REVOKE_UNSPECIFIED
      );
  inline constexpr std::uint32_t KMIP_REVOKE_KEY_COMPROMISE =
      static_cast<std::uint32_t>(
          revocation_reason_type::KMIP_REVOKE_KEY_COMPROMISE
      );
  inline constexpr std::uint32_t KMIP_REVOKE_CA_COMPROMISE =
      static_cast<std::uint32_t>(
          revocation_reason_type::KMIP_REVOKE_CA_COMPROMISE
      );
  inline constexpr std::uint32_t KMIP_REVOKE_AFFILIATION_CHANGED =
      static_cast<std::uint32_t>(
          revocation_reason_type::KMIP_REVOKE_AFFILIATION_CHANGED
      );
  inline constexpr std::uint32_t KMIP_REVOKE_SUSPENDED =
      static_cast<std::uint32_t>(revocation_reason_type::KMIP_REVOKE_SUSPENDED);
  inline constexpr std::uint32_t KMIP_REVOKE_CESSATION_OF_OPERATION =
      static_cast<std::uint32_t>(
          revocation_reason_type::KMIP_REVOKE_CESSATION_OF_OPERATION
      );
  inline constexpr std::uint32_t KMIP_REVOKE_PRIVILEDGE_WITHDRAWN =
      static_cast<std::uint32_t>(
          revocation_reason_type::KMIP_REVOKE_PRIVILEDGE_WITHDRAWN
      );
  inline constexpr std::uint32_t KMIP_REVOKE_EXTENSIONS =
      static_cast<std::uint32_t>(
          revocation_reason_type::KMIP_REVOKE_EXTENSIONS
      );
  inline constexpr std::uint32_t KMIP_SECDATA_PASSWORD =
      static_cast<std::uint32_t>(secret_data_type::KMIP_SECDATA_PASSWORD);
  inline constexpr std::uint32_t KMIP_SECDATA_SEED =
      static_cast<std::uint32_t>(secret_data_type::KMIP_SECDATA_SEED);
  inline constexpr std::uint32_t KMIP_SECDATA_EXTENSIONS =
      static_cast<std::uint32_t>(secret_data_type::KMIP_SECDATA_EXTENSIONS);

}  // namespace kmipcore

#endif  // KMIPCORE_KMIP_ENUMS_HPP
