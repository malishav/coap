# constants from draft-ietf-ace-oauth-authz-13

# Figure 12 draft-ietf-ace-oauth-authz-13: CBOR mappings used in token requests
ACE_PARAMETERS_LABELS_AUD = 3  # text string
ACE_PARAMETERS_LABELS_CLIENT_ID = 8  # text string
ACE_PARAMETERS_LABELS_CLIENT_SECRET = 9  # byte string
ACE_PARAMETERS_LABELS_RESPONSE_TYPE = 10  # text string
ACE_PARAMETERS_LABELS_REDIRECT_URI = 11  # text string
ACE_PARAMETERS_LABELS_SCOPE = 12  # text or byte string
ACE_PARAMETERS_LABELS_STATE = 13  # text string
ACE_PARAMETERS_LABELS_CODE = 14  # byte string
ACE_PARAMETERS_LABELS_ERROR = 15  # unsigned integer
ACE_PARAMETERS_LABELS_ERROR_DESCRIPTION = 16  # text string
ACE_PARAMETERS_LABELS_ERROR_URI = 17  # text string
ACE_PARAMETERS_LABELS_GRANT_TYPE = 18  # unsigned integer
ACE_PARAMETERS_LABELS_ACCESS_TOKEN = 19  # byte string
ACE_PARAMETERS_LABELS_TOKEN_TYPE = 20  # unsigned integer
ACE_PARAMETERS_LABELS_EXPIRES_IN = 21  # unsigned integer
ACE_PARAMETERS_LABELS_USERNAME = 22  # text string
ACE_PARAMETERS_LABELS_PASSWORD = 23  # text string
ACE_PARAMETERS_LABELS_REFRESH_TOKEN = 24  # byte string
ACE_PARAMETERS_LABELS_CNF = 25  # map
ACE_PARAMETERS_LABELS_PROFILE = 26  # unsigned integer
ACE_PARAMETERS_LABELS_RS_CNF = 31  # map

#  Figure 11 from draft-ietf-ace-oauth-authz-13: CBOR abbreviations for common grant types
ACE_CBOR_ABBREVIATIONS_PASSWORD = 0
ACE_CBOR_ABBREVIATIONS_AUTHORIZATION_CODE = 1
ACE_CBOR_ABBREVIATIONS_CLIENT_CREDENTIALS = 2
ACE_CBOR_ABBREVIATIONS_REFRESH_TOKEN = 3

ACE_ACCESS_TOKEN_TYPE_BEARER = 1
ACE_ACCESS_TOKEN_TYPE_POP = 2

# from https://tools.ietf.org/html/draft-ietf-ace-cwt-proof-of-possession-03#section-3.1
ACE_CWT_CNF_COSE_KEY = 1
ACE_CWT_CNF_ENCRYPTED_COSE_KEY = 2
ACE_CWT_CNF_KID = 3

#  Figure 2 from draft-ietf-ace-oauth-authz-13:
ACE_AS_INFO_LABEL_AS = 0
ACE_AS_INFO_LABEL_NONCE = 5

# values from RFC8152

# COSE key labels
COSE_KEY_LABEL_KTY                          = 1
COSE_KEY_LABEL_KID                          = 2
COSE_KEY_LABEL_ALG                          = 3
COSE_KEY_LABEL_KEYOPS                       = 4
COSE_KEY_LABEL_BASEIV                       = 5
COSE_KEY_LABEL_K                            = -1
COSE_KEY_LABEL_CLIENT_ID                    = 6      # value TBD by IANA, registered in draft-ietf-ace-oscore-profile-02
COSE_KEY_LABEL_SERVER_ID                    = 7      # value TBD by IANA, registered in draft-ietf-ace-oscore-profile-02
COSE_KEY_LABEL_KDF                          = 8      # value TBD by IANA, registered in draft-ietf-ace-oscore-profile-02
COSE_KEY_LABEL_SLT                          = 9      # value TBD by IANA, registered in draft-ietf-ace-oscore-profile-02
COSE_KEY_LABEL_ALL = [
    COSE_KEY_LABEL_KTY,
    COSE_KEY_LABEL_KID,
    COSE_KEY_LABEL_ALG,
    COSE_KEY_LABEL_KEYOPS,
    COSE_KEY_LABEL_BASEIV,
    COSE_KEY_LABEL_K,
    COSE_KEY_LABEL_CLIENT_ID,
    COSE_KEY_LABEL_SERVER_ID,
    COSE_KEY_LABEL_KDF,
    COSE_KEY_LABEL_SLT,
]

# COSE key values
COSE_KEY_VALUE_OKP                          = 1
COSE_KEY_VALUE_EC2                          = 2
COSE_KEY_VALUE_SYMMETRIC                    = 4
COSE_KEY_VALUE_ALL = [
    COSE_KEY_VALUE_OKP,
    COSE_KEY_VALUE_EC2,
    COSE_KEY_VALUE_SYMMETRIC,
]

COSE_ALG_AES_CCM_16_64_128                  = 10
COSE_ALG_AES_CCM_16_64_256                  = 11
COSE_ALG_AES_CCM_64_64_128                  = 12
COSE_ALG_AES_CCM_64_64_256                  = 13
COSE_ALG_AES_CCM_16_128_128                 = 30
COSE_ALG_AES_CCM_16_128_256                 = 31
COSE_ALG_AES_CCM_64_128_128                 = 32
COSE_ALG_AES_CCM_64_128_256                 = 33

COSE_ALG_AES_CCM_ALL = [
    COSE_ALG_AES_CCM_16_64_128,
    COSE_ALG_AES_CCM_16_64_256,
    COSE_ALG_AES_CCM_64_64_128,
    COSE_ALG_AES_CCM_64_64_256,
    COSE_ALG_AES_CCM_16_128_128,
    COSE_ALG_AES_CCM_16_128_256,
    COSE_ALG_AES_CCM_64_128_128,
    COSE_ALG_AES_CCM_64_128_256,
]

COSE_COMMON_HEADER_PARAMETERS_ALG                = 1
COSE_COMMON_HEADER_PARAMETERS_CRIT               = 2
COSE_COMMON_HEADER_PARAMETERS_CONTENT_TYPE       = 3
COSE_COMMON_HEADER_PARAMETERS_KID                = 4
COSE_COMMON_HEADER_PARAMETERS_IV                 = 5
COSE_COMMON_HEADER_PARAMETERS_PIV                = 6
COSE_COMMON_HEADER_PARAMETERS_COUNTER_SIGNATURE  = 7

COSE_COMMON_HEADER_PARAMETERS_ALL = [
    COSE_COMMON_HEADER_PARAMETERS_ALG,
    COSE_COMMON_HEADER_PARAMETERS_CRIT,
    COSE_COMMON_HEADER_PARAMETERS_CONTENT_TYPE,
    COSE_COMMON_HEADER_PARAMETERS_KID,
    COSE_COMMON_HEADER_PARAMETERS_IV,
    COSE_COMMON_HEADER_PARAMETERS_PIV,
    COSE_COMMON_HEADER_PARAMETERS_COUNTER_SIGNATURE,
]
