import os
import sys
here = sys.path[0]
sys.path.insert(0, os.path.join(here,'..'))

import time
import binascii
import cbor

from coap import coap
from coap import coapOption           as o
from coap import coapObjectSecurity   as oscoap
from coap import coapDefines          as d
from coap import coapUtils            as u
from coap import coapException        as e

import constants

import logging_setup

RS_IP = 'bbbb::1415:92cc:0:2'
SCOPE = 'resource1'
AUTHZ_INFO = 'authz-info'

# open
c = coap.coap(udpPort=5000)

context = oscoap.SecurityContext(masterSecret=binascii.unhexlify('000102030405060708090A0B0C0D0E0F'),
                                 senderID=binascii.unhexlify('636c69656e74'),
                                 recipientID='JRC',
                                 aeadAlgorithm=oscoap.AES_CCM_16_64_128())

objectSecurity = o.ObjectSecurity(context=context)

contentFormat = o.ContentFormat(cformat=[d.FORMAT_CBOR])

try:
    # Step 0. Request resource without OSCORE
    (respCode, respOptions, respPayload) = c.GET('coap://[{0}]/{1}'.format(RS_IP, SCOPE),
                                                  confirmable=True,
                                                  options=[],
                                                  )

    print '===== GET to coap://[{0}]/{1} returned ====='.format(RS_IP, SCOPE)
    print binascii.hexlify(cbor.dumps(respPayload))
    print '====='

except e.coapRcUnauthorized as err:

    print "Unauthorized exception handling."
    as_info = cbor.loads(err.reason)

    print '====== Response payload ======'
    print as_info
    print '====='

    as_uri = str(as_info[constants.ACE_AS_INFO_LABEL_AS])
    print as_uri

    # Step 1: Request authorization from the AS to access "resource1"
    request_payload = {}
    request_payload[constants.ACE_PARAMETERS_LABELS_GRANT_TYPE] = constants.ACE_CBOR_ABBREVIATIONS_CLIENT_CREDENTIALS
    request_payload[constants.ACE_PARAMETERS_LABELS_AUD] = unicode(RS_IP)
    request_payload[constants.ACE_PARAMETERS_LABELS_SCOPE] = unicode(SCOPE)

    print '====== Request payload ======'
    print binascii.hexlify(cbor.dumps(request_payload))
    print '====='

    # obtain an access token
    (respCode, respOptions, respPayload) = c.POST(as_uri,
                                                  confirmable=True,
                                                  options=[contentFormat, objectSecurity],
                                                  payload=u.str2buf(cbor.dumps(request_payload))
                                                  )

    payload_hex = u.buf2str(respPayload)
    print '====== Response payload ======'
    print binascii.hexlify(payload_hex)
    print '====='

    # Step 2: Decode the response, install the OSCORE security context and parse the access token for the RS
    as_response = cbor.loads(payload_hex)

    cnf = as_response[constants.ACE_PARAMETERS_LABELS_CNF]

    cose_key = cnf[constants.ACE_CWT_CNF_COSE_KEY]

    if cose_key[constants.COSE_KEY_LABEL_KTY] != constants.COSE_KEY_VALUE_SYMMETRIC:
        raise NotImplementedError

    if cose_key.get(constants.COSE_KEY_LABEL_ALG,
                    constants.COSE_ALG_AES_CCM_16_64_128) != constants.COSE_ALG_AES_CCM_16_64_128:
        raise NotImplementedError
    else:
        aeadAlgo = oscoap.AES_CCM_16_64_128()

    context_c_rs = oscoap.SecurityContext(
        masterSecret=cose_key.get(constants.COSE_KEY_LABEL_K),
        senderID=cose_key.get(constants.COSE_KEY_LABEL_CLIENT_ID),
        recipientID=cose_key.get(constants.COSE_KEY_LABEL_SERVER_ID),
        masterSalt=cose_key.get(constants.COSE_KEY_LABEL_SLT, ""),
        aeadAlgorithm=aeadAlgo,
    )

    access_token = as_response[constants.ACE_PARAMETERS_LABELS_ACCESS_TOKEN]

    audience = as_response.get(constants.ACE_PARAMETERS_LABELS_AUD,
                               "coap://[{0}]".format(RS_IP))  # if audience is not given, default to the RS we contacted in the first place

    # Step 3: POST the access token to the RS over unprotected channel
    (respCode, respOptions, respPayload) = c.POST('{0}/{1}'.format(audience, AUTHZ_INFO),
                                                  confirmable=True,
                                                  options=[],
                                                  payload=u.str2buf(access_token)
                                                  )

    if respCode != d.COAP_RC_2_01_CREATED:
        raise NotImplementedError


    try:
        # Step 4: Request the resource over OSCORE
        oscore = o.ObjectSecurity(context=context_c_rs)
        (respCode, respOptions, respPayload) = c.GET('{0}/{1}'.format(audience, SCOPE),
                                                     confirmable=True,
                                                     options=[
                                                         oscore
                                                     ],
                                                     )

        print '===== GET to {0}/{1} returned ====='.format(audience, SCOPE)
        print ''.join([chr(b) for b in respPayload])
        print '====='

    except Exception as err:
        print err

# this includes CoAP errors
except Exception as err:
    print err


# close
c.close()

time.sleep(0.500)

raw_input("Done. Press enter to close.")
