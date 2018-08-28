# --
# File: threatstream_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2016-2018
#
# This unpublished material is proprietary to Phantom Cyber Corporation.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

THREATSTREAM_JSON_USERNAME = "username"
THREATSTREAM_JSON_API_KEY = "api_key"
THREATSTREAM_JSON_HASH = "hash"
THREATSTREAM_JSON_DOMAIN = "domain"
THREATSTREAM_JSON_IP = "ip"
THREATSTREAM_JSON_EMAIL = "email"
# THREATSTREAM_JSON_IOC_VALUE = "ioc_value"
# THREATSTREAM_JSON_IOC_TYPE = "ioc_type"

ENDPOINT_INTELLIGENCE = "/v2/intelligence/"
ENDPOINT_PDNS = "/v1/pdns/{ioc_type}/{ioc_value}/"
ENDPOINT_INISGHT = "/v1/inteldetails/insights/"
ENDPOINT_REFERENCE = "/v1/inteldetails/references/{ioc_value}/"
ENDPOINT_CONFIDENCE = "/v1/inteldetails/confidence_trend/"
ENDPOINT_WHOIS = "/v1/inteldetails/whois/{ioc_value}/"
ENDPOINT_INCIDENT = "/v1/incident/"
ENDPOINT_INCIDENT_WITH_VALUE = "/v1/incident/associated_with_intelligence/"
ENDPOINT_SINGLE_INCIDENT = "/v1/incident/{inc_id}/"
ENDPOINT_IMPORT_IOC = "/v1/intelligence/"
ENDPOINT_FILE_DETONATION = "/v1/submit/new/"
ENDPOINT_URL_DETONATION = "/v1/submit/new/"

THREATSTREAM_ERR_INVALID_TYPE = "Invalid IOC Type"
THREATSTREAM_ERR_INVALID_VALUE = "Invalid IOC Value. Don't include the http:// or any paths"
THREATSTREAM_ERR_PARSE_REPLY = "Unable to parse whois response"

WHOIS_NO_DATA = "No Whois Data Available"
