# --
# File: threatstream_connector.py
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

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Local imports
from threatstream_consts import *

import requests
import datetime
import pythonwhois
import simplejson as json

# These are the fields outputted in the widget
# Check to see if all of these are in the the
#  the json
# Note that all of these should be in the "admin"
#  field
whois_fields = [ "city",
                 "country",
                 "email",
                 "name",
                 "organization" ]


def _json_fallback(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return obj


class ThreatstreamConnector(BaseConnector):

    ACTION_ID_WHOIS_IP = "whois_ip"
    ACTION_ID_WHOIS_DOMAIN = "whois_domain"
    ACTION_ID_EMAIL_REPUTATION = "email_reputation"
    ACTION_ID_IP_REPUTATION = "ip_reputation"
    ACTION_ID_DOMAIN_REPUTATION = "domain_reputation"
    ACTION_ID_FILE_REPUTATION = "file_reputation"

    def __init__(self):

        super(ThreatstreamConnector, self).__init__()
        self._data_dict = {}  # Blank dict to contain data from all API calls
        return

    def _make_rest_call(self, result, endpoint, payload):

        base_url = "https://optic.threatstream.com/api"

        try:
            r = requests.get(base_url + endpoint, params=payload)
        except Exception as e:
            return (result.set_status(phantom.APP_ERROR, "Connection failed", e), None)

        if (not (200 <= r.status_code <= 399)):
            msg = "Call failed with status code: {} {}".format(r.status_code, r.reason)
            return (result.set_status(phantom.APP_ERROR, msg), None)

        try:
            resp_json = r.json()
        except Exception as e:
            msg = "Error parsing string {} to json".format(r.text)
            return (result.set_status(phantom.APP_ERROR, msg, e), None)

        return (phantom.APP_SUCCESS, resp_json)

    def _generate_payload(self, **kwargs):
        """Create dict with username and password URL parameters
           Can also add in any further URL parameters
        """
        payload = {}
        config = self.get_config()
        payload['username'] = config[THREATSTREAM_JSON_USERNAME]
        payload['api_key'] = config[THREATSTREAM_JSON_API_KEY]
        for k, v in kwargs.iteritems():
            payload[k] = v
        return payload

    def _intel_details(self, value, action_result):
        """ Use the intelligence endpoint to get general details """
        payload = self._generate_payload(extend_source="true", limit="25", offset="0",
                                         order_by="-created_ts", value=value)

        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INTELLIGENCE, payload)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # action_result.add_data({'intel_details': resp_json['objects']})
        # self._data_dict['intel_details'] = resp_json['objects']
        for detail in resp_json['objects']:
            action_result.add_data(detail)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved intel details")

    def _pdns(self, value, ioc_type, action_result):

        # Validate input
        if ioc_type not in [ "ip", "domain" ]:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_TYPE)

        payload = self._generate_payload(order_by="-last_seen")
        pdns = ENDPOINT_PDNS.format(ioc_type=ioc_type, ioc_value=value)

        ret_val, resp_json = self._make_rest_call(action_result, pdns, payload)
        if (phantom.is_fail(ret_val) or not resp_json["success"]):
            return action_result.get_status()

        # action_result.add_data({'pdns': resp_json['results']})
        # self._data_dict['pdns'] = resp_json['results']
        action_result.add_extra_data({'pdns': resp_json['results']})
        return action_result.set_status(phantom.APP_SUCCESS, "Retrieved")

    def _insight(self, value, ioc_type, action_result):

        # Validate input
        if ioc_type not in [ "ip", "domain", "email", "md5" ]:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_TYPE)

        payload = self._generate_payload(type=ioc_type, value=value)

        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INISGHT, payload)
        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Error retrieving insights")

        # action_result.add_data({'insights': resp_json['insights']})
        # self._data_dict['insights'] = resp_json['insights']
        action_result.add_extra_data({'insights': resp_json['insights']})
        return action_result.set_status(phantom.APP_SUCCESS, "Retrieved")

    def _external_references(self, value, action_result):

        payload = self._generate_payload()
        ext_ref = ENDPOINT_REFERENCE.format(ioc_value=value)

        ret_val, resp_json = self._make_rest_call(action_result, ext_ref, payload)
        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_SUCCESS, "Error retrieving external references")

        # action_result.add_data({'external_references': resp_json})
        # self._data_dict['external_references'] = resp_json
        action_result.add_extra_data({'external_references': resp_json})
        return action_result.set_status(phantom.APP_SUCCESS, "Retrieved")

    def _whois(self, value, action_result, tipe=""):
        payload = self._generate_payload()
        whois = ENDPOINT_WHOIS.format(ioc_value=value)

        ret_val, resp_json = self._make_rest_call(action_result, whois, payload)
        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_SUCCESS, "Error making whois request")

        if (resp_json['data'] == WHOIS_NO_DATA):
            return action_result.set_status(phantom.APP_ERROR, WHOIS_NO_DATA)

        whois_response = pythonwhois.parse.parse_raw_whois([resp_json['data']], True)
        try:
            # Need to work on the json, it contains certain fields that are not
            # parsable, so will need to go the 'fallback' way.
            # TODO: Find a better way to do this
            whois_response = json.dumps(whois_response, default=_json_fallback)
            whois_response = json.loads(whois_response)
            action_result.add_data(whois_response)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_PARSE_REPLY, e)

        if 'admin' in whois_response:
            if all(key in whois_response['admin'] for key in whois_fields):
                return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved whois info")
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved whois info but unable to parse all required fields")

    def _retrieve_ip_domain(self, value, ioc_type, action_result):
        """ Retrieve all the information needed for domains or IPs """
        ret_val = self._intel_details(value, action_result)
        if (not ret_val):
            return action_result.get_status()

        ret_val = self._pdns(value, ioc_type, action_result)
        if (not ret_val):
            return action_result.get_status()

        ret_val = self._insight(value, ioc_type, action_result)
        if (not ret_val):
            return action_result.get_status()

        ret_val = self._external_references(value, action_result)
        if (not ret_val):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _retrieve_email_md5(self, value, ioc_type, action_result):
        """ Retrieve all the information needed for email or md5 hashes """
        ret_val = self._intel_details(value, action_result)
        if (not ret_val):
            return action_result.get_status()

        ret_val = self._insight(value, ioc_type, action_result)
        if (not ret_val):
            return action_result.get_status()

        ret_val = self._external_references(value, action_result)
        if (not ret_val):
            return action_result.get_status()

        return phantom.APP_SUCCESS

    def _test_connectivity(self, param):
        """ Test connectivity to threatstream by doing a simple request """
        action_result = ActionResult()

        self.save_progress("Starting connectivity test")
        payload = self._generate_payload(limit="1")
        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INTELLIGENCE, payload)
        if (phantom.is_fail(ret_val)):
            return self.set_status_save_progress(phantom.APP_ERROR, "Connectivity test failed")
        return self.set_status_save_progress(phantom.APP_SUCCESS, "Connectivity test passed")

    def _file_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = param[THREATSTREAM_JSON_HASH]
        ioc_type = "md5"
        ret_val = self._retrieve_email_md5(value, ioc_type, action_result)
        if (not ret_val):
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved information on File")

    def _domain_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = param[THREATSTREAM_JSON_DOMAIN]
        if "/" in value:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_VALUE)
        ioc_type = "domain"
        ret_val = self._retrieve_ip_domain(value, ioc_type, action_result)
        if (not ret_val):
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved information on Domain")

    def _ip_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = param[THREATSTREAM_JSON_IP]
        ioc_type = "ip"
        ret_val = self._retrieve_ip_domain(value, ioc_type, action_result)
        if (not ret_val):
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved information on IP")

    def _email_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = param[THREATSTREAM_JSON_EMAIL]
        ioc_type = "email"
        ret_val = self._retrieve_email_md5(value, ioc_type, action_result)
        if (not ret_val):
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved information on Email")

    def _whois_domain(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = param[THREATSTREAM_JSON_DOMAIN]
        ret_val = self._whois(value, action_result, tipe="domain")
        if (not ret_val):
            return action_result.get_status()
        return action_result.get_status()

    def _whois_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = param[THREATSTREAM_JSON_IP]
        ret_val = self._whois(value, action_result, tipe="ip")
        if (not ret_val):
            return action_result.get_status()
        return action_result.get_status()

    def handle_action(self, param):

        action = self.get_action_identifier()
        ret_val = phantom.APP_SUCCESS

        if (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            ret_val = self._test_connectivity(param)
        elif (action == self.ACTION_ID_FILE_REPUTATION):
            ret_val = self._file_reputation(param)
        elif (action == self.ACTION_ID_DOMAIN_REPUTATION):
            ret_val = self._domain_reputation(param)
        elif (action == self.ACTION_ID_IP_REPUTATION):
            ret_val = self._ip_reputation(param)
        elif (action == self.ACTION_ID_EMAIL_REPUTATION):
            ret_val = self._email_reputation(param)
        elif (action == self.ACTION_ID_WHOIS_DOMAIN):
            ret_val = self._whois_domain(param)
        elif (action == self.ACTION_ID_WHOIS_IP):
            ret_val = self._whois_ip(param)

        return ret_val

if __name__ == '__main__':
    """ Code that is executed when run in standalone debug mode
    for .e.g:
    python2.7 ./my_connector.py /tmp/my_input_test.json
        """

    # Imports
    import sys
    import pudb

    # Breakpoint at runtime
    pudb.set_trace()

    # The first param is the input json file
    with open(sys.argv[1]) as f:

        # Load the input json file
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        # Create the connector class object
        connector = ThreatstreamConnector()

        # Se the member vars
        connector.print_progress_message = True

        # Call BaseConnector::_handle_action(...) to kickoff action handling.
        ret_val = connector._handle_action(json.dumps(in_json), None)

        # Dump the return value
        print ret_val

    exit(0)
