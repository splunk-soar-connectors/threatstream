# File: threatstream_connector.py
#
# Copyright (c) 2016-2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import phantom.rules as phrules

# Local imports
from threatstream_consts import *

import ast
import os
import uuid
import shutil
import requests
import datetime
import ipaddress
import pythonwhois
import dateutil.parser
import pytz
import re
import sys
from ipwhois import IPWhois
import simplejson as json
from bs4 import BeautifulSoup
from bs4 import UnicodeDammit

try:
    from urlparse import urlsplit
except:
    from urllib.parse import urlsplit

# These are the fields outputted in the widget
# Check to see if all of these are in the the
#  the json
# Note that all of these should be in the "admin"
#  field
whois_fields = ["city",
                "country",
                "email",
                "name",
                "organization"]


def _json_fallback(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return obj


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class ThreatstreamConnector(BaseConnector):

    ACTION_ID_WHOIS_IP = "whois_ip"
    ACTION_ID_WHOIS_DOMAIN = "whois_domain"
    ACTION_ID_EMAIL_REPUTATION = "email_reputation"
    ACTION_ID_IP_REPUTATION = "ip_reputation"
    ACTION_ID_DOMAIN_REPUTATION = "domain_reputation"
    ACTION_ID_URL_REPUTATION = "url_reputation"
    ACTION_ID_FILE_REPUTATION = "file_reputation"
    ACTION_ID_LIST_INCIDENTS = "list_incidents"
    ACTION_ID_LIST_VULNERABILITY = "list_vulnerabilities"
    ACTION_ID_LIST_OBSERVABLE = "list_observables"
    ACTION_ID_GET_INCIDENT = "get_incident"
    ACTION_ID_GET_OBSERVABLE = "get_observable"
    ACTION_ID_GET_VULNERABILITY = "get_vulnerability"
    ACTION_ID_DELETE_INCIDENT = "delete_incident"
    ACTION_ID_CREATE_INCIDENT = "create_incident"
    ACTION_ID_UPDATE_INCIDENT = "update_incident"
    ACTION_ID_IMPORT_IOC = "import_observables"
    ACTION_ID_IMPORT_EMAIL_OBSERVABLES = "import_email_observable"
    ACTION_ID_IMPORT_FILE_OBSERVABLES = "import_file_observable"
    ACTION_ID_IMPORT_IP_OBSERVABLES = "import_ip_observable"
    ACTION_ID_IMPORT_URL_OBSERVABLES = "import_url_observable"
    ACTION_ID_IMPORT_DOMAIN_OBSERVABLES = "import_domain_observable"
    ACTION_ID_RUN_QUERY = "run_query"
    ACTION_ID_TAG_IOC = "tag_observable"
    ACTION_ID_ON_POLL = "on_poll"
    ACTION_ID_DETONATE_FILE = "detonate_file"
    ACTION_ID_GET_STATUS = "get_status"
    ACTION_ID_GET_REPORT = "get_report"
    ACTION_ID_DETONATE_URL = "detonate_url"
    ACTION_ID_GET_PCAP = "get_pcap"
    ACTION_IMPORT_SESSION_SEARCH = "import_session_search"
    ACTION_IMPORT_SESSION_UPDATE = "import_session_update"
    ACTION_THREAT_MODEL_SEARCH = "threat_model_search"
    ACTION_CREATE_THREAT_BULLETIN = "create_threat_bulletin"
    ACTION_UPDATE_THREAT_BULLETIN = "update_threat_bulletin"
    ACTION_DELETE_THREAT_BULLETIN = "delete_threat_bulletin"
    ACTION_LIST_THREAT_BULLETINS = "list_threat_bulletins"
    ACTION_LIST_ASSOCIATIONS = "list_associations"
    ACTION_CREATE_RULE = "create_rule"
    ACTION_UPDATE_RULE = "update_rule"
    ACTION_LIST_RULE = "list_rules"
    ACTION_DELETE_RULE = "delete_rule"
    ACTION_ADD_ASSOCIATION = "add_association"
    ACTION_REMOVE_ASSOCIATION = "remove_association"
    ACTION_LIST_ACTORS = "list_actors"
    ACTION_LIST_IMPORT = "list_imports"
    ACTION_CREATE_VULNERABILITY = "create_vulnerability"
    ACTION_UPDATE_VULNERABILITY = "update_vulnerability"
    ACTION_DELETE_VULNERABILITY = "delete_vulnerability"
    ACTION_DELETE_ACTOR = "delete_actor"
    ACTION_CREATE_ACTOR = "create_actor"
    ACTION_UPDATE_ACTOR = "update_actor"
    ACTION_CREATE_INVESTIGATION = 'create_investigation'
    ACTION_LIST_INVESTIGATIONS = 'list_investigations'
    ACTION_GET_INVESTIGATION = 'get_investigation'
    ACTION_UPDATE_INVESTIGATION = 'update_investigation'
    ACTION_DELETE_INVESTIGATION = 'delete_investigation'

    def __init__(self):

        super(ThreatstreamConnector, self).__init__()
        self._base_url = None
        self._state = None
        self._verify = None
        self._is_cloud_instance = None
        self._first_run_limit = None
        self._python_version = None
        self._data_dict = {}  # Blank dict to contain data from all API calls
        return

    def initialize(self):
        config = self.get_config()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR,
                                   "Error occurred while getting the Phantom server's Python major version.")

        self._base_url = "https://{0}/api".format(self._handle_py_ver_compat_for_input_str(config.get('hostname', 'api.threatstream.com')))
        self._state = self.load_state()
        self._verify = config.get("verify_server_cert", False)
        self._is_cloud_instance = config.get("is_cloud_instance", False)
        self._first_run_limit = config.get('first_run_containers')

        ret_val, self._first_run_limit = self._validate_integer(self, self._first_run_limit, THREATSTREAM_FIRST_RUN_CONTAINER)
        if phantom.is_fail(ret_val):
            return self.get_status()
        self.set_validator('ipv6', self._is_ip)

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_INVALID_INT.format(param=key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_INVALID_INT.format(param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_NEGATIVE_INT_PARAM.format(param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _process_empty_reponse(self, response, action_result):

        status_code = response.status_code
        action = self.get_action_identifier()

        if status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})
        elif status_code == 204 and action == self.ACTION_ID_DELETE_INCIDENT:
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted incident"), {})
        elif status_code == 204 and action == self.ACTION_DELETE_INVESTIGATION:
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted investigation"), {})
        elif status_code == 204 and action == self.ACTION_DELETE_RULE:
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted rule"), {})
        elif status_code == 204 and action == self.ACTION_DELETE_THREAT_BULLETIN:
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted threat bulletin"), {})
        elif status_code == 204 and action == self.ACTION_DELETE_VULNERABILITY:
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted vulnerability"), {})
        elif status_code == 204 and action == self.ACTION_DELETE_ACTOR:
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted actor"), {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code
        action = self.get_action_identifier()

        if 200 <= status_code < 399:

            if status_code == 202:
                return RetVal(phantom.APP_SUCCESS, {})
            elif status_code == 204 and action == self.ACTION_ID_DELETE_INCIDENT:
                return RetVal(action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted incident"), {})
            else:
                try:
                    resp = response.json()
                    return RetVal(phantom.APP_SUCCESS, resp)
                except:
                    if not response.text:
                        resp_text = "Unknown response from the server"
                    else:
                        resp_text = response.text
                    action_result.set_status(phantom.APP_SUCCESS, "Unable to parse the JSON response. Response Status Code: {}. Response: {}".format(
                                                status_code, self._handle_py_ver_compat_for_input_str(resp_text)))
                    return RetVal(phantom.APP_SUCCESS, {})

        data_message = ""
        if not response.text:
            data_message = "Empty response and no information in the header"
        else:
            try:
                soup = BeautifulSoup(response.text, "html.parser")
                # Remove the script, style, footer and navigation part from the HTML message
                for element in soup(["script", "style", "footer", "nav"]):
                    element.extract()
                error_text = soup.text
                split_lines = error_text.split('\n')
                split_lines = [x.strip() for x in split_lines if x.strip()]
                error_text = '\n'.join(split_lines)
            except:
                error_text = "Cannot parse error details"

            # Error text can still be an empty string
            if error_text:
                data_message = " Data from server:\n{0}\n".format(self._handle_py_ver_compat_for_input_str(error_text))

        message = "Status Code: {0}. {1}".format(status_code, data_message)

        message = message.replace('{', '{{').replace('}', '}}')

        if len(message) > 500:
            message = "Status Code: {0}. Error while connecting to the server. Please check the asset and the action's input parameters".format(status_code)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}"
                                                   .format(self._get_error_message_from_exception(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            if resp_json.get('error', None) is None:
                return RetVal(phantom.APP_SUCCESS, resp_json)

        if not r.text:
            message = "Status Code: {0}. {1}".format(r.status_code, "Empty response and no information in the header")
        else:
            # You should process the error returned in the json
            message = "Error from server. Status Code: {0} Data from server: {1}".format(
                    r.status_code, self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, self._handle_py_ver_compat_for_input_str(r.text.replace('{', '{{').replace('}', '}}')))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.
        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """
        try:
            if input_str and self._python_version < 3:
                input_str = UnicodeDammit(input_str).unicode_markup.encode('utf-8')
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _make_rest_call(self, action_result, endpoint, payload=None, headers=None, data=None, method="get", files=None, use_json=True):
        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = "{0}{1}".format(self._base_url, endpoint)

        if use_json:
            try:
                r = request_func(
                    url,
                    json=data,
                    headers=headers,
                    params=payload,
                    verify=self._verify,
                    files=files)
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Error making rest call to server. Details: {0}"
                                                       .format(error_msg)), resp_json)

        else:
            try:
                r = request_func(
                                url,
                                data=data,
                                headers=headers,
                                params=payload,
                                verify=self._verify,
                                files=files)
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Error making rest call to server. Details: {0}"
                                                    .format(error_msg)), resp_json)

        ret_val, response = self._process_response(r, action_result)

        current_message = action_result.get_message()

        if current_message:
            current_message = current_message.replace(payload.get('api_key'), '<api_key_value_provided_in_config_params>')

        if phantom.is_fail(ret_val):
            return RetVal(action_result.set_status(phantom.APP_ERROR, current_message), response)
        else:
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, current_message), response)

    def _is_ip(self, input_ip_address):
        """ Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        ip_address_input = input_ip_address

        try:
            ipaddress.ip_address(UnicodeDammit(ip_address_input).unicode_markup)
        except:
            return False

        return True

    def _generate_payload(self, **kwargs):
        """Create dict with username and password URL parameters
           Can also add in any further URL parameters
        """
        payload = {}
        config = self.get_config()
        payload['username'] = config[THREATSTREAM_JSON_USERNAME]
        payload['api_key'] = config[THREATSTREAM_JSON_API_KEY]

        for k, v in list(kwargs.items()):
            payload[k] = v

        return payload

    def _intel_details(self, value, action_result, limit=None, extend_source=False):
        """ Use the intelligence endpoint to get general details """

        payload = self._generate_payload(extend_source=extend_source, order_by="-created_ts", value=value, limit=limit)

        intel_details = self._paginator(ENDPOINT_INTELLIGENCE, action_result, payload=payload, limit=limit)

        if intel_details is None:
            return action_result.get_status()

        for detail in intel_details:
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
        if action_result.get_data():
            action_result.add_data(action_result.get_data()[0].update({'pdns': resp_json['results']}))
        else:
            action_result.add_data({'pdns': resp_json['results']})
        return action_result.set_status(phantom.APP_SUCCESS, "Retrieved")

    def _insight(self, value, ioc_type, action_result):

        # Validate input
        if ioc_type not in [ "ip", "domain", "email", "md5", "sha1", "sha256", "sha512" ]:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_TYPE)

        payload = self._generate_payload(type=ioc_type, value=value)

        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INISGHT, payload)
        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Error retrieving insights")

        if action_result.get_data():
            action_result.add_data(action_result.get_data()[0].update({'insights': resp_json['insights']}))
        else:
            action_result.add_data({'insights': resp_json['insights']})
        return action_result.set_status(phantom.APP_SUCCESS, "Retrieved")

    def _external_references(self, value, action_result):

        payload = self._generate_payload()
        ext_ref = ENDPOINT_REFERENCE.format(ioc_value=value)

        ret_val, resp_json = self._make_rest_call(action_result, ext_ref, payload)

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_SUCCESS, "Error retrieving external references")

        if action_result.get_data():
            action_result.add_data(action_result.get_data()[0].update({'external_references': resp_json}))
        else:
            action_result.add_data({'external_references': resp_json})
        return action_result.set_status(phantom.APP_SUCCESS, "Retrieved")

    def _whois(self, value, action_result, tipe=""):
        final_response = dict()

        # This fix for hanging issue of japanese domain
        if value.endswith("jp"):
            whois_response = pythonwhois.get_whois(value)
        else:
            payload = self._generate_payload()
            whois = ENDPOINT_WHOIS.format(ioc_value=value)

            ret_val, resp_json = self._make_rest_call(action_result, whois, payload)
            if (phantom.is_fail(ret_val)):
                return action_result.set_status(phantom.APP_ERROR, "Error making whois request")

            if not resp_json.get("data") or (resp_json['data'] == WHOIS_NO_DATA):
                return action_result.set_status(phantom.APP_ERROR, WHOIS_NO_DATA)

            try:
                whois_response = pythonwhois.parse.parse_raw_whois([resp_json['data']], True)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_FETCH_REPLY.format(error=self._get_error_message_from_exception(e)))

        try:
            # Need to work on the json, it contains certain fields that are not
            # parsable, so will need to go the 'fallback' way.
            # TODO: Find a better way to do this
            whois_response = json.dumps(whois_response, default=_json_fallback)
            whois_response = json.loads(whois_response)
            final_response.update(whois_response)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_PARSE_REPLY.format(error=self._get_error_message_from_exception(e)))

        try:
            if tipe == "ip":
                obj_whois = IPWhois(value)
                whois_response = obj_whois.lookup_whois(asn_methods=["whois", "dns", "http"])
                if whois_response:
                    final_response["addtional_info"] = whois_response
                else:
                    final_response["addtional_info"] = None
                    self.debug_print("The additional info response for the given IP is None")

                    action_result.add_data(final_response)
                    return action_result.set_status(phantom.APP_SUCCESS, "{}. {}".format(
                                THREATSTREAM_SUCCESS_WHOIS_MESSAGE, "Unable to fetch additional info for the given IP."))
        except Exception as e:
            final_response["addtional_info"] = None
            self.debug_print("Unable to fetch additional info for the given IP. ERROR: {error}".format(error=self._get_error_message_from_exception(e)))

            action_result.add_data(final_response)
            return action_result.set_status(phantom.APP_SUCCESS, "{}. {}".format(
                        THREATSTREAM_SUCCESS_WHOIS_MESSAGE,
                        "Unable to fetch additional info for the given IP. ERROR: {error}".format(error=self._get_error_message_from_exception(e))))

        action_result.add_data(final_response)

        return action_result.set_status(phantom.APP_SUCCESS, THREATSTREAM_SUCCESS_WHOIS_MESSAGE)

    def _retrieve_ip_domain(self, value, ioc_type, action_result, param, limit=None):
        """ Retrieve all the information needed for domains or IPs """
        extend_source = param.get("extend_source", False)
        include_pdns = param.get("pdns", False)
        include_insights = param.get("insights", False)
        include_external_references = param.get("external_references", False)

        self.debug_print('Retrieving ip domain with {0}'.format(param))

        ret_val = self._intel_details(value, action_result, limit=limit, extend_source=extend_source)
        if (not ret_val):
            return action_result.get_status()

        if include_pdns:
            self.debug_print('Fetching pdns')
            ret_val = self._pdns(value, ioc_type, action_result)
            if (not ret_val):
                return action_result.get_status()

        if include_insights:
            self.debug_print('Fetching insights')
            ret_val = self._insight(value, ioc_type, action_result)
            if (not ret_val):
                return action_result.get_status()

        if include_external_references:
            self.debug_print('Fetching external references')
            ret_val = self._external_references(value, action_result)
            if (not ret_val):
                return action_result.get_status()

        return phantom.APP_SUCCESS

    def _retrieve_email_md5(self, value, ioc_type, action_result, limit=None, extend_source=False):
        """ Retrieve all the information needed for email or md5 hashes """

        ret_val = self._intel_details(value, action_result, limit=limit, extend_source=extend_source)
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
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Please verify if the hostname provided in the [hostname] parameter is cloud or on-prem and provide input \
                            in the [Is the provided instance in hostname parameter cloud?] parameter accordingly. \
                            This parameter will impact the actions' execution of the application.")

        self.save_progress("Starting connectivity test")
        payload = self._generate_payload(limit="1")
        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INTELLIGENCE, payload)

        if (phantom.is_fail(ret_val)):
            self.save_progress("Connectivity test failed")
            return action_result.get_status()

        self.save_progress("Connectivity test passed")
        return action_result.set_status(phantom.APP_SUCCESS, "")

    def _file_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = param[THREATSTREAM_JSON_HASH]
        extend_source = param.get("extend_source", False)

        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ioc_type = None

        if phantom.is_md5(value):
            ioc_type = "md5"
        elif phantom.is_sha1(value):
            ioc_type = "sha1"
        elif phantom.is_sha256(value):
            ioc_type = "sha256"
        elif phantom.is_sha512(value):
            ioc_type = "sha512"

        ret_val = self._retrieve_email_md5(value, ioc_type, action_result, limit=limit, extend_source=extend_source)
        if (not ret_val):
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved information on File")

    def _domain_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = self._handle_py_ver_compat_for_input_str(param[THREATSTREAM_JSON_DOMAIN])
        extend_source = param.get("extend_source", False)

        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if "/" in value:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_VALUE)

        ioc_type = "domain"

        ret_val = self._retrieve_ip_domain(value, ioc_type, action_result, param, limit=limit)
        if (not ret_val):
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved information on Domain")

    def _ip_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = param[THREATSTREAM_JSON_IP]
        extend_source = param.get("extend_source", False)
        ioc_type = "ip"

        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val = self._retrieve_ip_domain(value, ioc_type, action_result, param, limit=limit)
        if (not ret_val):
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved information on IP")

    def _url_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = self._handle_py_ver_compat_for_input_str(param[THREATSTREAM_JSON_URL])
        extend_source = param.get("extend_source", False)

        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val = self._intel_details(value, action_result, limit=limit, extend_source=extend_source)
        if (not ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved information on URL")

    def _email_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        value = self._handle_py_ver_compat_for_input_str(param[THREATSTREAM_JSON_EMAIL])
        extend_source = param.get("extend_source", False)
        ioc_type = "email"

        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val = self._retrieve_email_md5(value, ioc_type, action_result, limit=limit, extend_source=extend_source)

        if (not ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved information on Email")

    def _whois_domain(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = self._handle_py_ver_compat_for_input_str(param[THREATSTREAM_JSON_DOMAIN])
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

    def _paginator(self, endpoint, action_result, payload=None, offset=0, limit=None):

        items_list = list()

        if payload:
            payload['limit'] = DEFAULT_MAX_RESULTS
        else:
            payload = self._generate_payload(limit=DEFAULT_MAX_RESULTS)

        payload['offset'] = offset

        while True:
            ret_val, items = self._make_rest_call(action_result, endpoint, payload)

            if phantom.is_fail(ret_val):
                return None

            items_list.extend(items.get("objects", []))

            if limit and len(items_list) >= limit:
                return items_list[:limit]

            if len(items.get("objects", [])) < DEFAULT_MAX_RESULTS:
                break

            offset = offset + DEFAULT_MAX_RESULTS
            payload['offset'] = offset

        return items_list

    def _handle_list_observable(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        payload = self._generate_payload()
        payload["order_by"] = "-created_ts"

        observable = self._paginator(ENDPOINT_INTELLIGENCE, action_result, limit=limit, payload=payload)

        if observable is None:
            return action_result.get_status()

        for obs in observable:
            action_result.add_data(obs)

        summary = action_result.update_summary({})
        summary['observables_returned'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_vulnerability(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        payload = self._generate_payload(order_by="-created_ts")
        vulnerability = self._paginator(ENDPOINT_VULNERABILITY, action_result, payload=payload, limit=limit)

        if vulnerability is None:
            return action_result.get_status()

        for vul in vulnerability:
            action_result.add_data(vul)

        summary = action_result.update_summary({})
        summary['vulnerabilities_returned'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_incidents(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        payload = self._generate_payload(order_by="-created_ts")

        if param.get("intel_value", None):
            payload["value"] = param.get("intel_value")
            incidents = self._paginator(ENDPOINT_INCIDENT_WITH_VALUE, action_result, payload=payload, limit=limit)
        else:
            incidents = self._paginator(ENDPOINT_INCIDENT, action_result, payload=payload, limit=limit)

        if incidents is None:
            return action_result.get_status()

        list_incident_name = list()
        for incident in incidents:
            list_incident_name.append(incident.get("name"))
            action_result.add_data(incident)

        summary = action_result.update_summary({})
        summary['incidents_returned'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_incident_support(self, action_result, param=None, payload=None, incident_id=None):

        ret_val = None
        resp_json = None
        if payload and payload.get("remote_api") is not None:
            del payload["remote_api"]

        if not payload:
            payload = self._generate_payload()
        if param and param.get("incident_id"):
            try:
                incident_id = int(param["incident_id"])
            except ValueError:
                return action_result.set_status(phantom.APP_ERROR, "Please provide a valid interger in 'incident id' parameter"), None
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error: {}".format(self._get_error_message_from_exception(e))), None

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None
        else:
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload)

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            endpoint = "{}{}/".format(ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), "intelligence")

            response = self._paginator(endpoint, action_result, payload=payload)

            if response is None:
                return action_result.get_status(), None

            resp_json.update({"intelligence": response})

        action_result.set_status(phantom.APP_SUCCESS, "")

        return phantom.APP_SUCCESS, resp_json

    def _get_threat_model_support(self, action_result, endpoint):

        ret_val = None
        resp_json = None

        payload = self._generate_payload()

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None
        else:
            ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload)

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

            endpoint = "{}{}/".format(endpoint, "intelligence")

            response = self._paginator(endpoint, action_result, payload=payload)

            if response is None:
                return action_result.get_status(), None

            resp_json.update({"intelligence": response})

        action_result.set_status(phantom.APP_SUCCESS, "")

        return phantom.APP_SUCCESS, resp_json

    def _handle_get_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, resp_json = self._get_incident_support(action_result, param)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved incident")

    def _handle_get_observable(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            intelligence_id = int(param["intelligence_id"])
        except ValueError:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid interger in 'intelligence id' parameter")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error: {}".format(self._get_error_message_from_exception(e)))

        payload = self._generate_payload(id=intelligence_id)

        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INTELLIGENCE, payload)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not resp_json.get("objects"):
            return action_result.set_status(phantom.APP_ERROR, "Please enter a valid 'intelligence id' parameter")

        action_result.add_data(resp_json.get("objects")[0])
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved observable")

    def _handle_get_vulnerability(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val = None
        resp_json = None
        try:
            vulnerability_id = int(param["vulnerability_id"])
        except ValueError:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid interger in 'vulnerability id' parameter")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error: {}".format(self._get_error_message_from_exception(e)))

        payload = self._generate_payload()

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_VULNERABILITY.format(vul_id=vulnerability_id), payload)
        else:
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_VULNERABILITY.format(vul_id=vulnerability_id), payload)

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_VULNERABILITY.format(vul_id=vulnerability_id), payload)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved vulnerability")

    def _handle_delete_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            incident_id = int(param["incident_id"])
        except ValueError:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid interger in 'incident id' parameter")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error: {}".format(self._get_error_message_from_exception(e)))

        payload = self._generate_payload()

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload, method="delete")
        else:
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload, method="delete")

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload, method="delete")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted incident")

    def _handle_create_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        create_on_cloud = param.get("create_on_cloud", False)

        data = {
                "name": param["name"], "is_public": param.get("is_public", False), "status": 1
               }
        data_dict = self._build_data(param, data, action_result)
        if data_dict is None:
            return action_result.get_status()

        data = data_dict.get("data")
        local_intelligence = data_dict.get("local_intelligence")
        cloud_intelligence = data_dict.get("cloud_intelligence")

        payload = self._generate_payload()
        intelligence = list()
        output_message = None
        is_error = False

        if self._is_cloud_instance:
            if cloud_intelligence:
                data.update({"intelligence": cloud_intelligence})
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INCIDENT, payload, data=data, method="post")

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            for intel in resp_json.get("intelligence", []):
                intelligence.append(intel.get("id"))

        elif create_on_cloud:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INCIDENT, payload, data=data, method="post")

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            incident_id = resp_json.get("id")
            if not incident_id:
                return action_result.set_status(phantom.APP_ERROR, "Error while fetching the incident ID of the created incident on the cloud")

            output_message = THREATSTREAM_SUCCESS_INCIDENT_MESSAGE.format(incident_id)

            if cloud_intelligence:
                intel_data = {"ids": cloud_intelligence}
                ret_val, response = self._make_rest_call(
                            action_result, ENDPOINT_ASSOCIATE_INTELLIGENCE.format(incident=incident_id), payload, data=intel_data, method="post")

                if phantom.is_fail(ret_val):
                    is_error = True
                    output_message = "{}. {}. Details: {}"\
                        .format(output_message, THREATSTREAM_ERR_INVALID_REMOTE_INTELLIGENCE.format(', '.join(cloud_intelligence)), action_result.get_message())

                if response and response.get("ids"):
                    intelligence.extend(response.get("ids"))

            if local_intelligence:
                del payload["remote_api"]
                intel_data = {"local_ids": local_intelligence}
                ret_val, response = self._make_rest_call(
                            action_result, ENDPOINT_ASSOCIATE_INTELLIGENCE.format(incident=incident_id), payload, data=intel_data, method="post")

                if phantom.is_fail(ret_val):
                    is_error = True
                    output_message = "{}. {}. Details: {}"\
                        .format(output_message, THREATSTREAM_ERR_INVALID_LOCAL_INTELLIGENCE.format(', '.join(local_intelligence)), action_result.get_message())

                if response and response.get("local_ids"):
                    intelligence.extend(response.get("local_ids"))

        else:
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INCIDENT, payload, data=data, method="post")

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            incident_id = resp_json.get("id")

            if not incident_id:
                return action_result.set_status(phantom.APP_ERROR, "Error while fetching the incident ID of the created incident on the on-prem")

            output_message = THREATSTREAM_SUCCESS_INCIDENT_MESSAGE.format(incident_id)

            intel_data = dict()

            if local_intelligence:
                intel_data["ids"] = local_intelligence
            if cloud_intelligence:
                intel_data["remote_ids"] = cloud_intelligence

            if intel_data:
                ret_val, response = self._make_rest_call(
                            action_result, ENDPOINT_ASSOCIATE_INTELLIGENCE.format(incident=incident_id), payload, data=intel_data, method="post")

                if phantom.is_fail(ret_val):
                    is_error = True
                    output_message = "{}. Error while adding intelligence to the incident. Details: {}".format(output_message, action_result.get_message())

                if response and response.get("remote_ids"):
                    intelligence.extend(response.get("remote_ids"))

                if response and response.get("ids"):
                    intelligence.extend(response.get("ids"))

        intel_list = list()

        if intelligence:
            msg_intel = list()
            for intel_value in intelligence:
                intel_id_dict = dict()
                intel_id_dict["id"] = intel_value
                intel_list.append(intel_id_dict)
                msg_intel.append(str(intel_value))

            resp_json["intelligence"] = intel_list

            message = "Incident created successfully. Associated intelligence : {}".format(', '.join(msg_intel))

        elif (local_intelligence or cloud_intelligence):
            message = "Incident created successfully. None of the intelligence got associated, please provide valid intelligence"

        else:
            message = "Incident created successfully"

        action_result.add_data(resp_json)
        if is_error:
            return action_result.set_status(phantom.APP_ERROR, output_message)

        summary = action_result.update_summary({})
        summary['created_on_cloud'] = create_on_cloud or self._is_cloud_instance
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_update_incident(self, param):  # noqa
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = None
        resp_json = None
        message = None
        try:
            incident_id = int(param["incident_id"])
        except ValueError:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid interger in 'incident id' parameter")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error: {}".format(self._get_error_message_from_exception(e)))

        if not (param.get("local_intelligence") or param.get("cloud_intelligence")) and not param.get("fields"):
            return action_result.set_status(phantom.APP_ERROR, "Please provide at least one parameter, either 'intelligence' or 'fields' to update the provided incident")

        data = {}
        intel_ids_list = list()
        data_dict = self._build_data(param, data, action_result)
        if data_dict is None:
            return action_result.get_status()

        local_intelligence = data_dict.get("local_intelligence")
        cloud_intelligence = data_dict.get("cloud_intelligence")
        data = data_dict.get("data")

        payload = self._generate_payload()
        output_message = None
        is_error = False

        if self._is_cloud_instance:
            if cloud_intelligence:
                data.update({"intelligence": cloud_intelligence})
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload, data=data, method="patch")
        else:

            if local_intelligence or cloud_intelligence:
                intel_data = dict()
                if local_intelligence:
                    intel_data["ids"] = local_intelligence

                if cloud_intelligence:
                    intel_data["remote_ids"] = cloud_intelligence

                ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_ASSOCIATE_INTELLIGENCE.format(incident=incident_id), payload, data=intel_data, method="post")

                if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                    intel_data = dict()
                    if local_intelligence:
                        intel_data["local_ids"] = local_intelligence

                        ret_val, resp_json = self._make_rest_call(
                            action_result, ENDPOINT_ASSOCIATE_INTELLIGENCE.format(incident=incident_id), payload, data=intel_data, method="post")

                        if phantom.is_fail(ret_val):
                            is_error = True
                            if output_message:
                                output_message = "{}. {}. Details: {}"\
                                    .format(output_message, THREATSTREAM_ERR_INVALID_LOCAL_INTELLIGENCE.format(', '.join(local_intelligence)), action_result.get_message())
                            else:
                                output_message = "{}. Details: {}"\
                                    .format(THREATSTREAM_ERR_INVALID_LOCAL_INTELLIGENCE.format(', '.join(local_intelligence)), action_result.get_message())
                        del intel_data["local_ids"]
                        if resp_json and resp_json.get("local_ids"):
                            intel_ids_list.extend(resp_json.get("local_ids"))

                    if cloud_intelligence:
                        intel_data["ids"] = cloud_intelligence
                        payload["remote_api"] = "true"
                        ret_val, resp_json = self._make_rest_call(
                            action_result, ENDPOINT_ASSOCIATE_INTELLIGENCE.format(incident=incident_id), payload, data=intel_data, method="post")

                        if phantom.is_fail(ret_val):
                            is_error = True
                            if output_message:
                                output_message = "{}. {}. Details: {}"\
                                    .format(output_message, THREATSTREAM_ERR_INVALID_REMOTE_INTELLIGENCE.format(', '.join(cloud_intelligence)), action_result.get_message())
                            else:
                                output_message = "{}. Details: {}"\
                                    .format(THREATSTREAM_ERR_INVALID_REMOTE_INTELLIGENCE.format(', '.join(cloud_intelligence)), action_result.get_message())

                if phantom.is_fail(ret_val):
                    is_error = True
                    if output_message:
                        output_message = "{}. Error while updating the incident. Details: {}".format(output_message, action_result.get_message())
                    else:
                        output_message = "{}. Details: {}".format("Error while updating the incident", action_result.get_message())

                if resp_json and resp_json.get("ids"):
                    intel_ids_list.extend(resp_json.get("ids"))
                if resp_json and resp_json.get("remote_ids"):
                    intel_ids_list.extend(resp_json.get("remote_ids"))

            if intel_ids_list:
                msg_intel = list()
                for intel_value in intel_ids_list:
                    msg_intel.append(str(intel_value))

                message = "Associated intelligence : {}".format(', '.join(msg_intel))

            elif (local_intelligence or cloud_intelligence):
                message = THREATSTREAM_ERR_INVALID_INTELLIGENCE

            else:
                message = None

            associated_intelligence = data_dict.get("associated_intelligence")
            if associated_intelligence:
                intel_ids_list.extend(associated_intelligence)

            # Update the incident in all cases with data or with empty data to get the latest intelligence values associated with it
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload, data=data, method="patch")

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident_id), payload, data=data, method="patch")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        intel_list = list()

        intel_ids_list = list(set(intel_ids_list))

        if intel_ids_list:
            for intel_value in intel_ids_list:
                intel_id_dict = dict()
                intel_id_dict["id"] = intel_value
                intel_list.append(intel_id_dict)

            resp_json["intelligence"] = intel_list

        action_result.add_data(resp_json)
        if is_error:
            return action_result.set_status(phantom.APP_ERROR, output_message)

        if message:
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated incident. {}".format(message))
        else:
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated incident")

    def _build_data(self, param, data, action_result):

        if param.get("fields", None):
            try:
                fields = ast.literal_eval(param["fields"])
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                action_result.set_status(
                    phantom.APP_ERROR, "Error building fields dictionary: {0}. Please ensure that provided input is in valid JSON format.".format(error_msg))
                return None

            if not isinstance(fields, dict):
                action_result.set_status(phantom.APP_ERROR, "Error building fields dictionary. Please ensure that provided input is in valid JSON dictionary format")
                return None

            if fields.get("tags") and not isinstance(fields.get("tags"), list):
                action_result.set_status(phantom.APP_ERROR, "Please enter the value of the key, 'tags', in 'fields' parameter in form of list")
                return None

            data.update(fields)

        data_dict = dict()
        local_intelligence = param.get("local_intelligence")
        cloud_intelligence = param.get("cloud_intelligence")

        # 1. Fetch the existing intelligence values in the incident to append to
        # in case of cloud instance API because it overwrites the existing values
        associated_intell = list()

        if self.get_action_identifier() == 'update_incident':

            ret_val, resp_json = self._get_incident_support(action_result, param)

            if phantom.is_fail(ret_val):
                return None

            for intell in resp_json.get("intelligence", []):
                associated_intell.append(int(intell.get("id")))

        if self.get_action_identifier() in ['update_actor', 'update_vulnerability']:

            ret_val, _id = self._validate_integer(action_result, param.get('id'), THREATSTREAM_ID)

            if phantom.is_fail(ret_val):
                return None

            if self.get_action_identifier() == "update_actor":
                endpoint = ENDPOINT_SINGLE_ACTOR.format(actor_id=_id)
            else:
                endpoint = ENDPOINT_SINGLE_VULNERABILITY.format(vul_id=_id)

            ret_val, resp_json = self._get_threat_model_support(action_result, endpoint)

            if phantom.is_fail(ret_val):
                return None

            for intell in resp_json.get("intelligence", []):
                associated_intell.append(int(intell.get("id")))

        if local_intelligence:
            local_intelligence = self._create_intelligence(action_result, local_intelligence)
            if local_intelligence is None:
                return local_intelligence

        if cloud_intelligence:
            cloud_intelligence = self._create_intelligence(action_result, cloud_intelligence)
            if cloud_intelligence is None:
                return cloud_intelligence

        data_dict.update({"data": data, "local_intelligence": local_intelligence, "cloud_intelligence": cloud_intelligence, "associated_intelligence": associated_intell})

        return data_dict

    def _create_intelligence(self, action_result, intelligence):
        # Adding a first check if we have been supplied a list - this will
        # be useful for playbooks supplying a list object as the parameter

        if type(intelligence) is list:
            try:
                intel = [x.strip() for x in intelligence if x.strip() != '']
            except Exception as e:
                action_result.set_status(phantom.APP_ERROR, "Error building list of intelligence IDs: {0}. Please supply as comma separated string of integers".format(e))
                return None
        else:
            try:
                intel = intelligence.strip().split(",")
                intel = [x.strip() for x in intel if x.strip() != '']

            except Exception as e:
                action_result.set_status(phantom.APP_ERROR, "Error building list of intelligence IDs: {0}. Please supply as comma separated string of integers".format(e))
                return None
        return intel

    def _handle_run_query(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        payload = self._generate_payload()

        try:
            search_string = param["query"]
            search_dict = json.loads(search_string)
            payload.update(search_dict)
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while parsing the JSON string provided in the 'query' parameter. Error: {0}".format(error_msg))

        order_by = param.get("order_by")
        if order_by:
            payload['order_by'] = order_by

        ret_val, offset = self._validate_integer(action_result, param.get('offset', 0), THREATSTREAM_OFFSET, True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        records = self._paginator(ENDPOINT_INTELLIGENCE, action_result, payload=payload, offset=offset, limit=limit)

        if records is None:
            return action_result.get_status()

        for record in records:
            action_result.add_data(record)

        summary = action_result.update_summary({})
        summary['records_returned'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_error_message_from_exception(self, e):
        """ This function is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."
        error_code = "Error code unavailable"
        try:
            if e.args:
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = "Error code unavailable"
                    error_msg = e.args[0]
            else:
                error_code = "Error code unavailable"
                error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."
        except:
            error_code = "Error code unavailable"
            error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = "Error occurred while connecting to the Threatstream server. Please check the asset configuration and|or the action parameters."
        except:
            error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def import_support(self, param, action_result):  # noqa

        payload = self._generate_payload()
        action_name = self.get_action_identifier()
        create_on_cloud = param.get("create_on_cloud", False)
        with_approval = param.get("with_approval", False)

        if self._is_cloud_instance or create_on_cloud:
            payload["remote_api"] = "true"

        if action_name == self.ACTION_ID_IMPORT_IOC:
            value = param["value"]
            if not with_approval:
                key = "itype"
                endpoint = ENDPOINT_IMPORT_IOC
                method = "patch"
                use_json = True
                if param["observable_type"] == "ip":
                    ob_type = "srcip"
                elif param["observable_type"] == "hash":
                    ob_type = "md5"
                else:
                    ob_type = param["observable_type"]
                data = {
                        "objects": [
                            {
                                ob_type: value, "classification": param["classification"]
                            }
                        ]
                    }
                if ob_type == "domain":
                    data.update({"meta": {
                        "allow_unresolved": param.get('allow_unresolved', False)
                    }})
            else:
                key = "threat_type"
                endpoint = ENDPOINT_IMPORT_APPROVAL_IOC
                method = "post"
                use_json = False
                data = {
                    'datatext': value,
                    "classification": param["classification"]
                }

            if param.get("fields", None):
                try:
                    fields = ast.literal_eval(param["fields"])
                except Exception as e:
                    error_msg = self._get_error_message_from_exception(e)
                    return action_result.set_status(phantom.APP_ERROR, "Error building fields dictionary: {0}. \
                        Please ensure that provided input is in valid JSON format".format(error_msg))

                if not isinstance(fields, dict):
                    return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_JSON)

                if with_approval and "confidence" not in fields:
                    return action_result.set_status(phantom.APP_ERROR, "Providing 'confidence' in fields parameter is mandatory for importing an observable with approval")

                if key in fields:
                    if not with_approval:
                        data["objects"][0].update(fields)
                    else:
                        data.update(fields)
                else:
                    return action_result.set_status(phantom.APP_ERROR, "Providing '{key}' in fields parameter is mandatory for importing an observable \
                                (e.g. {{\"itype\": \"<indicator_type>\"}} or {{\"threat_type\": \"<threat_type>\"}})".format(key=key))
            else:
                return action_result.set_status(phantom.APP_ERROR, "Providing '{key}' in fields parameter is mandatory for importing an observable \
                            (e.g. {{\"itype\": \"<indicator_type>\"}} or {{\"threat_type\": \"<threat_type>\"}})".format(key=key))

        else:
            ret_val, confidence = self._validate_integer(action_result, param.get('confidence', 100), THREATSTREAM_INVALID_CONFIDENCE)
            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_INVALID_CONFIDENCE)
            indicator_type = param['indicator_type']
            classification = param.get('classification')
            severity = param.get('severity')
            tags = param.get('tags')

            if not with_approval:
                endpoint = ENDPOINT_IMPORT_IOC
                method = "patch"
                use_json = True
                data = {}
                object_dict = {"itype": indicator_type}

                if action_name == self.ACTION_ID_IMPORT_EMAIL_OBSERVABLES:
                    value = param['email']
                    object_dict.update({"email": value})

                if action_name == self.ACTION_ID_IMPORT_FILE_OBSERVABLES:
                    value = param['file_hash']
                    object_dict.update({"md5": value})

                if action_name == self.ACTION_ID_IMPORT_IP_OBSERVABLES:
                    value = param['ip_address']
                    object_dict.update({"srcip": value})

                if action_name == self.ACTION_ID_IMPORT_URL_OBSERVABLES:
                    value = param['url']
                    object_dict.update({"url": value})

                if action_name == self.ACTION_ID_IMPORT_DOMAIN_OBSERVABLES:
                    value = param['domain']
                    object_dict.update({"domain": value})
                    data = {
                        "meta": {
                                "allow_unresolved": param.get('allow_unresolved', False)
                            }
                    }

                if confidence:
                    object_dict.update({"confidence": confidence})

                if severity:
                    object_dict.update({"severity": severity})

                if classification:
                    object_dict.update({"classification": classification})

                if tags:
                    tag = [x.strip() for x in tags.split(',')]
                    tag = list(filter(None, tag))

                    object_dict.update({"tags": tag})

                data.update({
                        "objects": [
                            object_dict
                        ]
                    })

            else:
                endpoint = ENDPOINT_IMPORT_APPROVAL_IOC
                method = "post"
                use_json = False
                data = {
                    "classification": classification
                }

                if confidence:
                    data.update({"confidence": confidence})

                if action_name == self.ACTION_ID_IMPORT_EMAIL_OBSERVABLES:
                    value = param['email']

                if action_name == self.ACTION_ID_IMPORT_FILE_OBSERVABLES:
                    value = param['file_hash']

                if action_name == self.ACTION_ID_IMPORT_IP_OBSERVABLES:
                    value = param['ip_address']

                if action_name == self.ACTION_ID_IMPORT_URL_OBSERVABLES:
                    value = param['url']

                if action_name == self.ACTION_ID_IMPORT_DOMAIN_OBSERVABLES:
                    value = param['domain']

                data.update({"datatext": value})
                data.update({"threat_type": indicator_type})

                if severity:
                    data.update({"severity": severity})

                if tags:
                    tag = [x.strip() for x in tags.split(',')]
                    tag = list(filter(None, tag))
                    tags_to_insert = list()
                    for value in tag:
                        temp_tag = dict()
                        temp_tag.update({"name": value})
                        tags_to_insert.append(temp_tag)
                    data.update({"tags": json.dumps(tags_to_insert)})

        ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload=payload, data=data, method=method, use_json=use_json)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if with_approval:
            action_result.add_data(resp_json)

        summary = action_result.update_summary({})
        summary['created_on_cloud'] = create_on_cloud or self._is_cloud_instance

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully sent the request for importing the observable")

    def _handle_import_email_observable(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.import_support(param, action_result)
        return action_result.get_status()

    def _handle_import_file_observable(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.import_support(param, action_result)
        return action_result.get_status()

    def _handle_import_ip_observable(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.import_support(param, action_result)
        return action_result.get_status()

    def _handle_import_url_observable(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.import_support(param, action_result)
        return action_result.get_status()

    def _handle_import_domain_observable(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.import_support(param, action_result)
        return action_result.get_status()

    def _handle_import_ioc(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.import_support(param, action_result)
        return action_result.get_status()

    def _handle_tag_ioc(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        config = self.get_config()
        try:
            intelligence_id = int(param["id"])
        except ValueError:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid interger in 'intelligence id' parameter")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error: {}".format(self._get_error_message_from_exception(e)))

        org_id = config.get("organization_id", None)
        if org_id is None:
            return action_result.set_status(phantom.APP_ERROR, "Please set the organization ID config value prior to tagging an observable")

        payload = self._generate_payload()

        # tags should be a comma-separated list
        tags = [x.strip() for x in param[THREATSTREAM_JSON_TAGS].split(',')]
        tags = list(filter(None, tags))

        data = {THREATSTREAM_JSON_TAGS: []}

        for tag in tags:
            data[THREATSTREAM_JSON_TAGS].append({
                "name": tag,
                "org_id": org_id,
                "tlp": param.get('tlp', 'red'),
                THREATSTREAM_JSON_SOURCE_USER_ID: param[THREATSTREAM_JSON_SOURCE_USER_ID]
            })

        endpoint = ENDPOINT_TAG_IOC.format(indicator_id=intelligence_id)

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, data=data, method="post")
        else:
            ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, data=data, method="post")

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, data=data, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully tagged observable")

    def _handle_get_status(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        payload = self._generate_payload()
        endpoint = self._handle_py_ver_compat_for_input_str(param.get("endpoint"))
        endpoint = endpoint.replace("/api/", "/")
        ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, method="get")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved detonation status")

    def _handle_get_report(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        payload = self._generate_payload()
        endpoint = param.get("endpoint")
        if "report" not in endpoint:
            return action_result.set_status(phantom.APP_ERROR, "Please provide correct report endpoint")

        endpoint = endpoint.replace("/api/", "/")
        ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, method="get")
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved detonation report")

    def _handle_detonate_file(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        # return action_result.set_status(phantom.APP_SUCCESS, param.get('classification'))
        vault_id = self._handle_py_ver_compat_for_input_str(param.get('vault_id'))

        try:
            success, message, vault_info = phrules.vault_info(vault_id=vault_id)
            vault_info = list(vault_info)[0]
        except IndexError:
            return action_result.set_status(phantom.APP_ERROR, "Vault file could not be found with supplied Vault ID"), None
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Vault ID not valid"), None

        if not vault_info:
            return action_result.set_status(phantom.APP_ERROR, "Error while fetching the vault information of the vault id: '{}'".format(param.get('vault_id')))

        vault_path = vault_info.get('path')
        if vault_path is None:
            return action_result.set_status(phantom.APP_ERROR, "Could not find a path associated with the provided vault ID")
        try:
            vault_file = open(vault_path, "rb")
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, "Unable to open vault file: {}".format(error_msg))

        payload = self._generate_payload()

        files = {
            "file": vault_file
        }
        data = {
            "report_radio-platform": param.get('platform', 'WINDOWS7'),
            "report_radio-file": vault_path,
            "report_radio-classification": param.get('classification')
        }

        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_FILE_DETONATION, payload, data=data, method="post", files=files, use_json=False)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully detonated file")

    def _handle_detonate_url(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        payload = self._generate_payload()
        data = {
            "report_radio-platform": param.get('platform', 'WINDOWS7'),
            "report_radio-url": param.get('url'),
            "report_radio-classification": param.get('classification')
        }

        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_URL_DETONATION, payload, data=data, method="post", use_json=False)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully detonated URL")

    def _handle_get_pcap(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        payload = self._generate_payload()
        ret_val, report_id = self._validate_integer(action_result, param["id"], THREATSTREAM_REPORT_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        endpoint = ENDPOINT_GET_REPORT.format(report_id=report_id)

        # retrieve report data
        ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        ret_val, vault_details = self._save_pcap_to_vault(resp_json, self.get_container_id(), action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(vault_details)

        return action_result.set_status(phantom.APP_SUCCESS, "PCAP file added successfully to the vault")

    def _save_pcap_to_vault(self, response, container_id, action_result):
        # get URL to pcap file
        try:
            pcap = response['pcap']
        except KeyError:
            return action_result.set_status(phantom.APP_ERROR, "Could not find PCAP file to download from report"), None

        filename = os.path.basename(urlsplit(pcap).path)

        # download file
        try:
            pcap_file = requests.get(pcap).content
        except:
            return action_result.set_status(phantom.APP_ERROR, "Could not download PCAP file"), None

        # Creating temporary directory and file
        try:
            if hasattr(phrules, 'get_vault_tmp_dir'):
                temp_dir = phrules.get_vault_tmp_dir()
            else:
                temp_dir = "/opt/phantom/vault/tmp/"
            temp_dir = temp_dir + '/{}'.format(uuid.uuid4())
            os.makedirs(temp_dir)
            file_path = os.path.join(temp_dir, filename)

            with open(file_path, 'wb') as file_obj:
                file_obj.write(pcap_file)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error while writing to temporary file", e), None

        # Adding pcap to vault
        vault_ret_dict = phrules.vault_add(container_id, file_path, filename)

        # Removing temporary directory created to download file
        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to remove temporary directory", e), None

        # Updating data with vault details
        if vault_ret_dict[0]:
            vault_details = {
                phantom.APP_JSON_VAULT_ID: vault_ret_dict[2],
                'file_name': filename
            }
            return phantom.APP_SUCCESS, vault_details

        # Error while adding report to vault
        self.debug_print('Error adding file to vault:', vault_ret_dict)
        action_result.append_to_message('. {}'.format(vault_ret_dict[1]))

        # Set the action_result status to error, the handler function will most probably return as is
        return phantom.APP_ERROR, None

    def _check_and_update_container_already_exists(self, incident_id, incident_name):

        url = '{0}rest/container?_filter_source_data_identifier="{1}"&_filter_asset={2}'.format(self.get_phantom_base_url(), incident_id, self.get_asset_id())

        try:
            r = requests.get(url, verify=False)
            resp_json = r.json()
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            self.debug_print("Unable to query ThreatStream incident container: {}".format(error_msg))
            return None

        if (resp_json.get('count', 0) <= 0):
            self.debug_print("No container matched")
            return None

        try:
            container_id = resp_json.get('data', [])[0]['id']
        except Exception as e:
            self.debug_print("Container results are not proper: ", e)
            return None

        # If the container exists and the name of the incident has been updated,
        # update the name of the container as well to stay in sync with the UI of ThreatStream
        if container_id and (resp_json.get('data', [])[0]['name'] != '{}-{}'.format(incident_id, incident_name)):
            url = '{0}rest/container/{1}'.format(self.get_phantom_base_url(), container_id)
            try:
                data = {"name": '{}-{}'.format(incident_id, incident_name)}
                r = requests.post(url, verify=False, json=data)
                resp_json = r.json()
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                self.debug_print("Unable to update the name of the ThreatStream incident container: {}".format(error_msg))
                return container_id

            if not resp_json.get('success'):
                self.debug_print("Container with ID: {0} could not be updated with the current incident_name: {1} of the incident ID: {2}".format(
                                    container_id, incident_name, incident_id))
                self.debug_print("Response of the container updation is: {0}".format(str(resp_json)))
                return container_id

        return container_id

    def _handle_on_poll(self, param):  # noqa
        action_result = self.add_action_result(ActionResult(dict(param)))
        config = self.get_config()

        org_id = config.get("organization_id")
        if org_id is None:
            return action_result.set_status(phantom.APP_ERROR, "Please set the organization ID config value before polling")

        self.save_progress("Retrieving incidents...")

        try:
            # Fetch the last fetched incident's ID in case of subsequent
            # polls for the scheduled polling
            start_ingestion_time = None

            if not self.is_poll_now() and self._state.get("first_run") is False:
                start_ingestion_time = self._state.get("last_incident_time")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching the incident ID of the last ingestion run. Error: {0}".format(str(e)))

        try:
            if self.is_poll_now():
                # Manual polling
                limit = param.get("container_count", 1000)
            elif self._state.get("first_run", True):
                # Scheduled polling first run
                limit = self._first_run_limit
                self._state["first_run"] = False
            else:
                # Poll every new update in the subsequent polls
                # of the scheduled_polling
                limit = None

            ret_val, limit = self._validate_integer(action_result, limit, THREATSTREAM_LIMIT)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching the number of containers to be ingested. Error: {0}"
                                            .format(self._get_error_message_from_exception(e)))

        if start_ingestion_time:
            payload = self._generate_payload(order_by="modified_ts", modified_ts__gte=start_ingestion_time)
        else:
            payload = self._generate_payload(order_by="modified_ts")

        incidents = []
        if limit:
            offset = 0
            while len(incidents) < limit:
                interim_incidents = self._paginator(ENDPOINT_INCIDENT, action_result, payload=payload, offset=offset, limit=DEFAULT_MAX_RESULTS)

                if interim_incidents is None:
                    return action_result.get_status()

                for incident in interim_incidents:
                    if incident.get("organization_id") == int(org_id):
                        incidents.append(incident)
                    else:
                        self.debug_print("Skipping incident ID: {0} due to organization ID: {1} being different than the configuration parameter organization_id: {2}".format(
                                    incident.get("id"), incident.get("organization_id"), org_id))

                if not interim_incidents:
                    break

                offset += DEFAULT_MAX_RESULTS

            # Fetch only the incidents equal to the number denoted by limit
            incidents = incidents[:limit]
        else:
            interim_incidents = self._paginator(ENDPOINT_INCIDENT, action_result, payload=payload, limit=limit)

            if interim_incidents is None:
                return action_result.get_status()

            for incident in interim_incidents:
                if incident.get("organization_id") == int(org_id):
                    incidents.append(incident)
                else:
                    self.debug_print("Skipping incident ID: {0} due organization ID: {1} being different than the configuration parameter organization_id: {2}".format(
                                incident.get("id"), incident.get("organization_id"), org_id))

        self.save_progress("Fetched {0} incidents in the oldest first order based on modified_ts time.".format(len(incidents)))
        self.save_progress("Started incident and intelligence artifacts creation...")

        for i, incident in enumerate(incidents):
            self.send_progress("Processing incident and corresponding intelligence artifacts - {} %".format(((i + 1) / len(incidents)) * 100))
            # self.send_progress("Processing containers and artifacts creation for the incident ID: {0}".format(incident.get("id")))
            # Handle the ingest_only_published_incidents scenario
            if config.get("ingest_only_published_incidents", False):
                if "published" != incident.get("publication_status"):
                    self.debug_print("Skipping incident ID: {0} because ingest_only_published_incidents configuration parameter is marked true".format(incident.get("id")))
                    continue

            self.debug_print("Retrieving details for the incident ID: {0}".format(incident.get("id")))

            ret_val, resp_json = self._get_incident_support(action_result, incident_id=incident["id"])

            if (not ret_val):
                return action_result.get_status()

            # Create the list of artifacts to be created
            artifacts_list = []
            intelligence = resp_json.pop("intelligence", [])

            for item in intelligence:
                artifact = {"label": "artifact",
                            "type": "network",
                            "name": "intelligence artifact",
                            "description": "Artifact added by ThreatStream App",
                            "source_data_identifier": item["id"]
                            }
                if item.get('tags'):
                    tags_dict = dict()
                    tags = item.get('tags')

                    for i, tag in enumerate(tags):
                        try:
                            tags_dict['tag_{}'.format(i + 1)] = '    ||    '.join('{} : {}'.format(
                                key, self._handle_py_ver_compat_for_input_str(value) if isinstance(value, basestring) else value) for key, value in tag.items())
                        except:
                            tags_dict['tag_{}'.format(i + 1)] = '    ||    '.join('{} : {}'.format(
                                key, self._handle_py_ver_compat_for_input_str(value) if isinstance(value, str) else value) for key, value in list(tag.items()))

                    item['tags_formatted'] = tags_dict

                artifact['cef'] = item
                artifact['cef_types'] = {'id': ["threatstream intelligence id"],
                                         'owner_organization_id': ["threatstream organization id"],
                                         'ip': ["ip"],
                                         'value': ["ip", "domain", "url", "email", "md5", "sha1", "hash"]
                                         }
                artifacts_list.append(artifact)

            artifact = {"label": "artifact",
                        "type": "network",
                        "name": "incident artifact",
                        "description": "Artifact added by ThreatStream App",
                        "source_data_identifier": resp_json["id"]
                        }

            if resp_json.get('tags_v2'):
                tags_dict = dict()
                tags = resp_json.get('tags_v2')

                for i, tag in enumerate(tags):
                    try:
                        tags_dict['tag_v2_{}'.format(i + 1)] = '    ||    '.join('{} : {}'.format(
                            key, self._handle_py_ver_compat_for_input_str(value) if isinstance(value, basestring) else value) for key, value in tag.items())
                    except:
                        tags_dict['tag_v2_{}'.format(i + 1)] = '    ||    '.join('{} : {}'.format(
                            key, self._handle_py_ver_compat_for_input_str(value) if isinstance(value, str) else value) for key, value in list(tag.items()))

                resp_json['tags_v2_formatted'] = tags_dict

            artifact['cef'] = resp_json
            artifact['cef_types'] = {'id': ["threatstream incident id"], 'organization_id': ["threatstream organization id"]}
            artifacts_list.append(artifact)

            existing_container_id = self._check_and_update_container_already_exists(resp_json.get("id"), self._handle_py_ver_compat_for_input_str(resp_json.get("name")))

            self.debug_print("Saving container and adding artifacts for the incident ID: {0}".format(resp_json.get("id")))

            if not existing_container_id:
                container = dict()
                container['description'] = "Container added by ThreatStream app"
                container['source_data_identifier'] = resp_json.get("id")
                container['name'] = '{}-{}'.format(resp_json.get("id"), self._handle_py_ver_compat_for_input_str(resp_json.get("name")))
                container['data'] = resp_json

                ret_val, message, container_id = self.save_container(container)

                if (phantom.is_fail(ret_val)):
                    message = "Failed to add container error msg: {0}".format(message)
                    self.debug_print(message)
                    return action_result.set_status(phantom.APP_ERROR, "Failed creating container")

                if (not container_id):
                    message = "save_container did not return a container_id"
                    self.debug_print(message)
                    return action_result.set_status(phantom.APP_ERROR, "Failed creating container")

                existing_container_id = container_id

            # Add the artifacts_list to either the created or
            # the existing container with ID in existing_container_id
            for artifact in artifacts_list:
                artifact['container_id'] = existing_container_id

            ret_val, message, _ = self.save_artifacts(artifacts_list)

            if (not ret_val):
                self.debug_print("Error while saving the artifact for the incident ID: {0}".format(resp_json.get("id")), message)
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while saving the artifact for the incident ID: {0}. Error message: {1}".format(
                                                    resp_json.get("id"), message))

        if not self.is_poll_now() and incidents:
            # 2019-08-14T11:37:01.113736 to 2019-08-14T11:37:01 conversion
            # The incidents are sorted in the ascending order
            last_incident_time = incidents[-1].get("modified_ts")
            if last_incident_time:
                self._state["last_incident_time"] = last_incident_time

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved and ingested the list of incidents")

    def _handle_import_session_search(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, offset = self._validate_integer(action_result, param.get("offset", 0), THREATSTREAM_OFFSET, True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        payload = self._generate_payload()
        status = param.get('status_in')

        if param.get('date_modified_gte'):
            payload["date_modified__gte"] = param.get('date_modified_gte')

        if status:
            status_list = [x.strip() for x in status.split(',')]
            status_list = list(filter(None, status_list))

            status = ",".join(status_list)
            payload["status__in"] = status

        import_sessions = self._paginator(ENDPOINT_IMPORT_SESSION, action_result, limit=limit, payload=payload, offset=offset)
        if import_sessions is None:
            return action_result.get_status()

        for import_session in import_sessions:
            action_result.add_data(import_session)

        summary = action_result.update_summary({})
        summary['import_sessions_returned'] = action_result.get_data_size()

        return phantom.APP_SUCCESS

    def _handle_import_session_update(self, param):  # noqa

        action_result = self.add_action_result(ActionResult(dict(param)))

        config = self.get_config()

        intelligence_source = param.get("intelligence_source")

        ret_val, item_id = self._validate_integer(action_result, param["item_id"], THREATSTREAM_ITEM_ID, True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        tlp = param.get("tlp")
        tags = param.get("tags")
        comment = param.get("comment")
        expire_time = param.get("expire_time")
        threat_model_type = param.get("threat_model_type")
        threat_model_to_associate = param.get("threat_model_to_associate")

        resp_json = {}
        messages = []

        updated = False

        if (threat_model_type or threat_model_to_associate) and not(threat_model_type and threat_model_to_associate):
            return action_result.set_status(phantom.APP_ERROR, "Please provide both 'threat_model_type' and 'threat_model_to_associate' parameters")
        if not(tlp or tags or comment or intelligence_source or expire_time) and not(threat_model_type and threat_model_to_associate):
            return action_result.set_status(phantom.APP_ERROR, "Please provide either 'tlp' or 'tags' or 'comment' or 'threat_model_type' and 'threat_model_associate' parameter")

        payload = self._generate_payload()
        if self._is_cloud_instance:
            payload["remote_api"] = "true"

        if tlp or intelligence_source or expire_time or (threat_model_type and threat_model_to_associate):
            data = {}
            threat_model_msg = ""
            param_list = []
            if tlp:
                data["tlp"] = tlp
                param_list.append("tlp")
            if intelligence_source:
                data["intelligence_source"] = intelligence_source
                param_list.append("intelligence_source")
            if expire_time:
                if expire_time == "null":
                    expire_time = None
                else:
                    try:
                        regex = r'^([0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])(T|\s{1})(2[0-3]|[01][0-9]):' \
                                r'([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?(Z|[+-](?:2[0-3]|[01][0-9])(:)?[0-5][0-9])?$'

                        match_iso8601 = re.compile(regex).match

                        if match_iso8601(expire_time) is None:
                            raise Exception

                        expire_time_date_obj = dateutil.parser.parse(expire_time)
                        try:
                            expire_time_utc_date_obj = expire_time_date_obj.astimezone(pytz.utc)
                        except ValueError:
                            expire_time_utc_date_obj = expire_time_date_obj.replace(tzinfo=dateutil.tz.tzutc())
                        expire_time_utc_date = expire_time_utc_date_obj.date()

                        current_time_utc_date_obj = datetime.datetime.utcnow().replace(tzinfo=dateutil.tz.tzutc())
                        current_time_utc_date = current_time_utc_date_obj.date()

                        if expire_time_utc_date < current_time_utc_date:
                            return action_result.set_status(phantom.APP_ERROR, "Invalid date. Please provide a date that is greater than or equal to the current date")
                    except:
                        pass
                data["expiration_ts"] = expire_time
                param_list.append("expire_time")
            if threat_model_type and threat_model_to_associate:
                threat_model_type_list = [x.strip() for x in threat_model_type.split(',')]
                threat_model_type_list = list(filter(None, threat_model_type_list))

                threat_model_to_associate_list = [x.strip() for x in threat_model_to_associate.split(',')]
                threat_model_to_associate_list = list(filter(None, threat_model_to_associate_list))

                if len(threat_model_to_associate_list) != len(threat_model_type_list):
                    return action_result.set_status(phantom.APP_ERROR,
                                                    "Please provide same number of values in 'threat_model_type_list' and 'threat_model_to_associate_list' parameters")

                for i, value in enumerate(threat_model_type_list):
                    if not data.get(value):
                        data[value] = [threat_model_to_associate_list[i]]
                    else:
                        data[value].append(threat_model_to_associate_list[i])

                threat_model_msg = "Request for association sent successfully. "

            endpoint = "{}{}/".format(ENDPOINT_IMPORT_SESSION, item_id)

            ret_val, resp_json = self._make_rest_call(action_result, endpoint=endpoint, payload=payload, headers=None, data=data, method='patch')
            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message() and payload.get("remote_api") != "true":
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, endpoint=endpoint, payload=payload, headers=None, data=data, method='patch')
            if (phantom.is_fail(ret_val)):
                msg = "{}Error: {}".format("Unable to update {}. ".format(param_list if param_list else ""), action_result.get_message())
                messages.append(msg)
            else:
                updated = True
                messages.append("{}{}".format(threat_model_msg, "Successfully updated {}".format(param_list) if param_list else ""))

        if tags:
            data = {}
            final_tags = []
            config = self.get_config()

            org_id = config.get("organization_id", None)

            tags_list = [x.strip() for x in tags.split(',')]
            tags_list = list(filter(None, tags_list))

            for tag in tags_list:
                final_tags.append({
                    "name": tag,
                    "org_id": org_id
                })

            data[THREATSTREAM_JSON_TAGS] = final_tags

            ret_val, resp_json = self._make_rest_call(action_result, endpoint=ENDPOINT_TAG_IMPORT_SESSION.format(session_id=item_id),
                                                      payload=payload, headers=None, data=data, method='post')
            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message() and payload.get("remote_api") != "true":
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, endpoint=ENDPOINT_TAG_IMPORT_SESSION.format(session_id=item_id),
                                                          payload=payload, headers=None, data=data, method='post')
            if (phantom.is_fail(ret_val)):
                messages.append("Unable to update the tags. Error: {}".format(action_result.get_message()))
            else:
                updated = True
                messages.append("Successfully updated tags")

        if comment:
            payload["default_comment"] = comment

            ret_val, resp_json = self._make_rest_call(action_result, endpoint=ENDPOINT_COMMENT_IMPORT_SESSION.format(session_id=item_id),
                                                      payload=payload, method='patch')
            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message() and payload.get("remote_api") != "true":
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, endpoint=ENDPOINT_COMMENT_IMPORT_SESSION.format(session_id=item_id),
                                                          payload=payload, method='patch')
            if (phantom.is_fail(ret_val)):
                messages.append("Unable to update the comment. Error: {}".format(action_result.get_message()))
            else:
                updated = True
                messages.append("Successfully updated comment")

        if not updated:
            return action_result.set_status(phantom.APP_ERROR, ". ".join(messages))

        endpoint = ENDPOINT_IMPORT_SESSION + "{}/".format(item_id)

        ret_val, resp_json = self._make_rest_call(action_result, endpoint=endpoint, payload=payload)
        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching the details. {}".format(". ".join(messages)))

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, ". ".join(messages))

    def _handle_threat_model_search(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        payload = self._generate_payload()

        if param.get('modified_ts__gte'):
            payload["modified_ts__gte"] = param.get('modified_ts__gte')

        if param.get("model_type"):
            payload["model_type"] = param.get('model_type')

        if param.get("tags_name"):
            payload["tags.name"] = param.get("tags_name")

        if param.get("publication_status"):
            payload["publication_status"] = param.get("publication_status")

        threat_models = self._paginator(ENDPOINT_THREAT_MODEL_SEARCH, action_result, limit=limit, payload=payload)

        if threat_models is None:
            return action_result.get_status()

        new_limit = limit - len(threat_models)

        if new_limit and not param.get("model_type"):
            payload["model_type"] = "vulnerability"

            vulnerability_threat_models = self._paginator(ENDPOINT_THREAT_MODEL_SEARCH, action_result, limit=new_limit, payload=payload)

            if vulnerability_threat_models is None:
                return action_result.get_status()

            threat_models.extend(vulnerability_threat_models)

        for threat_model in threat_models:
            action_result.add_data(threat_model)

        summary = action_result.update_summary({})
        summary['threat_models_returned'] = action_result.get_data_size()

        return phantom.APP_SUCCESS

    def _build_threatbulletin_data(self, param, data):
        source = param.get('source')
        tags = param.get('tags')
        tlp = param.get('tlp')
        assignee_user_id = param.get('assignee_user_id')
        body = param.get('body')
        circles = param.get('circles')

        if source:
            data.update({"source": source})

        if tags:
            tag = [x.strip() for x in tags.split(',')]
            tag = list(filter(None, tag))
            tags_to_insert = list()
            for value in tag:
                temp_tag = dict()
                temp_tag.update({"name": value})
                tags_to_insert.append(temp_tag)
            data.update({"tags_v2": tags_to_insert})

        if tlp:
            data.update({"tlp": tlp})

        if assignee_user_id:
            data.update({"assignee_user_id": assignee_user_id})

        if body:
            data.update({"body": body})

        if circles:
            circle_data = circles.strip().split(",")
            circle = list()
            for x in circle_data:
                if x.strip():
                    try:
                        circle.append(int(x.strip()))
                    except:
                        pass
            data.update({"circles": circle})

        return data

    def _handle_create_threat_bulletin(self, param):  # noqa

        action_result = self.add_action_result(ActionResult(dict(param)))
        comments = param.get('comments')
        if comments:
            comments = comments.encode("utf-8")
        import_sessions = param.get("import_sessions")
        attachments = param.get('attachments')
        create_on_cloud = param.get("create_on_cloud", False)
        local_intelligence = param.get("local_intelligence")
        cloud_intelligence = param.get("cloud_intelligence")

        if local_intelligence:
            local_intelligence = self._create_intelligence(action_result, local_intelligence)
            if local_intelligence is None:
                return local_intelligence

        if cloud_intelligence:
            cloud_intelligence = self._create_intelligence(action_result, cloud_intelligence)
            if cloud_intelligence is None:
                return cloud_intelligence

        data = {
                "name": param["name"],
                "is_public": param.get("is_public", False),
                "is_anonymous": param.get("is_anonymous", False),
                "status": param.get('status', "new"),
                "body_content_type": param.get('body_content_type', "markdown")
               }

        data = self._build_threatbulletin_data(param, data)

        if import_sessions:
            import_session_data = import_sessions.strip().split(",")
            session_data = [x.strip() for x in import_session_data if x.strip()]
            import_sessions = ','.join(session_data)

        payload = self._generate_payload()
        intelligence = list()
        output_message = None
        is_error = False

        if create_on_cloud or self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_THREAT_BULLETIN, payload, data=data, method="post")

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            threat_bulletin_id = resp_json.get("id")
            if not threat_bulletin_id:
                return action_result.set_status(phantom.APP_ERROR, "Error while fetching the threat bulletin ID of the created threat bulletin on the cloud")

            output_message = THREATSTREAM_SUCCESS_THREATBULLETIN_MESSAGE.format(threat_bulletin_id)

            if cloud_intelligence:
                intel_data = {"ids": cloud_intelligence}
                ret_val, response = self._make_rest_call(
                            action_result, ENDPOINT_THREAT_BULLETIN_ASSOCIATE_INTELLIGENCE.format(id=threat_bulletin_id), payload, data=intel_data, method="post")

                if phantom.is_fail(ret_val):
                    is_error = True
                    output_message = "{}. {}. Details: {}"\
                        .format(output_message, THREATSTREAM_ERR_INVALID_REMOTE_INTELLIGENCE.format(', '.join(cloud_intelligence)), action_result.get_message())

                if response and response.get("ids"):
                    intelligence.extend(response.get("ids"))

            if local_intelligence and create_on_cloud:
                del payload["remote_api"]
                intel_data = {"local_ids": local_intelligence}
                ret_val, response = self._make_rest_call(
                            action_result, ENDPOINT_THREAT_BULLETIN_ASSOCIATE_INTELLIGENCE.format(id=threat_bulletin_id), payload, data=intel_data, method="post")

                if phantom.is_fail(ret_val):
                    is_error = True
                    output_message = "{}. {}. Details: {}"\
                        .format(output_message, THREATSTREAM_ERR_INVALID_LOCAL_INTELLIGENCE.format(', '.join(local_intelligence)), action_result.get_message())

                if response and response.get("local_ids"):
                    intelligence.extend(response.get("local_ids"))

        else:
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_THREAT_BULLETIN, payload, data=data, method="post")

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            threat_bulletin_id = resp_json.get("id")
            if not threat_bulletin_id:
                return action_result.set_status(phantom.APP_ERROR, "Error while fetching the threat bulletin ID of the created threat bulletin on the on-prem")

            output_message = THREATSTREAM_SUCCESS_THREATBULLETIN_MESSAGE.format(threat_bulletin_id)

            intel_data = dict()

            if local_intelligence:
                intel_data["ids"] = local_intelligence
            if cloud_intelligence:
                intel_data["remote_ids"] = cloud_intelligence

            if intel_data:
                ret_val, response = self._make_rest_call(
                            action_result, ENDPOINT_THREAT_BULLETIN_ASSOCIATE_INTELLIGENCE.format(id=threat_bulletin_id), payload, data=intel_data, method="post")

                if phantom.is_fail(ret_val):
                    is_error = True
                    output_message = "{}. Error while adding intelligence to the threat bulletin. Details: {}".format(output_message, action_result.get_message())

                if response and response.get("remote_ids"):
                    intelligence.extend(response.get("remote_ids"))

                if response and response.get("ids"):
                    intelligence.extend(response.get("ids"))

        intel_list = list()

        if intelligence:
            msg_intel = list()
            for intel_value in intelligence:
                intel_id_dict = dict()
                intel_id_dict["id"] = intel_value
                intel_list.append(intel_id_dict)
                msg_intel.append(str(intel_value))

            resp_json["intelligence"] = intel_list

            message = "Threat bulletin created successfully. Associated intelligence : {}".format(', '.join(msg_intel))

        elif (local_intelligence or cloud_intelligence):
            message = "Threat bulletin created successfully. None of the intelligence got associated, please provide valid intelligence"

        else:
            message = "Threat bulletin created successfully"

        if attachments:
            ret_val, resp_json = self._add_threat_bulletin_attachment(action_result, attachments, threat_bulletin_id, payload, resp_json)
            if phantom.is_fail(ret_val):
                is_error = True
                output_message = "{}. Error while adding attachments to the threat bulletin. Details: {}".format(output_message, action_result.get_message())

        if import_sessions:
            ret_val, resp_json = self._add_threat_bulletin_sessions(action_result, import_sessions, threat_bulletin_id, payload, resp_json)

            if phantom.is_fail(ret_val):
                is_error = True
                output_message = "{}. Error while adding import sessions to the threat bulletin. Details: {}".format(output_message, action_result.get_message())

        if comments:
            ret_val, response = self.add_comment(action_result, comments, "tipreport", threat_bulletin_id, payload)
            if phantom.is_fail(ret_val):
                is_error = True
                output_message = "{}. Error while adding comments to the threat bulletin. Details: {}".format(output_message, action_result.get_message())

            if not phantom.is_fail(ret_val):
                if resp_json['comments']:
                    resp_json['comments'].append(response)
                else:
                    resp_json.update({"comments": response})

        action_result.add_data(resp_json)
        if is_error:
            return action_result.set_status(phantom.APP_ERROR, output_message)

        summary = action_result.update_summary({})
        summary['created_on_cloud'] = create_on_cloud or self._is_cloud_instance
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_update_threat_bulletin(self, param):  # noqa

        action_result = self.add_action_result(ActionResult(dict(param)))

        threat_bulletin_id = param.get('id')
        status = param.get("status")
        comments = param.get('comments')
        if comments:
            comments = comments.encode("utf-8")
        import_sessions = param.get('import_sessions')
        attachments = param.get('attachments')
        local_intelligence = param.get("local_intelligence")
        cloud_intelligence = param.get("cloud_intelligence")

        if local_intelligence:
            local_intelligence = self._create_intelligence(action_result, local_intelligence)
            if local_intelligence is None:
                return local_intelligence

        if cloud_intelligence:
            cloud_intelligence = self._create_intelligence(action_result, cloud_intelligence)
            if cloud_intelligence is None:
                return cloud_intelligence

        data = {
                "is_public": param.get("is_public", False),
                "is_anonymous": param.get("is_anonymous", False)
               }

        data = self._build_threatbulletin_data(param, data)

        if status:
            data.update({"status": status})

        if import_sessions:
            import_session_data = import_sessions.strip().split(",")
            session_data = [x.strip() for x in import_session_data if x.strip()]
            import_sessions = ','.join(session_data)

        payload = self._generate_payload()
        intel_ids_list = list()
        associated_intell = list()
        message = None
        output_message = None
        is_error = False

        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_UPDATE_THREAT_BULLETIN.format(id=threat_bulletin_id), payload)

        if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_UPDATE_THREAT_BULLETIN.format(id=threat_bulletin_id), payload)
            del payload['remote_api']

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for intell in resp_json.get("intelligence", []):
            associated_intell.append(int(intell.get("id")))

        if self._is_cloud_instance:
            if cloud_intelligence:
                data.update({"intelligence": cloud_intelligence})
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_UPDATE_THREAT_BULLETIN.format(id=threat_bulletin_id), payload, data=data, method="patch")
        else:

            if local_intelligence or cloud_intelligence:
                intel_data = dict()
                if local_intelligence:
                    intel_data["ids"] = local_intelligence

                if cloud_intelligence:
                    intel_data["remote_ids"] = cloud_intelligence

                ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_THREAT_BULLETIN_ASSOCIATE_INTELLIGENCE.format(id=threat_bulletin_id), payload,
                                                          data=intel_data, method="post")

                if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                    intel_data = dict()
                    if local_intelligence:
                        intel_data["local_ids"] = local_intelligence

                        ret_val, resp_json = self._make_rest_call(
                            action_result, ENDPOINT_THREAT_BULLETIN_ASSOCIATE_INTELLIGENCE.format(id=threat_bulletin_id), payload, data=intel_data, method="post")

                        if phantom.is_fail(ret_val):
                            is_error = True
                            if output_message:
                                output_message = "{}. {}. Details: {}"\
                                    .format(output_message, THREATSTREAM_ERR_INVALID_LOCAL_INTELLIGENCE.format(', '.join(local_intelligence)), action_result.get_message())
                            else:
                                output_message = "{}. Details: {}"\
                                    .format(THREATSTREAM_ERR_INVALID_LOCAL_INTELLIGENCE.format(', '.join(local_intelligence)), action_result.get_message())
                        del intel_data["local_ids"]
                        if resp_json and resp_json.get("local_ids"):
                            intel_ids_list.extend(resp_json.get("local_ids"))

                    if cloud_intelligence:
                        intel_data["ids"] = cloud_intelligence
                        payload["remote_api"] = "true"
                        ret_val, resp_json = self._make_rest_call(
                            action_result, ENDPOINT_THREAT_BULLETIN_ASSOCIATE_INTELLIGENCE.format(id=threat_bulletin_id), payload, data=intel_data, method="post")

                        if phantom.is_fail(ret_val):
                            is_error = True
                            if output_message:
                                output_message = "{}. {}. Details: {}"\
                                    .format(output_message, THREATSTREAM_ERR_INVALID_REMOTE_INTELLIGENCE.format(', '.join(cloud_intelligence)), action_result.get_message())
                            else:
                                output_message = "{}. Details: {}"\
                                    .format(THREATSTREAM_ERR_INVALID_REMOTE_INTELLIGENCE.format(', '.join(cloud_intelligence)), action_result.get_message())

                if phantom.is_fail(ret_val):
                    is_error = True
                    if output_message:
                        output_message = "{}. Error while updating the threat bulletin. Details: {}".format(output_message, action_result.get_message())
                    else:
                        output_message = "Error while updating the threat bulletin. Details: {}".format(action_result.get_message())

                if resp_json and resp_json.get("ids"):
                    intel_ids_list.extend(resp_json.get("ids"))
                if resp_json and resp_json.get("remote_ids"):
                    intel_ids_list.extend(resp_json.get("remote_ids"))

            if intel_ids_list:
                msg_intel = list()
                for intel_value in intel_ids_list:
                    msg_intel.append(str(intel_value))

                message = "Associated intelligence : {}".format(', '.join(msg_intel))

            elif (local_intelligence or cloud_intelligence):
                message = THREATSTREAM_ERR_INVALID_INTELLIGENCE

            else:
                message = None

            if associated_intell:
                intel_ids_list.extend(associated_intell)

            # Update the incident in all cases with data or with empty data to get the latest intelligence values associated with it
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_UPDATE_THREAT_BULLETIN.format(id=threat_bulletin_id), payload, data=data, method="patch")

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_UPDATE_THREAT_BULLETIN.format(id=threat_bulletin_id), payload, data=data, method="patch")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        intel_list = list()

        intel_ids_list = list(set(intel_ids_list))

        if intel_ids_list:
            for intel_value in intel_ids_list:
                intel_id_dict = dict()
                intel_id_dict["id"] = intel_value
                intel_list.append(intel_id_dict)

            resp_json["intelligence"] = intel_list

        if attachments:
            ret_val, resp_json = self._add_threat_bulletin_attachment(action_result, attachments, threat_bulletin_id, payload, resp_json)
            if phantom.is_fail(ret_val):
                is_error = True
                if output_message:
                    output_message = "{}. Error while updating attachments to the threat bulletin. Details: {}".format(output_message, action_result.get_message())
                else:
                    output_message = "Error while updating attachments to the threat bulletin. Details: {}".format(action_result.get_message())

        if import_sessions:
            ret_val, resp_json = self._add_threat_bulletin_sessions(action_result, import_sessions, threat_bulletin_id, payload, resp_json)

            if phantom.is_fail(ret_val):
                is_error = True
                if output_message:
                    output_message = "{}. Error while updating import sessions to the threat bulletin. Details: {}".format(output_message, action_result.get_message())
                else:
                    output_message = "Error while updating import sessions to the threat bulletin. Details: {}".format(action_result.get_message())

        if comments:
            ret_val, response = self.add_comment(action_result, comments, "tipreport", threat_bulletin_id, payload)
            if phantom.is_fail(ret_val):
                is_error = True
                if output_message:
                    output_message = "{}. Error while updating comments to the threat bulletin. Details: {}".format(output_message, action_result.get_message())
                else:
                    output_message = "Error while updating comments to the threat bulletin. Details: {}".format(action_result.get_message())

            if not phantom.is_fail(ret_val):
                if resp_json['comments']:
                    resp_json['comments'].append(response)
                else:
                    resp_json.update({"comments": response})

        action_result.add_data(resp_json)
        if is_error:
            return action_result.set_status(phantom.APP_ERROR, output_message)

        if message:
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated threat bulletin. {}".format(message))
        else:
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated threat bulletin")

    def _handle_delete_threat_bulletin(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, threat_bulletin_id = self._validate_integer(action_result, param["threat_bulletin_id"], THREATSTREAM_THREAT_BULLETIN_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        payload = self._generate_payload()

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result,
                                                      ENDPOINT_UPDATE_THREAT_BULLETIN.format(id=threat_bulletin_id), payload,
                                                      method="delete")
        else:
            ret_val, resp_json = self._make_rest_call(action_result,
                                                      ENDPOINT_UPDATE_THREAT_BULLETIN.format(id=threat_bulletin_id), payload,
                                                      method="delete")

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result,
                                                          ENDPOINT_UPDATE_THREAT_BULLETIN.format(id=threat_bulletin_id), payload,
                                                          method="delete")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted threat bulletin")

    def _handle_list_threat_bulletins(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        payload = self._generate_payload()

        if param.get("name"):
            payload["name"] = param.get("name")

        if param.get("status"):
            payload["status"] = param.get("status")

        if param.get("source"):
            payload["source"] = param.get("source")

        if param.get("tlp"):
            payload["tlp"] = param["tlp"]

        if param.get("is_public") in ["true", "false"]:
            payload["is_public"] = param.get("is_public")

        if param.get("assignee_user_id", None):
            payload["assignee_user_id"] = param.get("assignee_user_id")

        threat_bulletins = self._paginator(ENDPOINT_THREAT_BULLETIN, action_result, payload=payload, limit=limit)

        if threat_bulletins is None:
            return action_result.get_status()

        for bulletin in threat_bulletins:
            action_result.add_data(bulletin)

        summary = action_result.update_summary({})
        summary['threat_bulletins_returned'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_associations(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        payload = self._generate_payload()

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            associations = self._paginator(
                ENDPOINT_FETCH_ENTITIES.format(entity_type=param.get('entity_type'), id=param.get('entity_id'), associated_entity_type=param.get('associated_entity_type')),
                action_result, payload=payload, limit=limit)
        else:
            associations = self._paginator(
                ENDPOINT_FETCH_ENTITIES.format(entity_type=param.get('entity_type'), id=param.get('entity_id'), associated_entity_type=param.get('associated_entity_type')),
                action_result, payload=payload, limit=limit)

            if "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                associations = self._paginator(
                    ENDPOINT_FETCH_ENTITIES.format(entity_type=param.get('entity_type'), id=param.get('entity_id'), associated_entity_type=param.get('associated_entity_type')),
                    action_result, payload=payload, limit=limit)

        if associations is None:
            return action_result.get_status()

        for association in associations:
            action_result.add_data(association)

        summary = action_result.update_summary({})
        summary['associations_returned'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_association(self, param, endpoint):  # noqa

        action_result = self.add_action_result(ActionResult(dict(param)))

        entity_type = param['entity_type']
        entity_id = param['entity_id']
        ass_entity_type = param['associated_entity_type']

        local_ids = param.get("local_ids")
        remote_ids = param.get("remote_ids")

        if not local_ids and not remote_ids:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_MISSING_LOCAL_REMOTE_ID)

        if local_ids:
            local_ids = self._create_intelligence(action_result, local_ids)
            if local_ids is None:
                return local_ids

        if remote_ids:
            remote_ids = self._create_intelligence(action_result, remote_ids)
            if remote_ids is None:
                return remote_ids

        payload = self._generate_payload()
        intel_ids_list = list()
        message = None
        data = {}

        if self._is_cloud_instance:
            if remote_ids:
                data.update({"ids": remote_ids})
                ret_val, resp_json = self._make_rest_call(
                    action_result, endpoint.format(entity_type=entity_type, entity_id=entity_id, associated_entity_type=ass_entity_type),
                    payload, data=data, method="post")

                if phantom.is_fail(ret_val) and "Status Code: 405" in action_result.get_message():
                    return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_API_INVALID_VALUE)

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                if resp_json.get("ids"):
                    intel_ids_list.extend(resp_json.get("ids"))
        else:

            if local_ids or remote_ids:
                intel_data = dict()
                if local_ids:
                    intel_data["ids"] = local_ids

                if remote_ids:
                    intel_data["remote_ids"] = remote_ids

                ret_val, resp_json = self._make_rest_call(action_result, endpoint.format(entity_type=entity_type, entity_id=entity_id, associated_entity_type=ass_entity_type),
                                                          payload, data=intel_data, method="post")

                if phantom.is_fail(ret_val) and "Status Code: 405" in action_result.get_message():
                    return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_API_INVALID_VALUE)

                if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                    intel_data = dict()
                    if local_ids:
                        intel_data["local_ids"] = local_ids

                        ret_val, resp_json = self._make_rest_call(
                            action_result, endpoint.format(entity_type=entity_type, entity_id=entity_id, associated_entity_type=ass_entity_type),
                            payload, data=intel_data, method="post")

                        if phantom.is_fail(ret_val) and "Status Code: 405" in action_result.get_message():
                            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_API_INVALID_VALUE)

                        if phantom.is_fail(ret_val):
                            self.debug_print(THREATSTREAM_ERR_INVALID_LOCAL_INTELLIGENCE.format(
                                ', '.join(local_ids)))
                        del intel_data["local_ids"]
                        if resp_json and resp_json.get("local_ids"):
                            intel_ids_list.extend(resp_json.get("local_ids"))

                    if remote_ids:
                        intel_data["ids"] = remote_ids
                        payload["remote_api"] = "true"
                        ret_val, resp_json = self._make_rest_call(
                            action_result, endpoint.format(entity_type=entity_type, entity_id=entity_id, associated_entity_type=ass_entity_type),
                            payload, data=intel_data, method="post")

                        if phantom.is_fail(ret_val) and "Status Code: 405" in action_result.get_message():
                            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_API_INVALID_VALUE)

                        if phantom.is_fail(ret_val):
                            return action_result.get_status()

                if phantom.is_fail(ret_val):
                    return action_result.get_status()

                if resp_json.get("ids"):
                    intel_ids_list.extend(resp_json.get("ids"))
                if resp_json.get("remote_ids"):
                    intel_ids_list.extend(resp_json.get("remote_ids"))

        if intel_ids_list:
            msg_intel = list()
            for intel_value in intel_ids_list:
                msg_intel.append(str(intel_value))

            message = "Modified entities : {}".format(', '.join(msg_intel))

        elif (local_ids or remote_ids) and not intel_ids_list:
            message = "None of the entities got modified, please provide valid entities"

        else:
            message = None

        if intel_ids_list:
            action_result.add_data(msg_intel)
        else:
            action_result.add_data(list())

        if message == "None of the entities got modified, please provide valid entities":
            return action_result.set_status(phantom.APP_SUCCESS, "{}. Please check for the non-modified ids as they would be already associated or invalid".format(message))
        elif message:
            return action_result.set_status(phantom.APP_SUCCESS,
                                            "Successfully updated associations. {}. Please check for the non-modified ids as they would be already associated or invalid".format(
                                                message))
        else:
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated associations")

    def _handle_add_association(self, param):

        endpoint = ENDPOINT_ADD_ASSOCIATION
        return self._handle_association(param, endpoint)

    def _handle_remove_association(self, param):

        endpoint = ENDPOINT_REMOVE_ASSOCIATION
        return self._handle_association(param, endpoint)

    def _build_data_rule_action(self, action_result, data, param):
        # Preparing data dictionary
        if param.get("fields"):
            try:
                fields = ast.literal_eval(param["fields"])
            except Exception as e:
                error_msg = self._get_error_message_from_exception(e)
                action_result.set_status(
                    phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_JSON_WITH_PARAM.format(error_msg))
                return None

            if not isinstance(fields, dict):
                action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_JSON)
                return None

            resp_json = None
            if self.get_action_identifier() == self.ACTION_UPDATE_RULE:
                ret_val, resp_json = self._get_rule_support(action_result, param)

                if phantom.is_fail(ret_val):
                    return None

            validation_list = ["tags", "match_impacts", "actors", "campaigns", "incidents", "malware", "signatures",
                               "tips", "ttps", "vulnerabilities", "keywords"]

            for list_value in validation_list:
                fields_value = fields.get(list_value, '')
                if fields_value and not isinstance(fields_value, list):
                    action_result.set_status(phantom.APP_ERROR,
                                             THREATSTREAM_ERR_INVALID_FIELD_PARAM_VALUE.format(fields_value))
                    return None

                if fields_value and self.get_action_identifier() == self.ACTION_UPDATE_RULE:
                    try:
                        existing_value_list = resp_json.get(list_value, [])

                        # In case of str, append values and remove duplicates values
                        if list_value in ["keywords", "match_impacts"]:
                            existing_value = existing_value_list
                            existing_value.extend(fields_value)
                            existing_value = list(set(existing_value))
                        elif list_value == "tags":
                            existing_value_list.extend(fields_value)
                            existing_value = []
                            for i in range(0, len(existing_value_list)):
                                if existing_value_list[i] not in existing_value_list[i + 1:]:
                                    existing_value.append(existing_value_list[i])
                        else:
                            # In case of dict, get id from dict and remove duplicates
                            existing_value = [int(value.get('id')) for value in existing_value_list]
                            existing_value.extend(fields_value)
                            existing_value = list(set(existing_value))

                        fields[list_value] = existing_value
                    except Exception as e:
                        action_result.set_status(phantom.APP_ERROR, self._get_error_message_from_exception(e))
                        return None

            data.update(fields)

        return data

    def _get_rule_support(self, action_result, param=None, payload=None, rule_id=None):

        if payload and payload.get("remote_api") is not None:
            del payload["remote_api"]

        if not payload:
            payload = self._generate_payload()

        if param:
            rule_id = param['rule_id']

        ret_val, rule_id = self._validate_integer(action_result, rule_id, THREATSTREAM_RULE_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result,
                                                      ENDPOINT_SINGLE_RULE.format(rule_id=rule_id), payload)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None
        else:
            ret_val, resp_json = self._make_rest_call(action_result,
                                                      ENDPOINT_SINGLE_RULE.format(rule_id=rule_id), payload)

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result,
                                                          ENDPOINT_SINGLE_RULE.format(rule_id=rule_id), payload)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

        action_result.set_status(phantom.APP_SUCCESS)

        return phantom.APP_SUCCESS, resp_json

    def _handle_create_rule(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        create_on_cloud = param.get("create_on_cloud", False)

        try:
            keywords = ast.literal_eval(param["keywords"])
        except Exception as e:
            error_msg = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, error_msg)

        if not isinstance(keywords, list):
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_KEYWORDS_PARAM)

        data = {
            "name": param["name"],
            "keywords": keywords,
            "keyword": ",".join(keywords),
            "match_observables": False,
            "match_reportedfiles": False,
            "match_signatures": False,
            "match_tips": False,
            "match_vulnerabilities": False
        }

        data = self._build_data_rule_action(action_result, data, param)

        if data is None:
            return action_result.get_status()

        payload = self._generate_payload()

        if self._is_cloud_instance or create_on_cloud:
            payload["remote_api"] = "true"

        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_CREATE_RULE, payload, data=data,
                                                  method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        rule_id = resp_json.get("id")

        if not rule_id:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_RULE_ID_NOT_FOUND)

        # get call to retrieve actual json to display
        ret_val, resp_json = self._get_rule_support(action_result, payload=payload, rule_id=rule_id)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        message = "Rule is created successfully."

        action_result.add_data(resp_json)
        summary = action_result.update_summary({})
        summary['id'] = rule_id
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_update_rule(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, rule_id = self._validate_integer(action_result, param["rule_id"], THREATSTREAM_RULE_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        data = self._build_data_rule_action(action_result, data={}, param=param)

        if data is None:
            return action_result.get_status()

        payload = self._generate_payload()

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_RULE.format(rule_id=rule_id),
                                                      payload, data=data, method="patch")
        else:
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_RULE.format(rule_id=rule_id),
                                                      payload, data=data, method="patch")
            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_RULE.format(rule_id=rule_id),
                                                          payload, data=data, method="patch")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # get call to retrieve actual json to display
        ret_val, resp_json = self._get_rule_support(action_result, payload=payload, rule_id=rule_id)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        message = "Successfully updated rule"
        summary = action_result.update_summary({})
        summary['id'] = rule_id
        summary['message'] = message
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_list_rules(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        payload = self._generate_payload(order_by="-created_ts")

        rules = self._paginator(ENDPOINT_LIST_RULES, action_result, payload=payload, limit=limit)

        if rules is None:
            return action_result.get_status()

        for rule in rules:
            action_result.add_data(rule)

        summary = action_result.update_summary({})
        summary['rules_returned'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_delete_rule(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, rule_id = self._validate_integer(action_result, param["rule_id"], THREATSTREAM_RULE_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        payload = self._generate_payload()

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result,
                                                      ENDPOINT_SINGLE_RULE.format(rule_id=rule_id), payload,
                                                      method="delete")
        else:
            ret_val, resp_json = self._make_rest_call(action_result,
                                                      ENDPOINT_SINGLE_RULE.format(rule_id=rule_id), payload,
                                                      method="delete")

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result,
                                                          ENDPOINT_SINGLE_RULE.format(rule_id=rule_id), payload,
                                                          method="delete")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted rule")

    def _handle_list_actors(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        payload = self._generate_payload(order_by="-created_ts")

        actors = self._paginator(ENDPOINT_LIST_ACTORS, action_result, payload=payload, limit=limit)

        if actors is None:
            return action_result.get_status()

        for actor in actors:
            action_result.add_data(actor)

        summary = action_result.update_summary({})
        summary['actors_returned'] = action_result.get_data_size()

    def _handle_delete_actor(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, actor_id = self._validate_integer(action_result, param["actor_id"], THREATSTREAM_ACTOR_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        payload = self._generate_payload()

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result,
                                                      ENDPOINT_SINGLE_ACTOR.format(actor_id=actor_id), payload,
                                                      method="delete")
        else:
            ret_val, resp_json = self._make_rest_call(action_result,
                                                      ENDPOINT_SINGLE_ACTOR.format(actor_id=actor_id), payload,
                                                      method="delete")

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result,
                                                          ENDPOINT_SINGLE_ACTOR.format(actor_id=actor_id), payload,
                                                          method="delete")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted actor")

    def _handle_list_import(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        payload = self._generate_payload()

        payload['limit'] = limit

        if param.get("status"):
            status_map = {
                "Approved": "approved",
                "Ready To Review": "done",
                "Errors": "errors",
                "Rejected": "deleted",
                "Processing": "processing,approving,rejecting"
            }

            status = param["status"]

            payload["status"] = status_map[status]

        if param.get("list_from_remote"):
            payload["remote_api"] = "true"

        returned_imports = self._paginator(ENDPOINT_IMPORT, action_result, payload=payload, limit=limit)

        if returned_imports is None:
            return action_result.get_status()

        reversed_status_map = {
            "approved": "Approved",
            "done": "Ready To Review",
            "errors": "Errors",
            "deleted": "Rejected"
        }

        for imports in returned_imports:
            status = imports.get("status")
            if status in reversed_status_map:
                imports["status"] = reversed_status_map[status]
            else:
                imports["status"] = "Processing"

        for imports in returned_imports:
            action_result.add_data(imports)

        summary = action_result.update_summary({})
        summary['import_returned'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _validate_data(self, action_result, data):
        validation_list = ['circles', 'aliases', 'campaigns', 'incidents', 'vulnerability', 'signatures', 'tags', 'ttps', 'victims']

        for list_value in validation_list:
            fields_value = data.get(list_value, '')
            if fields_value and not isinstance(fields_value, list):
                action_result.set_status(phantom.APP_ERROR,
                                         THREATSTREAM_ERR_INVALID_FIELD_PARAM_VALUE.format(list_value))
                return None
        return data

    def add_attachment(self, action_result, attachment, entity_type, entity_id, payload, resp_json):
        try:
            file_id = self._handle_py_ver_compat_for_input_str(attachment)
            _, _, file_info = phrules.vault_info(vault_id=file_id)
            file_info = list(file_info)[0]
        except IndexError:
            return action_result.set_status(phantom.APP_ERROR, "Vault file could not be found with supplied Vault ID"), resp_json
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR,
                                            "Vault ID not valid: {}".format(self._get_error_message_from_exception(e))), resp_json

        use_json = False
        file_data = dict()
        files = {
            "attachment": (file_info.get('name'), open(file_info.get('path'), 'rb'), 'application/octet-stream')
        }
        file_data.update({"filename": file_info.get('name'),
                          "title": file_info.get('name'),
                          "r_type": "A"})

        ret_val, response = self._make_rest_call(action_result, ENDPOINT_ADD_ATTACHMENT.format(entity_type=entity_type, entity_id=entity_id), payload=payload,
                                                 files=files, data=file_data, method="post", use_json=use_json)

        if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
            payload["remote_api"] = "true"
            ret_val, response = self._make_rest_call(action_result,
                                                     ENDPOINT_ADD_ATTACHMENT.format(entity_type=entity_type, entity_id=entity_id), payload=payload,
                                                     files=files, data=file_data, method="post", use_json=use_json)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), resp_json

        resp_json.update({"attachments": response})

        return action_result.set_status(phantom.APP_SUCCESS, "Attachment created successfully"), resp_json

    def _add_threat_bulletin_sessions(self, action_result, import_sessions, threat_bulletin_id, payload, resp_json):
        payload.update({"ids": import_sessions, "operation": "add"})
        ret_val, response = self._make_rest_call(action_result, ENDPOINT_IMPORT_SESSIONS_THREAT_BULLETIN.format(id=threat_bulletin_id), payload=payload,
                                                method="patch", use_json=False)

        if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
            payload["remote_api"] = "true"
            ret_val, response = self._make_rest_call(action_result, ENDPOINT_IMPORT_SESSIONS_THREAT_BULLETIN.format(id=threat_bulletin_id), payload=payload,
                                                    method="patch", use_json=False)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), resp_json

        resp_json.update({"import_sessions": response["ids"]})

        return action_result.set_status(phantom.APP_SUCCESS, "Import sessions attached successfully"), resp_json

    def _add_threat_bulletin_attachment(self, action_result, attachments, threat_bulletin_id, payload, resp_json):
        try:
            file_id = self._handle_py_ver_compat_for_input_str(attachments)
            _, _, file_info = phrules.vault_info(vault_id=file_id)
            file_info = list(file_info)[0]
        except IndexError:
            return action_result.set_status(phantom.APP_ERROR, "Vault file could not be found with supplied Vault ID"), resp_json
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Vault ID not valid: {}".format(self._get_error_message_from_exception(e))), resp_json

        use_json = False
        file_data = dict()
        files = {
            "attachment": (file_info.get('name'), open(file_info.get('path'), 'rb'), 'application/octet-stream')
        }
        file_data.update({"filename": file_info.get('name')})

        ret_val, response = self._make_rest_call(action_result, ENDPOINT_ATTACHMENT_THREAT_BULLETIN.format(id=threat_bulletin_id), payload=payload,
                                                 files=files, data=file_data, method="post", use_json=use_json)

        if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
            payload["remote_api"] = "true"
            ret_val, response = self._make_rest_call(action_result, ENDPOINT_ATTACHMENT_THREAT_BULLETIN.format(id=threat_bulletin_id), payload=payload,
                                                     files=files, data=file_data, method="post", use_json=use_json)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), resp_json

        resp_json.update({"attachments": response})

        return action_result.set_status(phantom.APP_SUCCESS, "Attachment attached successfully"), resp_json

    def add_comment(self, action_result, comment, entity_type, entity_id, payload):
        ret_val, response = self._make_rest_call(action_result, ENDPOINT_ADD_COMMENT.format(entity_type=entity_type,
                                                                                            entity_id=entity_id),
                                                 payload=payload,
                                                 data=comment, method="post", use_json=False)

        if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
            payload["remote_api"] = "true"
            ret_val, response = self._make_rest_call(action_result, ENDPOINT_ADD_COMMENT.format(entity_type=entity_type,
                                                                                                entity_id=entity_id),
                                                     payload=payload,
                                                     data=comment, method="post", use_json=False)

        if phantom.is_fail(ret_val):
            return action_result.get_status(), None

        return action_result.set_status(phantom.APP_SUCCESS, "Comments added successfully"), response

    def _get_request_threat_model(self, action_result, payload=None, entity_type=None, entity_id=None):
        if payload and payload.get("remote_api") is not None:
            del payload["remote_api"]

        if not payload:
            payload = self._generate_payload()

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result,
                                                      ENDPOINT_GET_SINGLE_THREAT_MODEL.format(entity_type=entity_type, entity_id=entity_id), payload)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None
        else:
            ret_val, resp_json = self._make_rest_call(action_result,
                                                      ENDPOINT_GET_SINGLE_THREAT_MODEL.format(entity_type=entity_type, entity_id=entity_id), payload)

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result,
                                                          ENDPOINT_GET_SINGLE_THREAT_MODEL.format(entity_type=entity_type, entity_id=entity_id), payload)

            if phantom.is_fail(ret_val):
                return action_result.get_status(), None

        action_result.set_status(phantom.APP_SUCCESS, "")

        return phantom.APP_SUCCESS, resp_json

    def _create_and_get_threat_model(self, action_result, endpoint, payload, data, entity_type):
        ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, data=data, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status(), "", ""

        entity_id = resp_json.get("id")

        # get call to display result in data
        ret_val, resp_json = self._get_request_threat_model(action_result, payload, entity_type, entity_id)
        if phantom.is_fail(ret_val):
            return action_result.get_status(), "", ""

        return ret_val, resp_json, entity_id

    def _create_threat_model(self, action_result, param, endpoint, entity_type):  # noqa
        create_on_cloud = param.get("create_on_cloud", False)

        data = {
            "name": param["name"],
            "is_public": param.get("is_public", False),
            "publication_status": "new"
        }

        data_dict = self._build_data(param, data, action_result)
        if data_dict is None:
            return action_result.get_status()

        data = data_dict.get("data")
        data = self._validate_data(action_result, data)
        if data is None:
            return action_result.get_status()

        local_intelligence = data_dict.get("local_intelligence")
        cloud_intelligence = data_dict.get("cloud_intelligence")
        attachment = param.get("attachment")
        comment = param.get("comment")

        payload = self._generate_payload()
        intelligence = list()
        is_error = False

        if self._is_cloud_instance:
            if cloud_intelligence:
                data.update({"intelligence": cloud_intelligence})
            payload["remote_api"] = "true"

            ret_val, resp_json, entity_id = self._create_and_get_threat_model(action_result, endpoint, payload, data, entity_type)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            for intel in resp_json.get("intelligence", []):
                intelligence.append(intel.get("id"))

            output_message = THREATSTREAM_SUCCESS_THREATMODEL_MESSAGE.format(entity_type, entity_id)

        elif create_on_cloud:
            payload["remote_api"] = "true"

            ret_val, resp_json, entity_id = self._create_and_get_threat_model(action_result, endpoint, payload, data, entity_type)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            if not entity_id:
                return action_result.set_status(
                    phantom.APP_ERROR, "Error while fetching the {key} ID of the created {key} on the cloud".format(key=entity_type))

            output_message = THREATSTREAM_SUCCESS_THREATMODEL_MESSAGE.format(entity_type, entity_id)

            if cloud_intelligence:
                intel_data = {"ids": cloud_intelligence}
                ret_val, response = self._make_rest_call(
                    action_result, ENDPOINT_ADD_ASSOCIATION.format(entity_type=entity_type, entity_id=entity_id,
                                                                   associated_entity_type="intelligence"), payload,
                    data=intel_data, method="post")

                if phantom.is_fail(ret_val):
                    is_error = True
                    if output_message:
                        output_message = "{}. {}. Details: {}" \
                            .format(output_message, THREATSTREAM_ERR_INVALID_REMOTE_INTELLIGENCE.format(', '.join(cloud_intelligence)), action_result.get_message())
                    else:
                        output_message = "{}. Details: {}".format(THREATSTREAM_ERR_INVALID_REMOTE_INTELLIGENCE.format(', '.join(cloud_intelligence)), action_result.get_message())

                if response and response.get("ids"):
                    intelligence.extend(response.get("ids"))

            if local_intelligence:
                del payload["remote_api"]
                intel_data = {"local_ids": local_intelligence}
                ret_val, response = self._make_rest_call(
                    action_result, ENDPOINT_ADD_ASSOCIATION.format(entity_type=entity_type, entity_id=entity_id, associated_entity_type="intelligence"), payload,
                    data=intel_data, method="post")

                if phantom.is_fail(ret_val):
                    is_error = True
                    if output_message:
                        output_message = "{}. {}. Details: {}"\
                            .format(output_message, THREATSTREAM_ERR_INVALID_LOCAL_INTELLIGENCE.format(', '.join(local_intelligence)), action_result.get_message())
                    else:
                        output_message = "{}. Details: {}" \
                            .format(THREATSTREAM_ERR_INVALID_LOCAL_INTELLIGENCE.format(', '.join(local_intelligence)), action_result.get_message())

                if response and response.get("local_ids"):
                    intelligence.extend(response.get("local_ids"))

        else:
            ret_val, resp_json, entity_id = self._create_and_get_threat_model(action_result, endpoint, payload, data, entity_type)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            if not entity_id:
                return action_result.set_status(phantom.APP_ERROR, "Error while fetching the {key} ID of the created {key} on the on-prem".format(key=entity_type))

            output_message = THREATSTREAM_SUCCESS_THREATMODEL_MESSAGE.format(entity_type, entity_id)

            intel_data = dict()

            if local_intelligence:
                intel_data["ids"] = local_intelligence
            if cloud_intelligence:
                intel_data["remote_ids"] = cloud_intelligence

            if intel_data:
                ret_val, response = self._make_rest_call(action_result,
                                                         ENDPOINT_ADD_ASSOCIATION.format(entity_type=entity_type, entity_id=entity_id, associated_entity_type="intelligence"),
                                                         payload, data=intel_data, method="post")

                if phantom.is_fail(ret_val):
                    is_error = True
                    if output_message:
                        output_message = "{}. Error while adding intelligence. Details: {}".format(output_message, action_result.get_message())
                    else:
                        output_message = "Error while adding intelligence. Details: {}".format(action_result.get_message())

                if response and response.get("remote_ids"):
                    intelligence.extend(response.get("remote_ids"))

                if response and response.get("ids"):
                    intelligence.extend(response.get("ids"))

        intel_list = list()

        if intelligence:
            msg_intel = list()
            for intel in intelligence:
                intel_id_dict = dict()
                intel_id_dict["id"] = intel
                intel_list.append(intel_id_dict)
                msg_intel.append(str(intel))

            resp_json["intelligence"] = intel_list

            message = "{} created successfully. Associated intelligence : {}".format(entity_type.capitalize(), ', '.join(msg_intel))

        elif (local_intelligence or cloud_intelligence) and not intelligence:
            message = "{} created successfully. {}".format(entity_type.capitalize(), THREATSTREAM_ERR_INVALID_INTELLIGENCE)
        else:
            message = "{} created successfully".format(entity_type.capitalize())

        if attachment:
            ret_val, resp_json = self.add_attachment(action_result, attachment, entity_type, entity_id, payload, resp_json)
            if phantom.is_fail(ret_val):
                is_error = True
                output_message = "{}. Error while adding attachments. Details: {}".format(output_message, action_result.get_message())

        if comment:
            ret_val, resp_json_comment = self.add_comment(action_result, comment.encode('utf-8'), entity_type, entity_id, payload)
            if phantom.is_fail(ret_val):
                is_error = True
                output_message = "{}. Error while adding comments. Details: {}".format(output_message, action_result.get_message())
            else:
                resp_json["comment"] = resp_json_comment

        action_result.add_data(resp_json)
        if is_error:
            return action_result.set_status(phantom.APP_ERROR, output_message)

        summary = action_result.update_summary({})
        summary['created_on_cloud'] = create_on_cloud or self._is_cloud_instance
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _update_threat_model(self, action_result, param, endpoint, entity_type, entity_id):  # noqa

        if not (param.get("local_intelligence") or param.get("cloud_intelligence")) and not param.get("fields") and not param.get("attachment") and not param.get("comment"):
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_MISSING_PARAMS_UPDATE_THREAT_MODEL.format(entity_type))

        data = {}
        intel_ids_list = list()
        data_dict = self._build_data(param, data, action_result)
        if data_dict is None:
            return action_result.get_status()

        local_intelligence = data_dict.get("local_intelligence")
        cloud_intelligence = data_dict.get("cloud_intelligence")
        attachment = param.get("attachment")
        comment = param.get("comment")
        if comment:
            comment = comment.encode('utf-8')
        data = data_dict.get("data")
        data = self._validate_data(action_result, data)
        if data is None:
            return action_result.get_status()

        payload = self._generate_payload()
        is_error = False
        output_message = None
        message = None

        if self._is_cloud_instance:
            if cloud_intelligence:
                data.update({"intelligence": cloud_intelligence})
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, data=data, method="patch")
        else:
            if local_intelligence or cloud_intelligence:
                intel_data = dict()
                if local_intelligence:
                    intel_data["ids"] = local_intelligence

                if cloud_intelligence:
                    intel_data["remote_ids"] = cloud_intelligence

                ret_val, resp_json = self._make_rest_call(action_result,
                                                          ENDPOINT_ADD_ASSOCIATION.format(entity_type=entity_type, entity_id=entity_id, associated_entity_type="intelligence"),
                                                          payload, data=intel_data, method="post")

                if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                    intel_data = dict()
                    if local_intelligence:
                        intel_data["local_ids"] = local_intelligence

                        ret_val, resp_json = self._make_rest_call(
                            action_result, ENDPOINT_ADD_ASSOCIATION.format(entity_type=entity_type, entity_id=entity_id, associated_entity_type="intelligence"), payload,
                            data=intel_data, method="post")

                        if phantom.is_fail(ret_val):
                            is_error = True
                            if output_message:
                                output_message = "{}. {}. Details: {}" \
                                    .format(output_message, THREATSTREAM_ERR_INVALID_LOCAL_INTELLIGENCE.format(', '.join(cloud_intelligence)), action_result.get_message())
                            else:
                                output_message = "{}. Details: {}"\
                                    .format(THREATSTREAM_ERR_INVALID_LOCAL_INTELLIGENCE.format(', '.join(cloud_intelligence)), action_result.get_message())

                        del intel_data["local_ids"]
                        if resp_json and resp_json.get("local_ids"):
                            intel_ids_list.extend(resp_json.get("local_ids"))

                    if cloud_intelligence:
                        intel_data["ids"] = cloud_intelligence
                        payload["remote_api"] = "true"
                        ret_val, resp_json = self._make_rest_call(
                            action_result, ENDPOINT_ADD_ASSOCIATION.format(entity_type=entity_type, entity_id=entity_id, associated_entity_type="intelligence"), payload,
                            data=intel_data, method="post")

                        if phantom.is_fail(ret_val):
                            is_error = True
                            if output_message:
                                output_message = "{}. {}. Details: {}" \
                                    .format(output_message, THREATSTREAM_ERR_INVALID_REMOTE_INTELLIGENCE.format(', '.join(cloud_intelligence)), action_result.get_message())
                            else:
                                output_message = "{}. Details: {}".format(THREATSTREAM_ERR_INVALID_REMOTE_INTELLIGENCE.format(', '.join(cloud_intelligence)),
                                                                          action_result.get_message())

                if phantom.is_fail(ret_val):
                    is_error = True
                    if output_message:
                        output_message = "{}. Error while updating intelligence. Details: {}".format(output_message, action_result.get_message())
                    else:
                        output_message = "Error while updating intelligence. Details: {}".format(action_result.get_message())

                if resp_json and resp_json.get("ids"):
                    intel_ids_list.extend(resp_json.get("ids"))
                if resp_json and resp_json.get("remote_ids"):
                    intel_ids_list.extend(resp_json.get("remote_ids"))

            if intel_ids_list:
                msg_intel = list()
                for intel_value in intel_ids_list:
                    msg_intel.append(str(intel_value))

                message = "Associated intelligence : {}".format(', '.join(msg_intel))

            elif (local_intelligence or cloud_intelligence) and not intel_ids_list:
                message = THREATSTREAM_ERR_INVALID_INTELLIGENCE
            else:
                message = None

            associated_intelligence = data_dict.get("associated_intelligence")
            if associated_intelligence:
                intel_ids_list.extend(associated_intelligence)

            # Update the threat model in all cases with data or with empty data to get the latest intelligence values associated with it
            ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, data=data, method="patch")

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, data=data, method="patch")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        intel_list = list()

        intel_ids_list = list(set(intel_ids_list))

        if intel_ids_list:
            for intel_value in intel_ids_list:
                intel_id_dict = dict()
                intel_id_dict["id"] = intel_value
                intel_list.append(intel_id_dict)

            resp_json["intelligence"] = intel_list

        # get call to display information in data
        ret_val, resp_json = self._get_request_threat_model(action_result, payload, entity_type, entity_id)
        if phantom.is_fail(ret_val):
            is_error = True
            if output_message:
                output_message = "{}. Error while getting threat model. Details: {}".format(output_message, action_result.get_message())
            else:
                output_message = "Error while getting threat model. Details: {}".format(action_result.get_message())

        if attachment:
            ret_val, resp_json = self.add_attachment(action_result, attachment, entity_type, entity_id, payload, resp_json)
            if phantom.is_fail(ret_val):
                is_error = True
                if output_message:
                    output_message = "{}. Error while adding attachments. Details: {}".format(output_message, action_result.get_message())
                else:
                    output_message = "Error while adding attachments. Details: {}".format(action_result.get_message())

        if comment:
            ret_val, response = self.add_comment(action_result, comment, entity_type, entity_id, payload)
            if phantom.is_fail(ret_val):
                is_error = True
                if output_message:
                    output_message = "{}. Error while adding comments. Details: {}".format(output_message, action_result.get_message())
                else:
                    output_message = "Error while adding comments. Details: {}".format(action_result.get_message())
            else:
                resp_json.update({"comments": response})

        action_result.add_data(resp_json)

        if is_error:
            return action_result.set_status(phantom.APP_ERROR, output_message)

        if message:
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated {}. {}".format(entity_type, message))
        else:
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated {}".format(entity_type))

    def _handle_create_vulnerability(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self._create_threat_model(action_result, param, ENDPOINT_VULNERABILITY, "vulnerability")
        return action_result.get_status()

    def _handle_update_vulnerability(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, vulnerability_id = self._validate_integer(action_result, param["id"], "Please provide a valid interger in 'id' parameter")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._update_threat_model(action_result, param, ENDPOINT_SINGLE_VULNERABILITY.format(vul_id=vulnerability_id), "vulnerability", vulnerability_id)
        return action_result.get_status()

    def _handle_delete_vulnerability(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, vulnerability_id = self._validate_integer(action_result, param["vulnerability_id"],
                                                           THREATSTREAM_VULNERABILITY_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        payload = self._generate_payload()

        if self._is_cloud_instance:
            payload["remote_api"] = "true"
            ret_val, resp_json = self._make_rest_call(action_result,
                                                      ENDPOINT_SINGLE_VULNERABILITY.format(vul_id=vulnerability_id),
                                                      payload,
                                                      method="delete")
        else:
            ret_val, resp_json = self._make_rest_call(action_result,
                                                      ENDPOINT_SINGLE_VULNERABILITY.format(vul_id=vulnerability_id),
                                                      payload,
                                                      method="delete")

            if phantom.is_fail(ret_val) and "Status Code: 404" in action_result.get_message():
                payload["remote_api"] = "true"
                ret_val, resp_json = self._make_rest_call(action_result,
                                                          ENDPOINT_SINGLE_VULNERABILITY.format(vul_id=vulnerability_id),
                                                          payload,
                                                          method="delete")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted vulnerability")

    def _handle_create_actor(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        self._create_threat_model(action_result, param, ENDPOINT_ACTOR, "actor")
        return action_result.get_status()

    def _handle_update_actor(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, actor_id = self._validate_integer(action_result, param["id"], "Please provide a valid interger in 'id' parameter")
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self._update_threat_model(action_result, param, ENDPOINT_SINGLE_ACTOR.format(actor_id=actor_id), "actor", actor_id)
        return action_result.get_status()

    def _handle_create_investigation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        name = param['name']
        priority = param['priority']

        create_on_cloud = param.get('create_on_cloud', False)

        data = {
            'name': name,
            'priority': priority
        }

        data_dict = self._build_data(param, data, action_result)
        if data_dict is None:
            return action_result.get_status()

        data = data_dict.get("data")
        data = self._validate_data(action_result, data)
        if data is None:
            return action_result.get_status()

        payload = self._generate_payload()
        if self._is_cloud_instance or create_on_cloud:
            payload['remote_api'] = 'true'

        ret_val, resp_json = self._make_rest_call(
            action_result, ENDPOINT_INVESTIGATION, payload, data=data, method='post')
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        summary = action_result.update_summary({})
        summary['created_on_cloud'] = create_on_cloud or self._is_cloud_instance

        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully created investigation')

    def _handle_list_investigations(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, limit = self._validate_integer(action_result, param.get("limit", 1000), THREATSTREAM_LIMIT)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        payload = self._generate_payload()

        investigations = self._paginator(ENDPOINT_INVESTIGATION, action_result, limit=limit, payload=payload)
        if investigations is None:
            return action_result.get_status()

        for investigation in investigations:
            action_result.add_data(investigation)

        summary = action_result.update_summary({})
        summary['investigations_returned'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_investigation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        payload = self._generate_payload()

        ret_val, investigation_id = self._validate_integer(
            action_result, param['investigation_id'], THREATSTREAM_INVESTIGATION_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        endpoint = ENDPOINT_SINGLE_INVESTIGATION.format(investigation_id)
        if self._is_cloud_instance:
            payload['remote_api'] = 'true'
            ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, method='get')
        else:
            ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, method='get')

            # Retry with remote api
            if phantom.is_fail(ret_val) and 'Status Code: 404' in action_result.get_message():
                payload['remote_api'] = 'true'
                ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, method='get')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully retrieved investigation')

    def _handle_update_investigation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, investigation_id = self._validate_integer(
            action_result, param['investigation_id'], THREATSTREAM_INVESTIGATION_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        data_dict = self._build_data(param, {}, action_result)
        if data_dict is None:
            return action_result.get_status()

        data = data_dict.get("data")
        data = self._validate_data(action_result, data)
        if data is None:
            return action_result.get_status()

        payload = self._generate_payload()
        endpoint = ENDPOINT_SINGLE_INVESTIGATION.format(investigation_id)

        if self._is_cloud_instance:
            payload['remote_api'] = 'true'
            ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, data=data, method='patch')
        else:
            ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, data=data, method='patch')

            # Retry with remote api
            if phantom.is_fail(ret_val) and 'Status Code: 404' in action_result.get_message():
                payload['remote_api'] = 'true'
                ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, data=data, method='patch')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully updated investigation')

    def _handle_delete_investigation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, investigation_id = self._validate_integer(
            action_result, param['investigation_id'], THREATSTREAM_INVESTIGATION_ID)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        payload = self._generate_payload()

        endpoint = ENDPOINT_SINGLE_INVESTIGATION.format(investigation_id)

        if self._is_cloud_instance:
            payload['remote_api'] = 'true'
            ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, method='delete')
        else:
            ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, method='delete')

            # Retry with remote api
            if phantom.is_fail(ret_val):
                payload['remote_api'] = 'true'
                ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, method='delete')

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully deleted investigation')

    def handle_action(self, param):  # noqa

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
        elif (action == self.ACTION_ID_URL_REPUTATION):
            ret_val = self._url_reputation(param)
        elif (action == self.ACTION_ID_EMAIL_REPUTATION):
            ret_val = self._email_reputation(param)
        elif (action == self.ACTION_ID_WHOIS_DOMAIN):
            ret_val = self._whois_domain(param)
        elif (action == self.ACTION_ID_WHOIS_IP):
            ret_val = self._whois_ip(param)
        elif (action == self.ACTION_ID_LIST_INCIDENTS):
            ret_val = self._handle_list_incidents(param)
        elif (action == self.ACTION_ID_LIST_VULNERABILITY):
            ret_val = self._handle_list_vulnerability(param)
        elif (action == self.ACTION_ID_LIST_OBSERVABLE):
            ret_val = self._handle_list_observable(param)
        elif (action == self.ACTION_ID_GET_INCIDENT):
            ret_val = self._handle_get_incident(param)
        elif (action == self.ACTION_ID_GET_VULNERABILITY):
            ret_val = self._handle_get_vulnerability(param)
        elif (action == self.ACTION_ID_GET_OBSERVABLE):
            ret_val = self._handle_get_observable(param)
        elif (action == self.ACTION_ID_DELETE_INCIDENT):
            ret_val = self._handle_delete_incident(param)
        elif (action == self.ACTION_ID_CREATE_INCIDENT):
            ret_val = self._handle_create_incident(param)
        elif (action == self.ACTION_ID_UPDATE_INCIDENT):
            ret_val = self._handle_update_incident(param)
        elif (action == self.ACTION_ID_IMPORT_IOC):
            ret_val = self._handle_import_ioc(param)
        elif (action == self.ACTION_ID_IMPORT_EMAIL_OBSERVABLES):
            ret_val = self._handle_import_email_observable(param)
        elif (action == self.ACTION_ID_IMPORT_FILE_OBSERVABLES):
            ret_val = self._handle_import_file_observable(param)
        elif (action == self.ACTION_ID_IMPORT_IP_OBSERVABLES):
            ret_val = self._handle_import_ip_observable(param)
        elif (action == self.ACTION_ID_IMPORT_URL_OBSERVABLES):
            ret_val = self._handle_import_url_observable(param)
        elif (action == self.ACTION_ID_IMPORT_DOMAIN_OBSERVABLES):
            ret_val = self._handle_import_domain_observable(param)
        elif (action == self.ACTION_ID_RUN_QUERY):
            ret_val = self._handle_run_query(param)
        elif (action == self.ACTION_ID_ON_POLL):
            ret_val = self._handle_on_poll(param)
        elif (action == self.ACTION_ID_DETONATE_FILE):
            ret_val = self._handle_detonate_file(param)
        elif (action == self.ACTION_ID_GET_STATUS):
            ret_val = self._handle_get_status(param)
        elif (action == self.ACTION_ID_GET_REPORT):
            ret_val = self._handle_get_report(param)
        elif (action == self.ACTION_ID_DETONATE_URL):
            ret_val = self._handle_detonate_url(param)
        elif (action == self.ACTION_ID_GET_PCAP):
            ret_val = self._handle_get_pcap(param)
        elif (action == self.ACTION_ID_TAG_IOC):
            ret_val = self._handle_tag_ioc(param)
        elif (action == self.ACTION_IMPORT_SESSION_SEARCH):
            ret_val = self._handle_import_session_search(param)
        elif (action == self.ACTION_IMPORT_SESSION_UPDATE):
            ret_val = self._handle_import_session_update(param)
        elif(action == self.ACTION_THREAT_MODEL_SEARCH):
            ret_val = self._handle_threat_model_search(param)
        elif(action == self.ACTION_CREATE_THREAT_BULLETIN):
            ret_val = self._handle_create_threat_bulletin(param)
        elif(action == self.ACTION_UPDATE_THREAT_BULLETIN):
            ret_val = self._handle_update_threat_bulletin(param)
        elif(action == self.ACTION_DELETE_THREAT_BULLETIN):
            ret_val = self._handle_delete_threat_bulletin(param)
        elif(action == self.ACTION_LIST_THREAT_BULLETINS):
            ret_val = self._handle_list_threat_bulletins(param)
        elif(action == self.ACTION_LIST_ASSOCIATIONS):
            ret_val = self._handle_list_associations(param)
        elif (action == self.ACTION_CREATE_RULE):
            ret_val = self._handle_create_rule(param)
        elif (action == self.ACTION_UPDATE_RULE):
            ret_val = self._handle_update_rule(param)
        elif (action == self.ACTION_LIST_RULE):
            ret_val = self._handle_list_rules(param)
        elif (action == self.ACTION_DELETE_RULE):
            ret_val = self._handle_delete_rule(param)
        elif (action == self.ACTION_ADD_ASSOCIATION):
            ret_val = self._handle_add_association(param)
        elif (action == self.ACTION_REMOVE_ASSOCIATION):
            ret_val = self._handle_remove_association(param)
        elif (action == self.ACTION_LIST_ACTORS):
            ret_val = self._handle_list_actors(param)
        elif (action == self.ACTION_LIST_IMPORT):
            ret_val = self._handle_list_import(param)
        elif (action == self.ACTION_CREATE_VULNERABILITY):
            ret_val = self._handle_create_vulnerability(param)
        elif (action == self.ACTION_UPDATE_VULNERABILITY):
            ret_val = self._handle_update_vulnerability(param)
        elif (action == self.ACTION_DELETE_VULNERABILITY):
            ret_val = self._handle_delete_vulnerability(param)
        elif (action == self.ACTION_DELETE_ACTOR):
            ret_val = self._handle_delete_actor(param)
        elif (action == self.ACTION_CREATE_ACTOR):
            ret_val = self._handle_create_actor(param)
        elif (action == self.ACTION_UPDATE_ACTOR):
            ret_val = self._handle_update_actor(param)
        elif (action == self.ACTION_CREATE_INVESTIGATION):
            ret_val = self._handle_create_investigation(param)
        elif (action == self.ACTION_LIST_INVESTIGATIONS):
            ret_val = self._handle_list_investigations(param)
        elif (action == self.ACTION_GET_INVESTIGATION):
            ret_val = self._handle_get_investigation(param)
        elif (action == self.ACTION_UPDATE_INVESTIGATION):
            ret_val = self._handle_update_investigation(param)
        elif (action == self.ACTION_DELETE_INVESTIGATION):
            ret_val = self._handle_delete_investigation(param)

        return ret_val


if __name__ == '__main__':

    # Imports
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
        print(ret_val)

    exit(0)
