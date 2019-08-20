# File: threatstream_connector.py
# Copyright (c) 2016-2018 Splunk Inc.
#
# SPLUNK CONFIDENTIAL – Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Local imports
from threatstream_consts import *

import ast
import time
import os
import tempfile
import shutil
import requests
import datetime
import ipaddress
import pythonwhois
import simplejson as json
from bs4 import BeautifulSoup
from urlparse import urlsplit

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
    ACTION_ID_GET_INCIDENT = "get_incident"
    ACTION_ID_GET_VULNERABILITY = "get_vulnerability"
    ACTION_ID_DELETE_INCIDENT = "delete_incident"
    ACTION_ID_CREATE_INCIDENT = "create_incident"
    ACTION_ID_UPDATE_INCIDENT = "update_incident"
    ACTION_ID_IMPORT_IOC = "import_observables"
    ACTION_ID_RUN_QUERY = "run_query"
    ACTION_ID_TAG_IOC = "tag_observable"
    ACTION_ID_ON_POLL = "on_poll"
    ACTION_ID_DETONATE_FILE = "detonate_file"
    ACTION_ID_GET_STATUS = "get_status"
    ACTION_ID_GET_REPORT = "get_report"
    ACTION_ID_DETONATE_URL = "detonate_url"
    ACTION_ID_GET_PCAP = "get_pcap"

    def __init__(self):

        super(ThreatstreamConnector, self).__init__()
        self._data_dict = {}  # Blank dict to contain data from all API calls
        return

    def initialize(self):
        config = self.get_config()

        self._base_url = "https://{0}/api".format(config.get('hostname', 'api.threatstream.com'))
        self._state = self.load_state()

        self.set_validator('ipv6', self._is_ip)

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code
        action = self.get_action_identifier()

        if status_code == 202:
            return RetVal(phantom.APP_SUCCESS, {})
        elif status_code == 204 and action == self.ACTION_ID_DELETE_INCIDENT:
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted incident"), {})
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        data_message = ""
        # Error text can still be an empty string
        if error_text:
            data_message = " Data from server:\n{0}\n".format(error_text.encode('utf-8'))

        message = "Status Code: {0}. {1}".format(status_code, data_message)

        message = message.replace('{', '{{').replace('}', '}}')

        if len(message) > 500:
            message = "Status Code: {0}. Error while connecting to the server. Please check the asset and the action's input parameters.".format(status_code)

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            if resp_json.get('error', None) is None:
                return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

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

        # Process an HTML resonse, Do this no matter what the api talks.
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
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, action_result, endpoint, payload=None, headers=None, data=None, method="get", files=None, use_json=True):

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint
        if use_json:
            try:
                r = request_func(
                                url,
                                json=data,
                                headers=headers,
                                params=payload,
                                files=files)
            except Exception as e:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Error making rest call to server. Details: {0}".format(str(e))), resp_json)

        else:
            try:
                r = request_func(
                                url,
                                data=data,
                                headers=headers,
                                params=payload,
                                files=files)
            except Exception as e:
                return RetVal(action_result.set_status(phantom.APP_ERROR, "Error making rest call to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _is_ip(self, input_ip_address):
        """ Function that checks given address and return True if address is valid IPv4 or IPV6 address.

        :param input_ip_address: IP address
        :return: status (success/failure)
        """

        ip_address_input = input_ip_address

        try:
            ipaddress.ip_address(unicode(ip_address_input))
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
        for k, v in kwargs.iteritems():
            payload[k] = v
        return payload

    def _intel_details(self, value, action_result):
        """ Use the intelligence endpoint to get general details """

        # strip out scheme because API cannot find
        # intel with it included
        if phantom.is_url(value):
            value_regexp = '.*{0}.*'.format(urlsplit(value).netloc)
            payload = self._generate_payload(extend_source="true", type="url", order_by="-created_ts", value__regexp=value_regexp)
        else:
            payload = self._generate_payload(extend_source="true", order_by="-created_ts", value=value)

        intel_details = self._paginator(ENDPOINT_INTELLIGENCE, action_result, payload=payload)

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
        if ioc_type not in [ "ip", "domain", "email", "md5", "sha1", "sha256" ]:
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
        payload = self._generate_payload()
        whois = ENDPOINT_WHOIS.format(ioc_value=value)

        ret_val, resp_json = self._make_rest_call(action_result, whois, payload)
        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_SUCCESS, "Error making whois request")

        if (resp_json['data'] == WHOIS_NO_DATA):
            return action_result.set_status(phantom.APP_ERROR, WHOIS_NO_DATA)

        try:
            whois_response = pythonwhois.parse.parse_raw_whois([resp_json['data']], True)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_FETCH_REPLY.format(error=str(e)))

        try:
            # Need to work on the json, it contains certain fields that are not
            # parsable, so will need to go the 'fallback' way.
            # TODO: Find a better way to do this
            whois_response = json.dumps(whois_response, default=_json_fallback)
            whois_response = json.loads(whois_response)
            action_result.add_data(whois_response)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_PARSE_REPLY.format(error=str(e)))

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

        ioc_type = None

        if phantom.is_md5(value):
            ioc_type = "md5"
        if phantom.is_sha1(value):
            ioc_type = "sha1"
        if phantom.is_sha256(value):
            ioc_type = "sha256"

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

    def _url_reputation(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        value = param[THREATSTREAM_JSON_URL]
        ret_val = self._intel_details(value, action_result)
        if (not ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved information on URL")

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

            items_list.extend(items.get("objects"))

            if limit and len(items_list) >= limit:
                return items_list[:limit]

            if len(items.get("objects")) < DEFAULT_MAX_RESULTS:
                break

            offset = offset + DEFAULT_MAX_RESULTS
            payload['offset'] = offset

        return items_list

    def _handle_list_vulnerability(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get("limit")

        if limit == 0 or (limit and (not str(limit).isdigit() or limit <= 0)):
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))

        vulnerability = self._paginator(ENDPOINT_VULNERABILITY, action_result, limit=limit)

        if vulnerability is None:
            return action_result.get_status()

        for vul in vulnerability:
            action_result.add_data(vul)

        summary = action_result.update_summary({})
        summary['vulnerabilities_returned'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_incidents(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        limit = param.get("limit")

        if limit == 0 or (limit and (not str(limit).isdigit() or limit <= 0)):
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))

        if param.get("intel_value", None):
            payload = self._generate_payload(value=param["intel_value"])
            incidents = self._paginator(ENDPOINT_INCIDENT_WITH_VALUE, action_result, payload=payload, limit=limit)
        else:
            incidents = self._paginator(ENDPOINT_INCIDENT, action_result, limit=limit)

        if incidents is None:
            return action_result.get_status()

        for incident in incidents:
            action_result.add_data(incident)

        summary = action_result.update_summary({})
        summary['incidents_returned'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        payload = self._generate_payload()

        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=param["incident_id"]), payload)

        if (not ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved incident")

    def _handle_get_vulnerability(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        payload = self._generate_payload()

        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_VULNERABILITY.format(vul_id=param["vulnerability_id"]), payload)

        if (not ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved vulnerability")

    def _handle_delete_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        payload = self._generate_payload()
        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=param["incident_id"]), payload, method="delete")

        if (not ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully deleted incident")

    def _handle_create_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        data = {
                "name": param["name"], "is_public": param["is_public"], "status": 1
               }
        data = self._build_data(param, data, action_result)
        if data is None:
            return action_result.get_status()

        payload = self._generate_payload()
        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INCIDENT, payload, data=data, method="post")

        if (not ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully created incident")

    def _handle_update_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        data = {}
        data = self._build_data(param, data, action_result)
        if data is None:
            return action_result.get_status()

        payload = self._generate_payload()
        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=param["incident_id"]), payload, data=data, method="patch")

        if (not ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully updated incident")

    def _build_data(self, param, data, action_result):

        if param.get("fields", None):
            try:
                fields = ast.literal_eval(param["fields"])
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error building fields dictionary: {0}  Please ensure that you format as JSON.".format(e))
            data.update(fields)

        intel = []
        if param.get("intelligence", None):
            # Adding a first check if we have been supplied a list - this will
            # be useful for playbooks supplying a list object as the parameter
            if type(param["intelligence"]) is list:
                try:
                    intel = [int(x.strip()) for x in intel if x.strip() != '']
                except Exception as e:
                    action_result.set_status(phantom.APP_ERROR, "Error building list of intelligence IDs: {0}  Please supply as comma separated string of integers.".format(e))
                    return None
            else:
                try:
                    intel = param["intelligence"].strip().split(",")
                    intel = [int(x.strip()) for x in intel if x.strip() != '']
                except Exception as e:
                    action_result.set_status(phantom.APP_ERROR, "Error building list of intelligence IDs: {0}  Please supply as comma separated string of integers.".format(e))
                    return None
            data.update({"intelligence": intel})

        return data

    def _handle_run_query(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        payload = self._generate_payload()

        try:
            search_string = param["query"]
            search_dict = json.loads(search_string)
            payload.update(search_dict)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while parsing the JSON string provided in the 'query' parameter. Error: {0}".format(str(e)))

        order_by = param.get("order_by")
        if order_by:
            payload['order_by'] = order_by

        offset = param.get('offset', 0)
        if offset and (not str(offset).isdigit() or offset <= 0):
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="offset"))

        limit = param.get("limit")
        if limit == 0 or (limit and (not str(limit).isdigit() or limit <= 0)):
            return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param="limit"))

        records = self._paginator(ENDPOINT_INTELLIGENCE, action_result, payload=payload, offset=offset, limit=limit)

        if records is None:
            return action_result.get_status()

        for record in records:
            action_result.add_data(record)

        summary = action_result.update_summary({})
        summary['records_returned'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_import_ioc(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        payload = self._generate_payload()
        if param["observable_type"] == "ip":
            ob_type = "srcip"
        elif param["observable_type"] == "hash":
            ob_type = "md5"
        else:
            ob_type = param["observable_type"]

        data = {
                "objects": [
                    {ob_type: param["value"], "classification": param["classification"]}
                ]
               }

        if param.get("fields", None):
            try:
                fields = ast.literal_eval(param["fields"])
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error building fields dictionary: {0}  Please ensure that you format as JSON.".format(e))

            data["objects"][0].update(fields)
            #        , "itype": "actor_ip", "detail": "dionea,smbd,port-445,Windows-XP,DSL", "confidence": 50, "severity": "high"}

        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_IMPORT_IOC, payload, data=data, method="patch")

        if (not ret_val):
            return action_result.get_status()

        need_info = True
        counter = 1
        while need_info and counter <= 5:
            self.save_progress("Retrieving intelligence details attempt {0} of 5".format(counter))
            time.sleep(5)
            payload = self._generate_payload(extend_source="true", limit="25", offset="0",
                                         order_by="-created_ts", value=param["value"])

            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INTELLIGENCE, payload)
            if (phantom.is_fail(ret_val)):
                return action_result.get_status()

            if resp_json['objects'] != []:
                for detail in resp_json['objects']:
                    action_result.add_data(detail)
                need_info = False
            counter += 1

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully imported observable. Perform a reputation action if details are not included in this action.")

    def _handle_tag_ioc(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        config = self.get_config()

        org_id = config.get("organization_id", None)
        if org_id is None:
            return action_result.set_status(phantom.APP_ERROR, "Please set the organization ID config value prior to tagging an observable")

        payload = self._generate_payload()

        # tags should be a comma-separated list
        tags = param[THREATSTREAM_JSON_TAGS].split(',')
        data = {THREATSTREAM_JSON_TAGS: []}

        for tag in tags:
            data[THREATSTREAM_JSON_TAGS].append({
                "name": tag,
                "org_id": org_id,
                "tlp": param.get('tlp', 'red'),
                THREATSTREAM_JSON_SOURCE_USER_ID: param[THREATSTREAM_JSON_SOURCE_USER_ID]
            })

        endpoint = ENDPOINT_TAG_IOC.format(indicator_id=param["id"])
        ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload, data=data, method="post")

        if (not ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully tagged observable")

    def _handle_get_status(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        payload = self._generate_payload()
        endpoint = param.get("endpoint")
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
        vault_info = Vault.get_file_info(vault_id=param.get('vault_id'))

        for item in vault_info:
            vault_path = item.get('path')
            if vault_path is None:

                return action_result.set_status(phantom.APP_ERROR, "Could not find a path associated with the provided vault ID")
            try:
                vault_file = open(vault_path)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Unable to open vault file: " + str(e))

            payload = self._generate_payload()

            files = {
                "file": vault_file
            }
            data = {
                "report_radio-platform": param.get('platform'),
                "report_radio-file": vault_path,
                "report_radio-classification": param.get('classification')
            }

            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_FILE_DETONATION, payload, data=data, method="post", files=files, use_json=False)
            if (phantom.is_fail(ret_val)):
                return action_result.get_status()
            action_result.add_data(resp_json)
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully detonated file.")

    def _handle_detonate_url(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        payload = self._generate_payload()
        data = {
            "report_radio-platform": param.get('platform'),
            "report_radio-url": param.get('url'),
            "report_radio-classification": param.get('classification')
        }

        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_URL_DETONATION, payload, data=data, method="post", use_json=False)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()
        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully detonated URL.")

    def _handle_get_pcap(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        payload = self._generate_payload()
        endpoint = ENDPOINT_GET_REPORT.format(report_id=param['id'])

        # retrieve report data
        ret_val, resp_json = self._make_rest_call(action_result, endpoint, payload)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        ret_val, vault_details = self._save_pcap_to_vault(resp_json, self.get_container_id(), action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(vault_details)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _save_pcap_to_vault(self, response, container_id, action_result):
        # get URL to pcap file
        try:
            pcap = response['pcap']
        except KeyError:
            return action_result.set_status(phantom.APP_ERROR, "Could not find PCAP file to download from report."), None

        filename = os.path.basename(urlsplit(pcap).path)

        # download file
        try:
            pcap_file = requests.get(pcap).content
        except:
            return action_result.set_status(phantom.APP_ERROR, "Could not download PCAP file."), None

        # Creating temporary directory and file
        try:
            temp_dir = tempfile.mkdtemp()
            file_path = os.path.join(temp_dir, filename)
            with open(file_path, 'wb') as file_obj:
                file_obj.write(pcap_file)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error while writing to temporary file.", e), None

        # Adding pcap to vault
        vault_ret_dict = Vault.add_attachment(file_path, container_id, filename)

        # Removing temporary directory created to download file
        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to remove temporary directory", e), None

        # Updating data with vault details
        if vault_ret_dict['succeeded']:
            vault_details = {
                phantom.APP_JSON_VAULT_ID: vault_ret_dict[phantom.APP_JSON_HASH],
                'file_name': filename
            }
            return phantom.APP_SUCCESS, vault_details

        # Error while adding report to vault
        self.debug_print('Error adding file to vault:', vault_ret_dict)
        action_result.append_to_message('. {}'.format(vault_ret_dict['message']))

        # Set the action_result status to error, the handler function will most probably return as is
        return phantom.APP_ERROR, None

    def _check_and_update_container_already_exists(self, incident_id, incident_name):

        url = '{0}rest/container?_filter_source_data_identifier="{1}"&_filter_asset={2}'.format(self.get_phantom_base_url(), incident_id, self.get_asset_id())

        try:
            r = requests.get(url, verify=False)
            resp_json = r.json()
        except Exception as e:
            self.debug_print("Unable to query ThreatStream incident container: ", e)
            return None

        if (resp_json.get('count', 0) <= 0):
            self.debug_print("No container matched")
            return None

        try:
            container_id = resp_json.get('data', [])[0]['id']
        except Exception as e:
            self.debug_print("Container results are not proper: ", e)
            return None

        # If the container exists and he name of the incident has been updated,
        # update the name of the container as well to stay in sync with the UI of ThreatStream
        if container_id and (resp_json.get('data', [])[0]['name'] != incident_name):
            url = '{0}rest/container/{1}'.format(self.get_phantom_base_url(), container_id)
            try:
                data = {"name": incident_name}
                r = requests.post(url, verify=False, json=data)
                resp_json = r.json()
            except Exception as e:
                self.debug_print("Unable to update the name of the ThreatStream incident container: ", e)
                return container_id

            if not resp_json.get('success'):
                self.debug_print("Container with ID: {0} could not be updated with the current incident_name: {1} of the incident ID: {2}".format(
                                    container_id, incident_name, incident_id))
                self.debug_print("Response of the container updation is: {0}".format(str(resp_json)))
                return container_id

        return container_id

    def _handle_on_poll(self, param):
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
                limit = int(param.get("container_count", 1000))
                parameter = "container_count"
            elif self._state.get("first_run", True):
                # Scheduled polling first run
                limit = int(param.get("first_run_containers", 1000))
                self._state["first_run"] = False
                parameter = "first_run_containers"
            else:
                # Poll every new update in the subsequent polls
                # of the scheduled_polling
                limit = None

            if limit == 0 or (limit and (not str(limit).isdigit() or limit <= 0)):
                return action_result.set_status(phantom.APP_ERROR, THREATSTREAM_ERR_INVALID_PARAM.format(param=parameter))

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching the number of containers to be ingested. Error: {0}".format(str(e)))

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

        self.save_progress("Fetched {0} incidents".format(len(incidents)))

        for incident in incidents:
            self.send_progress("Creating containers and artifacts for the incident ID: {0}".format(incident.get("id")))
            # Handle the ingest_only_published_incidents scenario
            if config.get("ingest_only_published_incidents", True):
                if "published" != incident.get("publication_status"):
                    self.debug_print("Skipping incident ID: {0} because ingest_only_published_incidents configuration parameter is marked true".format(incident.get("id")))
                    continue

            self.debug_print("Retrieving details for the incident ID: {0}".format(incident.get("id")))

            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident["id"]), payload=payload)

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
                artifact['cef'] = item
                artifact['cef_types'] = {'id': [ "threatstream intelligence id" ],
                        'owner_organization_id': [ "threatstream organization id" ],
                        'ip': [ "ip" ],
                        'value': [ "ip", "domain", "url", "email", "md5", "sha1", "hash" ]
                                }
                artifacts_list.append(artifact)

            artifact = {"label": "artifact",
                        "type": "network",
                        "name": "incident artifact",
                        "description": "Artifact added by ThreatStream App",
                        "source_data_identifier": resp_json["id"]
                        }
            artifact['cef'] = resp_json
            artifact['cef_types'] = {'id': [ "threatstream incident id" ], 'organization_id': [ "threatstream organization id" ]}
            artifacts_list.append(artifact)

            existing_container_id = self._check_and_update_container_already_exists(resp_json.get("id"), resp_json.get("name"))

            self.debug_print("Saving container and adding artifacts for the incident ID: {0}".format(resp_json.get("id")))

            if not existing_container_id:
                container = dict()
                container['description'] = "Container added by ThreatStream app"
                container['source_data_identifier'] = resp_json.get("id")
                container['name'] = resp_json.get("name")
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
                self._state["last_incident_time"] = last_incident_time[:-7]

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved and ingested the list of incidents")

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
        elif (action == self.ACTION_ID_GET_INCIDENT):
            ret_val = self._handle_get_incident(param)
        elif (action == self.ACTION_ID_GET_VULNERABILITY):
            ret_val = self._handle_get_vulnerability(param)
        elif (action == self.ACTION_ID_DELETE_INCIDENT):
            ret_val = self._handle_delete_incident(param)
        elif (action == self.ACTION_ID_CREATE_INCIDENT):
            ret_val = self._handle_create_incident(param)
        elif (action == self.ACTION_ID_UPDATE_INCIDENT):
            ret_val = self._handle_update_incident(param)
        elif (action == self.ACTION_ID_IMPORT_IOC):
            ret_val = self._handle_import_ioc(param)
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

        return ret_val


if __name__ == '__main__':

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
