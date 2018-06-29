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

import ast
import requests
import datetime
import pythonwhois
import simplejson as json
from bs4 import BeautifulSoup
import time

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
    ACTION_ID_FILE_REPUTATION = "file_reputation"
    ACTION_ID_LIST_INCIDENTS = "list_incidents"
    ACTION_ID_GET_INCIDENT = "get_incident"
    ACTION_ID_DELETE_INCIDENT = "delete_incident"
    ACTION_ID_CREATE_INCIDENT = "create_incident"
    ACTION_ID_UPDATE_INCIDENT = "update_incident"
    ACTION_ID_IMPORT_IOC = "import_observables"
    ACTION_ID_ON_POLL = "on_poll"

    def __init__(self):

        super(ThreatstreamConnector, self).__init__()
        self._data_dict = {}  # Blank dict to contain data from all API calls
        return

    def initialize(self):
        config = self.get_config()

        self._base_url = "https://{0}/api".format(config.get('hostname', 'api.threatstream.com'))
        self._state = self.load_state()
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
            data_message = " Data from server:\n{0}\n".format(error_text)

        message = "Status Code: {0}.{1}".format(
            status_code,
            data_message
        )

        message = message.replace('{', '{{').replace('}', '}}')

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

    def _make_rest_call(self, action_result, endpoint, payload=None, headers=None, data=None, method="get"):

        config = self.get_config()
        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            json=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=payload)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error making rest call to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

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

    def _handle_list_incidents(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        if param.get("intel_value", None):
            payload = self._generate_payload(limit=param.get("limit", "20"), value=param["intel_value"])
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INCIDENT_WITH_VALUE, payload)
        else:
            payload = self._generate_payload(limit=param.get("limit", "20"))
            ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INCIDENT, payload)

        if (not ret_val):
            return action_result.get_status()

        for incident in resp_json['objects']:
            action_result.add_data(incident)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved list of incidents")

    def _handle_get_incident(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        payload = self._generate_payload()
        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=param["incident_id"]), payload)

        if (not ret_val):
            return action_result.get_status()

        action_result.add_data(resp_json)
        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved incident")

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

    def _handle_on_poll(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        config = self.get_config()

        org_id = config.get("organization_id", None)
        if org_id is None:
            return action_result.set_status(phantom.APP_ERROR, "Please set the organization ID config value before polling")

        self.save_progress("Retrieving incidents...")
        payload = self._generate_payload(limit=param.get("limit", "1000"))
        ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_INCIDENT, payload)

        if (not ret_val):
            return action_result.get_status()
        # This set will be used to track all incidents added on this poll and
        # save state for future polls
        set_of_inc_ids = set()
        start_incident_id = self._state.get("last_incident_id", 0)
        if self.is_poll_now():
            max_containers = int(param.get("container_count", 100))
        else:
            max_containers = int(config.get("max_containers", 100))
        added_containers = 0

        for incident in resp_json['objects']:
            if config.get("ingest_only_published_incidents", True):
                if incident["publication_status"] != "published":
                    continue
            if all([incident["organization_id"] == int(org_id),
                    int(incident["id"]) > start_incident_id,
                    added_containers < max_containers]):
                container = {"description": "Container added by ThreatStream App"}
                self.save_progress("Retrieving details for incident {0}...".format(incident["id"]))
                ret_val, resp_json = self._make_rest_call(action_result, ENDPOINT_SINGLE_INCIDENT.format(inc_id=incident["id"]), payload)
                if (not ret_val):
                    return action_result.get_status()
                container['source_data_identifier'] = resp_json["id"]
                container['name'] = resp_json["name"]
                container['data'] = resp_json
                container['artifacts'] = []

                intelligence = resp_json.pop("intelligence")
                if intelligence != []:
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
                                'value': [ "ip", "domain", "md5", "sha1", "hash" ]
                                        }
                        container['artifacts'].append(artifact)

                artifact = {"label": "artifact",
                            "type": "network",
                            "name": "incident artifact",
                            "description": "Artifact added by ThreatStream App",
                            "source_data_identifier": resp_json["id"]
                            }
                artifact['cef'] = resp_json
                artifact['cef_types'] = {'id': [ "threatstream incident id" ],
                            'organization_id': [ "threatstream organization id" ]
                                         }
                container['artifacts'].append(artifact)

                self.save_progress("Saving container and adding artifacts...")
                ret_val, message, container_id = self.save_container(container)

                if (phantom.is_fail(ret_val)):
                    message = "Failed to add Container error msg: {0}".format(message)
                    self.debug_print(message)
                    return action_result.set_status(phantom.APP_ERROR, "Failed Creating container")

                if (not container_id):
                    message = "save_container did not return a container_id"
                    self.debug_print(message)
                    return action_result.set_status(phantom.APP_ERROR, "Failed Creating container")
                # Add incident ID to tracking set for state saving later
                set_of_inc_ids.add(int(resp_json["id"]))
                added_containers += 1

        if (not self.is_poll_now()):
            try:
                self._state["last_incident_id"] = sorted(set_of_inc_ids)[-1]
            except:
                self._state["last_incident_id"] = 0

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved list of incidents")

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
        elif (action == self.ACTION_ID_LIST_INCIDENTS):
            ret_val = self._handle_list_incidents(param)
        elif (action == self.ACTION_ID_GET_INCIDENT):
            ret_val = self._handle_get_incident(param)
        elif (action == self.ACTION_ID_DELETE_INCIDENT):
            ret_val = self._handle_delete_incident(param)
        elif (action == self.ACTION_ID_CREATE_INCIDENT):
            ret_val = self._handle_create_incident(param)
        elif (action == self.ACTION_ID_UPDATE_INCIDENT):
            ret_val = self._handle_update_incident(param)
        elif (action == self.ACTION_ID_IMPORT_IOC):
            ret_val = self._handle_import_ioc(param)
        elif (action == self.ACTION_ID_ON_POLL):
            ret_val = self._handle_on_poll(param)

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
