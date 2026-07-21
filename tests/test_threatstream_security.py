# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import importlib
import json as stdlib_json
import sys
import types
import unittest
from unittest import mock


def _install_import_stubs():
    phantom = types.ModuleType("phantom")
    phantom.__path__ = []
    phantom_app = types.ModuleType("phantom.app")
    phantom_app.APP_SUCCESS = True
    phantom_app.APP_ERROR = False
    phantom_app.is_fail = lambda value: not value
    phantom.app = phantom_app
    phantom_rules = types.ModuleType("phantom.rules")
    phantom.rules = phantom_rules
    phantom_action_result = types.ModuleType("phantom.action_result")
    phantom_action_result.ActionResult = object
    phantom_base_connector = types.ModuleType("phantom.base_connector")
    phantom_base_connector.BaseConnector = object
    phantom_vault = types.ModuleType("phantom.vault")
    phantom_vault.Vault = object

    dateutil = types.ModuleType("dateutil")
    dateutil.__path__ = []
    dateutil_parser = types.ModuleType("dateutil.parser")
    dateutil_tz = types.ModuleType("dateutil.tz")
    dateutil.parser = dateutil_parser
    dateutil.tz = dateutil_tz

    simplejson = types.ModuleType("simplejson")
    simplejson.dumps = stdlib_json.dumps
    simplejson.loads = stdlib_json.loads
    bs4 = types.ModuleType("bs4")
    bs4.BeautifulSoup = object
    bs4.UnicodeDammit = object
    ipwhois = types.ModuleType("ipwhois")
    ipwhois.IPWhois = object
    pytz = types.ModuleType("pytz")
    requests = types.ModuleType("requests")
    wizard_whois = types.ModuleType("wizard_whois")

    modules = {
        "phantom": phantom,
        "phantom.app": phantom_app,
        "phantom.rules": phantom_rules,
        "phantom.action_result": phantom_action_result,
        "phantom.base_connector": phantom_base_connector,
        "phantom.vault": phantom_vault,
        "dateutil": dateutil,
        "dateutil.parser": dateutil_parser,
        "dateutil.tz": dateutil_tz,
        "simplejson": simplejson,
        "bs4": bs4,
        "ipwhois": ipwhois,
        "pytz": pytz,
        "requests": requests,
        "wizard_whois": wizard_whois,
    }
    for name, module in modules.items():
        sys.modules.setdefault(name, module)


_install_import_stubs()
connector_module = importlib.import_module("threatstream_connector")


class FakeActionResult:
    def __init__(self):
        self.data = []
        self.status = None
        self.message = ""

    def add_data(self, value):
        self.data.append(value)

    def get_data(self):
        return self.data

    def set_status(self, status, message):
        self.status = status
        self.message = message
        return status

    def get_status(self):
        return self.status


class Response:
    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


class ThreatstreamSecurityTests(unittest.TestCase):
    def connector(self):
        connector = object.__new__(connector_module.ThreatstreamConnector)
        connector._state = {}
        connector.debug_print = mock.Mock()
        return connector

    def test_exact_lookup_uses_encoded_exact_parameter_and_drops_mismatches(self):
        connector = self.connector()
        connector._paginator = mock.Mock(
            return_value=[
                {"id": 1, "value": "requested"},
                {"id": 2, "value": "injected-result"},
            ]
        )
        result = FakeActionResult()

        status = connector._intel_details(result, exact_value="requested", limit=10)

        self.assertTrue(status)
        self.assertEqual(result.data, [{"id": 1, "value": "requested"}])
        payload = connector._paginator.call_args.kwargs["payload"]
        self.assertEqual(payload["value"], "requested")
        self.assertNotIn("q", payload)

    def test_external_reference_failure_fails_action(self):
        connector = self.connector()
        connector._make_rest_call = mock.Mock(return_value=(False, {}))
        result = FakeActionResult()

        status = connector._external_references("indicator", result)

        self.assertFalse(status)
        self.assertEqual(result.message, "Error retrieving external references")

    def test_enrichment_updates_existing_row_without_appending_none(self):
        connector = self.connector()
        connector._make_rest_call = mock.Mock(return_value=(True, {"insights": ["one"]}))
        result = FakeActionResult()
        result.add_data({"value": "indicator"})

        status = connector._insight("indicator", "domain", result)

        self.assertTrue(status)
        self.assertEqual(result.data, [{"value": "indicator", "insights": ["one"]}])

    def test_untracked_container_match_is_rejected(self):
        connector = self.connector()
        connector.get_phantom_base_url = mock.Mock(return_value="https://soar/")
        connector.get_asset_id = mock.Mock(return_value=7)

        with mock.patch.object(
            connector_module.requests,
            "get",
            return_value=Response({"count": 1, "data": [{"id": 99, "name": "12-test"}]}),
            create=True,
        ):
            status, container_id = connector._check_and_update_container_already_exists(12, "test")

        self.assertFalse(status)
        self.assertIsNone(container_id)

    def test_only_state_tracked_container_is_reused(self):
        connector = self.connector()
        connector._state = {"incident_container_ids": {"12": 99}}
        connector.get_phantom_base_url = mock.Mock(return_value="https://soar/")
        connector.get_asset_id = mock.Mock(return_value=7)

        with mock.patch.object(
            connector_module.requests,
            "get",
            return_value=Response({"count": 1, "data": [{"id": 99, "name": "12-test"}]}),
            create=True,
        ):
            status, container_id = connector._check_and_update_container_already_exists(12, "test")

        self.assertTrue(status)
        self.assertEqual(container_id, 99)


if __name__ == "__main__":
    unittest.main()
