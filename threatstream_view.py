# File: threatstream_view.py
# Copyright (c) 2016-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.


def _get_ctx_result(result, provides):

    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result['param'] = param
    ctx_result["action_name"] = provides
    if summary:
        ctx_result['summary'] = summary

    if not data:
        ctx_result['data'] = {}
        return ctx_result

    ctx_result['data'] = data

    return ctx_result


def display_view(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if not ctx_result:
                continue
            results.append(ctx_result)

    if provides == "get incident":
        ret_val = 'threatstream_get_incident.html'

    if provides == "get vulnerability":
        ret_val = 'threatstream_get_vulnerability.html'

    if provides == "update incident":
        ret_val = 'threatstream_update_incident.html'

    if provides == "detonate url" or provides == "detonate file":
        ret_val = 'threatstream_detonate_url.html'

    if provides == "get observable":
        ret_val = 'threatstream_get_observable.html'

    return ret_val
