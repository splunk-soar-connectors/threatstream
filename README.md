[comment]: # "Auto-generated SOAR connector documentation"
# ThreatStream

Publisher: Splunk  
Connector Version: 3\.5\.0  
Product Vendor: Anomali  
Product Name: ThreatStream  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.3  

Integrates a variety of generic, reputation, and investigative actions from the Anomali ThreatStream threat intelligence platform

[comment]: # " File: README.md"
[comment]: # " Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
**Playbook Backward Compatibility**

-   New action parameters have been added to the actions given below. Hence, it is requested to the
    end-user please update their existing playbooks and provide values to these new action
    parameters to ensure the correct functioning of the playbooks created on the earlier versions of
    the app.

      

    -   **For version 3.4.X :**

          

        -   Import domain observable - **source** parameter has been added
        -   Import URL observable - **source, allow_unresolved** parameters have been added
        -   Import IP observable - **source** parameter has been added
        -   Import file observable - **source** parameter has been added
        -   Import email observable - **source** parameter has been added
        -   Detonate file - **use_premium_sandbox, use_vmray_sandbox, vmray_max_jobs, fields**
            parameters have been added
        -   Detonate URL - **use_premium_sandbox, use_vmray_sandbox, vmray_max_jobs, fields**
            parameters have been added

    -   **For version 3.0.X :**

          

        -   Import domain observable - **with_approval, allow_unresolved** parameters have been
            added
        -   Import URL observable - **with_approval** parameter has been added
        -   Import IP observable - **with_approval** parameter has been added
        -   Import file observable - **with_approval** parameter has been added
        -   Import email observable - **with_approval** parameter has been added
        -   Import observables - **with_approval, allow_unresolved** parameters have been added
        -   List threat models - **publication_status** parameter has been added

    -   **For version 2.0.9 :**

          

        -   Create Incident - **create_on_cloud** parameter has been added
        -   Import domain observable - **create_on_cloud** parameter has been added
        -   Import URL observable - **create_on_cloud** parameter has been added
        -   Import IP observable - **create_on_cloud** parameter has been added
        -   Import file observable - **create_on_cloud** parameter has been added
        -   Import email observable - **create_on_cloud** parameter has been added
        -   Import observables - **create_on_cloud** parameter has been added

**Asset Configuration Parameters**

-   **is_cloud_instance** - This boolean parameter is used to indicate whether the Anomali
    Threatstream instance is on the cloud. If the parameter is left unchecked, the app and its
    functionalities will internally consider it as an on-prem instance.

**Prerequisite for \[Delete Incident / Delete Actor / Delete Vulnerability / Delete Rule / Delete
Threat Bulletin\] actions**

-   The authenticated user in the app should have appropriate permissions (Organization Admin) for
    deleting the incidents/actors/vulnerabilities/rules/threat-bulletins on the Anomali Threatstream
    instance for these actions to be executed successfully.

**Behavior for \[Whois IP\] action**

-   If the action can fetch additional whois data for the provided IP then, the action will pass
    successfully with that additional data.
-   If the action is unable to fetch additional whois data for the provided IP then, the action will
    pass successfully without that additional data but with an appropriate message.

**Behavior for Domain Reputation**

-   The action will try to find an intelligence with the same name provided in the \[domain\]
    parameter in the Anomali ThreatStream instance. If it is not found, then 'None' will be
    displayed under the corresponding columns in the output view.
-   If the provided domain is not found as intelligence in the Anomali ThreatStream instance, then
    the user needs to import a domain observable with the provided domain as input and then try to
    re-run the \[domain reputation\] action.

**On Poll Functionality**

-   It fetches the incidents (belonging to the configured organization ID in the configuration
    parameters) and their intelligence data to ingest them as containers and artifacts.

-   Approaches for fetching incidents based on the **Ingest only incidents marked published**
    configuration parameter

      

    -   Parameter kept unchecked: Ingesting all the incidents irrespective of their publication
        status
    -   Parameter kept checked: Ingesting the incidents which are only in the published state

-   Types of polling

      

    -   Manual Polling

          

        -   All the incidents are fetched, controlled by the count mentioned in the container_count
            parameter in the oldest first order based on the **modified_ts** value of the incidents
            irrespective of the incidents fetched in the last run. If the user tries to run the
            manual polling again with a value less than the already ingested incidents, then, again
            the same incidents will be fetched starting from the oldest first and will be marked as
            duplicates. It is recommended to run manual polling using a relatively greater value in
            the container_count parameter to ensure all the incidents are ingested.
        -   The **modified_ts** time of the last fetched incident is not considered for consequent
            runs of the manual polling.

    -   Scheduled \| Interval Polling

          

        -   Same functionality as manual polling along with the additional points mentioned below:

              

            -   **The maximum number of incidents to poll in the first run of the scheduled
                polling** configuration parameter governs the number of incidents fetched in the
                first run.
            -   The **modified_ts** time of the last fetched incident is stored in the
                **last_incident_time** key of the state file.
            -   For the consecutive runs, the incidents are fetched starting from the time stored in
                the **last_incident_time** key of the state file.
            -   Please provide a larger value in the **Maximum number of incidents to poll in the
                first run of the scheduled polling** configuration parameter to fetch all the
                existing (older) incidents in the first run itself. From the consecutive runs, the
                newly created or the modified incidents will be automatically ingested.

**Behavior for \[Create vulnerability / Update vulnerability / Create actor / Update Actor / Create
threat bulletin / Update threat bulletin\] actions**

-   Trusted circles are not available locally on On-prem (Hybrid) instance.

**Behavior for \[Create vulnerability / Update vulnerability / Create actor / Update Actor / Create
threat bulletin / Update threat bulletin / Create incident / Update incident\] actions**

-   The action uses different API endpoints for creating / updating an entity and associating
    intelligence, attachments, import sessions or comments to the entity.
-   If the action fails to associate the intelligence, attachments, import sessions or comments
    while creating an entity, the user can associate them by running the Update action with valid
    inputs.

**Confidence action parameter for import observable related actions**

-   For \[import file observable\] and \[import email observable\] actions user has to provide the
    confidence value in \[confidence\] action parameter.

-   For \[import domain observable\], \[import ip observable\], and \[import url observable\]
    actions ThreatStream automatically gives the confidence value based on some internal logical
    operations \| processes as per the API documentation.

-   For \[import observable\] action user can provide confidence value in 'fields' parameter as
    {"confidence": \<confidence_value>}.

      

    -   For hash and email type of observable, the value of the confidence will be reflected.
    -   For domain, IP, and URL type of observable, the value of the confidence will be ignored.

**Behavior of import\_\<indicator_type>\_observable and the import_observables actions**

-   The action run just sends a request for importing the observable value to the Anomali server.

-   The action run is a success if a response of **202 Accepted** is returned by the Anomali API.
    The action does not wait for the observable to reflect on the Anomali UI.

-   The successful run of the actions does not guarantee the successful import of the observable on
    the Anomali server

      

    -   If the provided parameters and their expected combinations are correct, then the observable
        will be successfully imported after an indefinite interval of time (based on the Anomali
        server).
    -   If the provided parameters and their combinations are incorrect, then the action run would
        be a success (because the API does not return an error response for this and accepts the
        request) though the observable is not imported on the Anomali server.

-   It is recommended to add a required time delay between the action blocks which are dependent on
    the successful import of an observable.

-   To check if the observable was successfully imported, the user can run and check the **List
    Observables** action which fetches the observables in the latest first order (based on
    **created_ts** time).

**List of indicator types (itype) for the import\_\<indicator_type>\_observable and the
import_observables actions (To be given as input when with_approval parameter is set to False)**

| actor_ip                | actor_ipv6           | adware_domain           | adware_registry_key         |
|-------------------------|----------------------|-------------------------|-----------------------------|
| anon_proxy              | anon_proxy_ipv6      | anon_vpn                | anon_vpn_ipv6               |
| apt_domain              | apt_email            | apt_file_name           | apt_file_path               |
| apt_ip                  | apt_ipv6             | apt_md5                 | apt_mta                     |
| apt_mutex               | apt_registry_key     | apt_service_description | apt_service_displayname     |
| apt_service_name        | apt_ssdeep           | apt_subject             | apt_ua                      |
| apt_url                 | bot_ip               | bot_ipv6                | brute_ip                    |
| brute_ipv6              | c2_domain            | c2_ip                   | c2_ipv6                     |
| c2_url                  | comm_proxy_domain    | comm_proxy_ip           | compromised_domain          |
| compromised_email       | compromised_ip       | compromised_ipv6        | compromised_service_account |
| compromised_url         | crypto_hash          | crypto_ip               | crypto_pool                 |
| crypto_url              | crypto_wallet        | ddos_ip                 | ddos_ipv6                   |
| disposable_email_domain | dyn_dns              | exfil_domain            | exfil_ip                    |
| exfil_ipv6              | exfil_url            | exploit_domain          | exploit_ip                  |
| exploit_ipv6            | exploit_url          | fraud_domain            | fraud_ip                    |
| fraud_md5               | fraud_email          | fraud_url               | free_email_domain           |
| geolocation_url         | hack_tool            | i2p_ip                  | i2p_ipv6                    |
| ipcheck_url             | mal_domain           | mal_email               | mal_file_name               |
| mal_file_path           | mal_ip               | mal_ipv6                | mal_md5                     |
| mal_mutex               | mal_registry_key     | mal_service_description | mal_service_displayname     |
| mal_service_name        | mal_ssdeep           | mal_sslcert_sh1         | mal_ua                      |
| mal_url                 | p2pcnc               | p2pcnc_ipv6             | parked_domain               |
| parked_ip               | parked_ipv6          | parked_url              | pastesite_url               |
| phish_domain            | phish_email          | phish_ip                | phish_ipv6                  |
| phish_md5               | phish_url            | proxy_ip                | proxy_ipv6                  |
| scan_ip                 | scan_ipv6            | sinkhole_domain         | sinkhole_ip                 |
| sinkhole_ipv6           | social_media_url     | spam_domain             | spam_email                  |
| spam_ip                 | spam_ipv6            | spam_mta                | spam_url                    |
| speedtest_url           | ssh_ip               | ssh_ipv6                | ssl_cert_serial_number      |
| suppress                | suspicious_domain    | suspicious_email        | suspicious_ip               |
| suspicious_reg_email    | suspicious_url       | tor_ip                  | tor_ipv6                    |
| torrent_tracker_url     | vpn_domain           | vps_ip                  | vps_ipv6                    |
| whois_bulk_reg_email    | whois_privacy_domain | whois_privacy_email     |                             |

**NOTE:** If the input contains any indicator_type value except the ones listed above, the action
will behave according to the API behavior.

**List of threat types (threat_type) for the import\_\<indicator_type>\_observable and the
import_observables actions (To be given as input when with_approval parameter is set to True)**

| adware | anomalous     | anonymization | apt         |
|--------|---------------|---------------|-------------|
| bot    | brute         | c2            | compromised |
| crypto | data_leakage  | ddos          | dyn_dns     |
| exfil  | exploit       | fraud         | hack_tool   |
| i2p    | informational | malware       | p2p         |
| parked | phish         | scan          | sinkhole    |
| spam   | suppress      | suspicious    | tor         |
| vps    |               |               |             |

**NOTE:** If the input contains any threat_type value except the ones listed above, the action will
behave according to the API behavior.

## Port Information

The app uses HTTP/HTTPS protocol for communicating with the ThreatStream Server. Below are the
default ports used by Splunk SOAR.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |

## ipwhois

This app uses the ipwhois module, which is licensed under the BSD License, Copyright (c) 2013-2019
Philip Hane.

## wizard-whois

This app uses the wizard-whois module, which is licensed under the MIT License, Copyright (c)
Michael Ramsey.

## dnspython

This app uses the dns module, which is licensed under the Freeware (BSD-like) License, Copyright (c)
2018 Bob Halley.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a ThreatStream asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**hostname** |  required  | string | Host Name
**organization\_id** |  optional  | numeric | Organization ID for filtering incidents when polling
**username** |  required  | string | User name
**api\_key** |  required  | password | API Key
**first\_run\_containers** |  optional  | numeric | Maximum number of incidents to poll in the first run of the scheduled polling
**ingest\_only\_published\_incidents** |  optional  | boolean | Ingest only incidents marked as published
**is\_cloud\_instance** |  optional  | boolean | Is the provided instance in hostname parameter cloud?
**verify\_server\_cert** |  optional  | boolean | Verify server certificate

### Supported Actions  
[test connectivity](#action-test-connectivity) - Test connectivity to ThreatStream by querying the intelligence endpoint  
[file reputation](#action-file-reputation) - Get information about a file  
[domain reputation](#action-domain-reputation) - Get information about a given domain  
[ip reputation](#action-ip-reputation) - Get information about a given IP  
[email reputation](#action-email-reputation) - Get information about a given email  
[url reputation](#action-url-reputation) - Get information about a URL  
[whois ip](#action-whois-ip) - Execute a whois lookup on the given IP  
[whois domain](#action-whois-domain) - Execute a whois lookup on the given domain  
[get observable](#action-get-observable) - Get observable present in ThreatStream by ID number  
[list observables](#action-list-observables) - List observables present in ThreatStream  
[get vulnerability](#action-get-vulnerability) - Get vulnerability present in ThreatStream by ID number  
[list vulnerabilities](#action-list-vulnerabilities) - List vulnerabilities present in ThreatStream  
[list incidents](#action-list-incidents) - List incidents present in ThreatStream  
[delete incident](#action-delete-incident) - Delete incident in ThreatStream by ID number  
[get incident](#action-get-incident) - Get incident in ThreatStream by ID number  
[create incident](#action-create-incident) - Create an incident in ThreatStream  
[update incident](#action-update-incident) - Update an incident in ThreatStream by ID number  
[import domain observable](#action-import-domain-observable) - Import domain observable into ThreatStream  
[import url observable](#action-import-url-observable) - Import URL observable into ThreatStream  
[import ip observable](#action-import-ip-observable) - Import IP observable into ThreatStream  
[import file observable](#action-import-file-observable) - Import file observable into ThreatStream  
[import email observable](#action-import-email-observable) - Import email observable into ThreatStream  
[import observables](#action-import-observables) - Import observables into ThreatStream  
[tag observable](#action-tag-observable) - Add a tag to the observable  
[get pcap](#action-get-pcap) - Download pcap file of a sample submitted to the sandbox and add it to vault  
[detonate file](#action-detonate-file) - Detonate file in ThreatStream  
[detonate url](#action-detonate-url) - Detonate URL in ThreatStream  
[get status](#action-get-status) - Retrieve detonation status present in Threatstream  
[get report](#action-get-report) - Retrieve detonation report present in Threatstream  
[on poll](#action-on-poll) - Callback action for the on\_poll ingest functionality  
[run query](#action-run-query) - Run observables query in ThreatStream  
[list import sessions](#action-list-import-sessions) - List all the import sessions  
[update import session](#action-update-import-session) - This action updates the fields of the provided item id  
[list threat models](#action-list-threat-models) - List all the threat models  
[create threat bulletin](#action-create-threat-bulletin) - Create a threat bulletin in ThreatStream  
[update threat bulletin](#action-update-threat-bulletin) - Update a threat bulletin in ThreatStream  
[list threat bulletins](#action-list-threat-bulletins) - List threat bulletins present in ThreatStream  
[list associations](#action-list-associations) - List associations of an entity present in ThreatStream  
[create rule](#action-create-rule) - Creates a new rule in Threatstream  
[update rule](#action-update-rule) - Update a rule in ThreatStream by ID number  
[list rules](#action-list-rules) - List rules present in ThreatStream  
[delete rule](#action-delete-rule) - Delete rule in ThreatStream by ID number  
[add association](#action-add-association) - Create associations between threat model entities on the ThreatStream platform  
[remove association](#action-remove-association) - Remove associations between threat model entities on the ThreatStream platform  
[list actors](#action-list-actors) - List actors present in ThreatStream  
[list imports](#action-list-imports) - List imports present in ThreatStream  
[create vulnerability](#action-create-vulnerability) - Create a vulnerability in ThreatStream  
[update vulnerability](#action-update-vulnerability) - Update the vulnerability in ThreatStream  
[create actor](#action-create-actor) - Create an actor in ThreatStream  
[update actor](#action-update-actor) - Update an actor in ThreatStream  
[delete threat bulletin](#action-delete-threat-bulletin) - Delete threat bulletin in ThreatStream by ID  
[delete vulnerability](#action-delete-vulnerability) - Delete vulnerability in ThreatStream by ID  
[delete actor](#action-delete-actor) - Delete actor in ThreatStream by ID number  
[update observable](#action-update-observable) - Update an observable in ThreatStream  
[create investigation](#action-create-investigation) - Create an investigation in ThreatStream  
[list investigations](#action-list-investigations) - List investigations present in ThreatStream  
[get investigation](#action-get-investigation) - Retrieve investigation present in Threatstream by ID  
[update investigation](#action-update-investigation) - Update an investigation in ThreatStream  
[delete investigation](#action-delete-investigation) - Delete investigation in ThreatStream by ID number  

## action: 'test connectivity'
Test connectivity to ThreatStream by querying the intelligence endpoint

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'file reputation'
Get information about a file

Type: **investigate**  
Read only: **True**

If nothing is found, this is because ThreatStream has no information on that file\. If the limit parameter is not provided, then the default value \(1000\) will be considered as the value of the limit parameter\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | Hash of file | string |  `sha1`  `sha256`  `md5`  `hash` 
**limit** |  optional  | Total number of observables to return | numeric | 
**extend\_source** |  optional  | Fetch extra data from Anomali server if available | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.extend\_source | boolean | 
action\_result\.parameter\.hash | string |  `sha1`  `sha256`  `md5`  `hash` 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.asn | string | 
action\_result\.data\.\*\.confidence | numeric | 
action\_result\.data\.\*\.country | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.expiration\_ts | string | 
action\_result\.data\.\*\.extended\_source | string | 
action\_result\.data\.\*\.external\_references\.VirusTotal | string | 
action\_result\.data\.\*\.external\_references\.remote\_api | boolean | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `threatstream intelligence id` 
action\_result\.data\.\*\.import\_session\_id | string | 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.itype | string | 
action\_result\.data\.\*\.latitude | string | 
action\_result\.data\.\*\.longitude | string | 
action\_result\.data\.\*\.meta\.detail2 | string | 
action\_result\.data\.\*\.meta\.severity | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.org | string | 
action\_result\.data\.\*\.owner\_organization\_id | numeric |  `threatstream organization id` 
action\_result\.data\.\*\.rdns | string | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.retina\_confidence | numeric | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.source\_reported\_confidence | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.org\_id | string | 
action\_result\.data\.\*\.tags\.\*\.source\_user | string | 
action\_result\.data\.\*\.tags\.\*\.source\_user\_id | string | 
action\_result\.data\.\*\.threat\_type | string | 
action\_result\.data\.\*\.threatscore | numeric | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.trusted\_circle\_ids | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.update\_id | numeric | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.value | string |  `md5` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'domain reputation'
Get information about a given domain

Type: **investigate**  
Read only: **True**

If nothing is found, this may be due to the format of the domain\. Try excluding any subdomains \(namely www\)\. If there is still no information found, then it is because ThreatStream has no information on that domain\. ThreatStream, however, may still have Passive DNS \(PDNS\) information on it, which can be found in extra data\. If the limit parameter is not provided, then the default value \(1000\) will be considered as the value of the limit parameter\.<br>Extra data includes PDNS, insights, and external resources\. By default, extra data is not included in the response\. You can update the flag params to include the extra data\. The <b>search\_exact\_value</b> parameter searches for the exact domain on ThreatStream server\. If this parameter is kept <b>true</b>, then the <b>extend\_source</b> parameter will be ignored and no extra information will be available\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to investigate | string |  `domain`  `url` 
**limit** |  optional  | Total number of observables to return | numeric | 
**extend\_source** |  optional  | Fetch extra data from Anomali server if available | boolean | 
**pdns** |  optional  | If enabled, pdns will also be fetched | boolean | 
**insights** |  optional  | If enabled, insights will also be fetched | boolean | 
**external\_references** |  optional  | If enabled, external references will also be fetched | boolean | 
**search\_exact\_value** |  optional  | Search for the exact domain | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.parameter\.extend\_source | boolean | 
action\_result\.parameter\.external\_references | boolean | 
action\_result\.parameter\.insights | boolean | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.pdns | boolean | 
action\_result\.parameter\.search\_exact\_value | boolean | 
action\_result\.data\.\*\.asn | string | 
action\_result\.data\.\*\.confidence | numeric | 
action\_result\.data\.\*\.country | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.expiration\_ts | string | 
action\_result\.data\.\*\.extended\_source | string | 
action\_result\.data\.\*\.external\_references\.Google Safe Browsing | string | 
action\_result\.data\.\*\.external\_references\.URLVoid | string | 
action\_result\.data\.\*\.external\_references\.VirusTotal | string | 
action\_result\.data\.\*\.external\_references\.Web of Trust | string | 
action\_result\.data\.\*\.external\_references\.urlscan\.io | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `threatstream intelligence id` 
action\_result\.data\.\*\.import\_session\_id | string | 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.itype | string | 
action\_result\.data\.\*\.latitude | string | 
action\_result\.data\.\*\.longitude | string | 
action\_result\.data\.\*\.meta\.detail2 | string | 
action\_result\.data\.\*\.meta\.severity | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.org | string | 
action\_result\.data\.\*\.owner\_organization\_id | numeric |  `threatstream organization id` 
action\_result\.data\.\*\.rdns | string | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.retina\_confidence | numeric | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.source\_reported\_confidence | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.org\_id | string | 
action\_result\.data\.\*\.tags\.\*\.source\_user | string | 
action\_result\.data\.\*\.tags\.\*\.source\_user\_id | string | 
action\_result\.data\.\*\.threat\_type | string | 
action\_result\.data\.\*\.threatscore | numeric | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.trusted\_circle\_ids | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.update\_id | numeric | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.value | string |  `domain` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'ip reputation'
Get information about a given IP

Type: **investigate**  
Read only: **True**

If nothing is found, then it is because ThreatStream has no information on that IP\. ThreatStream, however, may still have Passive DNS \(PDNS\) information on it, which can be found in extra data\. If the limit parameter is not provided, then the default value \(1000\) will be considered as the value of the limit parameter\.<br>Extra data includes PDNS, insights, and external resources\. By default, extra data is not included in the response\. You can update the flag params to include the extra data\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to investigate | string |  `ip`  `ipv6` 
**limit** |  optional  | Total number of observables to return | numeric | 
**extend\_source** |  optional  | Fetch extra data from Anomali server if available | boolean | 
**pdns** |  optional  | If enabled, pdns will also be fetched | boolean | 
**insights** |  optional  | If enabled, insights will also be fetched | boolean | 
**external\_references** |  optional  | If enabled, external references will also be fetched | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.extend\_source | boolean | 
action\_result\.parameter\.external\_references | boolean | 
action\_result\.parameter\.insights | boolean | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.pdns | boolean | 
action\_result\.data\.\*\.asn | string | 
action\_result\.data\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.confidence | numeric | 
action\_result\.data\.\*\.country | string | 
action\_result\.data\.\*\.created\_by | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.expiration\_ts | string | 
action\_result\.data\.\*\.extended\_source | string | 
action\_result\.data\.\*\.external\_references\.Google Safe Browsing | string | 
action\_result\.data\.\*\.external\_references\.IPVoid | string | 
action\_result\.data\.\*\.external\_references\.Shodan | string | 
action\_result\.data\.\*\.external\_references\.VirusTotal | string | 
action\_result\.data\.\*\.external\_references\.remote\_api | boolean | 
action\_result\.data\.\*\.external\_references\.urlscan\.io | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `threatstream intelligence id` 
action\_result\.data\.\*\.import\_session\_id | numeric | 
action\_result\.data\.\*\.import\_source | string | 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.itype | string | 
action\_result\.data\.\*\.latitude | string | 
action\_result\.data\.\*\.longitude | string | 
action\_result\.data\.\*\.meta\.detail | string | 
action\_result\.data\.\*\.meta\.detail2 | string | 
action\_result\.data\.\*\.meta\.severity | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.org | string | 
action\_result\.data\.\*\.owner\_organization\_id | numeric |  `threatstream organization id` 
action\_result\.data\.\*\.rdns | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.retina\_confidence | numeric | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.source\_reported\_confidence | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.subtype | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.org\_id | string | 
action\_result\.data\.\*\.tags\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\.\*\.source\_user | string | 
action\_result\.data\.\*\.tags\.\*\.source\_user\_id | string | 
action\_result\.data\.\*\.tags\.\*\.tlp | string | 
action\_result\.data\.\*\.threat\_type | string | 
action\_result\.data\.\*\.threatscore | numeric | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.trusted\_circle\_ids | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.update\_id | numeric | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.value | string |  `ip` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'email reputation'
Get information about a given email

Type: **investigate**  
Read only: **True**

If the limit parameter is not provided, then the default value \(1000\) will be considered as the value of the limit parameter\. The <b>search\_exact\_value</b> parameter searches for the exact email on ThreatStream server\. If this parameter is kept <b>true</b>, then the <b>extend\_source</b> parameter will be ignored and no extra information will be available\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Email to investigate | string |  `email` 
**limit** |  optional  | Total number of observables to return | numeric | 
**extend\_source** |  optional  | Fetch extra data from Anomali server if available | boolean | 
**search\_exact\_value** |  optional  | Search for the exact email | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.parameter\.extend\_source | boolean | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.search\_exact\_value | boolean | 
action\_result\.data\.\*\.asn | string | 
action\_result\.data\.\*\.confidence | numeric | 
action\_result\.data\.\*\.country | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.expiration\_ts | string | 
action\_result\.data\.\*\.extended\_source | string | 
action\_result\.data\.\*\.external\_references\.remote\_api | boolean | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `threatstream intelligence id` 
action\_result\.data\.\*\.import\_session\_id | string | 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.itype | string | 
action\_result\.data\.\*\.latitude | string | 
action\_result\.data\.\*\.longitude | string | 
action\_result\.data\.\*\.meta\.detail | string | 
action\_result\.data\.\*\.meta\.detail2 | string | 
action\_result\.data\.\*\.meta\.severity | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.org | string | 
action\_result\.data\.\*\.owner\_organization\_id | numeric |  `threatstream organization id` 
action\_result\.data\.\*\.rdns | string | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.retina\_confidence | numeric | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.source\_reported\_confidence | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.org\_id | string | 
action\_result\.data\.\*\.tags\.\*\.source\_user | string | 
action\_result\.data\.\*\.tags\.\*\.source\_user\_id | string | 
action\_result\.data\.\*\.threat\_type | string | 
action\_result\.data\.\*\.threatscore | numeric | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.trusted\_circle\_ids | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.update\_id | numeric | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.value | string |  `email` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'url reputation'
Get information about a URL

Type: **investigate**  
Read only: **True**

If nothing is found, this is because ThreatStream has no information on that URL\. If the limit parameter is not provided, then the default value \(1000\) will be considered as the value of the limit parameter\. The <b>search\_exact\_value</b> parameter searches for the exact url on ThreatStream server\. If this parameter is kept <b>true</b>, then the <b>extend\_source</b> parameter will be ignored and no extra information will be available\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to investigate | string |  `url` 
**limit** |  optional  | Total number of observables to return | numeric | 
**extend\_source** |  optional  | Fetch extra data from Anomali server if available | boolean | 
**search\_exact\_value** |  optional  | Search for the exact url | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.extend\_source | boolean | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.parameter\.search\_exact\_value | boolean | 
action\_result\.data\.\*\.asn | string | 
action\_result\.data\.\*\.confidence | numeric | 
action\_result\.data\.\*\.country | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.expiration\_ts | string | 
action\_result\.data\.\*\.extended\_source | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `threatstream intelligence id` 
action\_result\.data\.\*\.import\_session\_id | numeric | 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.itype | string | 
action\_result\.data\.\*\.latitude | numeric | 
action\_result\.data\.\*\.longitude | numeric | 
action\_result\.data\.\*\.meta\.detail | string | 
action\_result\.data\.\*\.meta\.detail2 | string | 
action\_result\.data\.\*\.meta\.registrant\_address | string | 
action\_result\.data\.\*\.meta\.registrant\_created | string | 
action\_result\.data\.\*\.meta\.registrant\_email | string | 
action\_result\.data\.\*\.meta\.registrant\_name | string | 
action\_result\.data\.\*\.meta\.registrant\_org | string | 
action\_result\.data\.\*\.meta\.registrant\_phone | string | 
action\_result\.data\.\*\.meta\.registrant\_updated | string | 
action\_result\.data\.\*\.meta\.severity | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.org | string | 
action\_result\.data\.\*\.owner\_organization\_id | numeric |  `threatstream organization id` 
action\_result\.data\.\*\.rdns | string | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.retina\_confidence | numeric | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.source\_reported\_confidence | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.org\_id | string | 
action\_result\.data\.\*\.tags\.\*\.source\_user | string | 
action\_result\.data\.\*\.tags\.\*\.source\_user\_id | string | 
action\_result\.data\.\*\.threat\_type | string | 
action\_result\.data\.\*\.threatscore | numeric | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.trusted\_circle\_ids | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.update\_id | numeric | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.value | string |  `url` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'whois ip'
Execute a whois lookup on the given IP

Type: **investigate**  
Read only: **True**

ThreatStream returns whois info as a raw string \(present in the raw field\) which the app will then attempt to parse into the output\. Depending on the contents of the raw string, it may not be able to parse all or any of the required fields\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.addtional\_info | string | 
action\_result\.data\.\*\.addtional\_info\.asn | string | 
action\_result\.data\.\*\.addtional\_info\.asn\_cidr | string | 
action\_result\.data\.\*\.addtional\_info\.asn\_country\_code | string | 
action\_result\.data\.\*\.addtional\_info\.asn\_date | string | 
action\_result\.data\.\*\.addtional\_info\.asn\_description | string | 
action\_result\.data\.\*\.addtional\_info\.asn\_registry | string | 
action\_result\.data\.\*\.addtional\_info\.nets\.\*\.address | string | 
action\_result\.data\.\*\.addtional\_info\.nets\.\*\.cidr | string | 
action\_result\.data\.\*\.addtional\_info\.nets\.\*\.city | string | 
action\_result\.data\.\*\.addtional\_info\.nets\.\*\.country | string | 
action\_result\.data\.\*\.addtional\_info\.nets\.\*\.created | string | 
action\_result\.data\.\*\.addtional\_info\.nets\.\*\.description | string | 
action\_result\.data\.\*\.addtional\_info\.nets\.\*\.emails | string |  `email` 
action\_result\.data\.\*\.addtional\_info\.nets\.\*\.handle | string | 
action\_result\.data\.\*\.addtional\_info\.nets\.\*\.name | string | 
action\_result\.data\.\*\.addtional\_info\.nets\.\*\.postal\_code | string | 
action\_result\.data\.\*\.addtional\_info\.nets\.\*\.range | string | 
action\_result\.data\.\*\.addtional\_info\.nets\.\*\.state | string | 
action\_result\.data\.\*\.addtional\_info\.nets\.\*\.updated | string | 
action\_result\.data\.\*\.addtional\_info\.nir | string | 
action\_result\.data\.\*\.addtional\_info\.query | string |  `ip` 
action\_result\.data\.\*\.addtional\_info\.raw | string | 
action\_result\.data\.\*\.addtional\_info\.raw\_referral | string | 
action\_result\.data\.\*\.addtional\_info\.referral | string | 
action\_result\.data\.\*\.contacts\.admin\.handle | string | 
action\_result\.data\.\*\.contacts\.billing | string | 
action\_result\.data\.\*\.contacts\.registrant | string | 
action\_result\.data\.\*\.contacts\.registrant\.name | string | 
action\_result\.data\.\*\.contacts\.tech\.handle | string | 
action\_result\.data\.\*\.emails | string |  `email` 
action\_result\.data\.\*\.raw | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.updated\_date | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'whois domain'
Execute a whois lookup on the given domain

Type: **investigate**  
Read only: **True**

ThreatStream returns whois info as a raw string \(present in the raw field\) which the app will then attempt to parse into the output\. Depending on the contents of the raw string, it may not be able to parse all or any of the required fields\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.data\.\*\.contacts\.admin | string | 
action\_result\.data\.\*\.contacts\.admin\.city | string | 
action\_result\.data\.\*\.contacts\.admin\.country | string | 
action\_result\.data\.\*\.contacts\.admin\.email | string |  `email` 
action\_result\.data\.\*\.contacts\.admin\.fax | string | 
action\_result\.data\.\*\.contacts\.admin\.fax\_ext | string | 
action\_result\.data\.\*\.contacts\.admin\.handle | string | 
action\_result\.data\.\*\.contacts\.admin\.name | string | 
action\_result\.data\.\*\.contacts\.admin\.organization | string | 
action\_result\.data\.\*\.contacts\.admin\.phone | string | 
action\_result\.data\.\*\.contacts\.admin\.postalcode | string | 
action\_result\.data\.\*\.contacts\.admin\.state | string | 
action\_result\.data\.\*\.contacts\.admin\.street | string | 
action\_result\.data\.\*\.contacts\.billing | string | 
action\_result\.data\.\*\.contacts\.registrant | string | 
action\_result\.data\.\*\.contacts\.registrant\.city | string | 
action\_result\.data\.\*\.contacts\.registrant\.country | string | 
action\_result\.data\.\*\.contacts\.registrant\.email | string |  `email` 
action\_result\.data\.\*\.contacts\.registrant\.fax | string | 
action\_result\.data\.\*\.contacts\.registrant\.fax\_ext | string | 
action\_result\.data\.\*\.contacts\.registrant\.handle | string | 
action\_result\.data\.\*\.contacts\.registrant\.name | string | 
action\_result\.data\.\*\.contacts\.registrant\.organization | string | 
action\_result\.data\.\*\.contacts\.registrant\.phone | string | 
action\_result\.data\.\*\.contacts\.registrant\.postalcode | string | 
action\_result\.data\.\*\.contacts\.registrant\.state | string | 
action\_result\.data\.\*\.contacts\.registrant\.street | string | 
action\_result\.data\.\*\.contacts\.tech | string | 
action\_result\.data\.\*\.contacts\.tech\.city | string | 
action\_result\.data\.\*\.contacts\.tech\.country | string | 
action\_result\.data\.\*\.contacts\.tech\.email | string |  `email` 
action\_result\.data\.\*\.contacts\.tech\.fax | string | 
action\_result\.data\.\*\.contacts\.tech\.fax\_ext | string | 
action\_result\.data\.\*\.contacts\.tech\.handle | string | 
action\_result\.data\.\*\.contacts\.tech\.name | string | 
action\_result\.data\.\*\.contacts\.tech\.organization | string | 
action\_result\.data\.\*\.contacts\.tech\.phone | string | 
action\_result\.data\.\*\.contacts\.tech\.postalcode | string | 
action\_result\.data\.\*\.contacts\.tech\.state | string | 
action\_result\.data\.\*\.contacts\.tech\.street | string | 
action\_result\.data\.\*\.creation\_date | string | 
action\_result\.data\.\*\.emails | string |  `email` 
action\_result\.data\.\*\.expiration\_date | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.nameservers | string | 
action\_result\.data\.\*\.raw | string | 
action\_result\.data\.\*\.registrar | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.updated\_date | string | 
action\_result\.data\.\*\.whois\_server | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get observable'
Get observable present in ThreatStream by ID number

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**intelligence\_id** |  required  | ID number of intelligence to return | string |  `threatstream intelligence id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.intelligence\_id | string |  `threatstream intelligence id` 
action\_result\.data\.\*\.asn | string | 
action\_result\.data\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.confidence | numeric | 
action\_result\.data\.\*\.country | string | 
action\_result\.data\.\*\.created\_by | string |  `email` 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.expiration\_ts | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `threatstream intelligence id` 
action\_result\.data\.\*\.import\_session\_id | string | 
action\_result\.data\.\*\.import\_source | string | 
action\_result\.data\.\*\.ip | string | 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.itype | string | 
action\_result\.data\.\*\.latitude | string | 
action\_result\.data\.\*\.longitude | string | 
action\_result\.data\.\*\.meta\.detail2 | string | 
action\_result\.data\.\*\.meta\.severity | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.org | string | 
action\_result\.data\.\*\.owner\_organization\_id | numeric | 
action\_result\.data\.\*\.rdns | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.retina\_confidence | numeric | 
action\_result\.data\.\*\.source | string |  `email` 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.source\_reported\_confidence | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.subtype | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.org\_id | string | 
action\_result\.data\.\*\.tags\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\.\*\.tlp | string | 
action\_result\.data\.\*\.threat\_type | string | 
action\_result\.data\.\*\.threatscore | numeric | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.trusted\_circle\_ids | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.update\_id | numeric | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.value | string |  `email` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list observables'
List observables present in ThreatStream

Type: **investigate**  
Read only: **True**

<ul><li>The observables will be listed in the latest first order on the basis of created\_ts\.</li><li>If the limit parameter is not provided, then the default value \(1000\) will be considered as the value of the limit parameter\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Total number of observables to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.asn | string | 
action\_result\.data\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.confidence | numeric | 
action\_result\.data\.\*\.country | string | 
action\_result\.data\.\*\.created\_by | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.expiration\_ts | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `threatstream intelligence id` 
action\_result\.data\.\*\.import\_session\_id | string | 
action\_result\.data\.\*\.import\_source | string | 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.itype | string | 
action\_result\.data\.\*\.latitude | string | 
action\_result\.data\.\*\.longitude | string | 
action\_result\.data\.\*\.meta\.detail | string | 
action\_result\.data\.\*\.meta\.detail2 | string | 
action\_result\.data\.\*\.meta\.registrant\_address | string | 
action\_result\.data\.\*\.meta\.registrant\_created | string | 
action\_result\.data\.\*\.meta\.registrant\_email | string | 
action\_result\.data\.\*\.meta\.registrant\_name | string | 
action\_result\.data\.\*\.meta\.registrant\_org | string | 
action\_result\.data\.\*\.meta\.registrant\_phone | string | 
action\_result\.data\.\*\.meta\.registrant\_updated | string | 
action\_result\.data\.\*\.meta\.registrantion\_created | string | 
action\_result\.data\.\*\.meta\.registrantion\_updated | string | 
action\_result\.data\.\*\.meta\.registration\_created | string | 
action\_result\.data\.\*\.meta\.registration\_updated | string | 
action\_result\.data\.\*\.meta\.severity | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.org | string | 
action\_result\.data\.\*\.owner\_organization\_id | numeric | 
action\_result\.data\.\*\.rdns | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.retina\_confidence | numeric | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.source\_reported\_confidence | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.subtype | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.org\_id | string | 
action\_result\.data\.\*\.tags\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\.\*\.tlp | string | 
action\_result\.data\.\*\.threat\_type | string | 
action\_result\.data\.\*\.threatscore | numeric | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.trusted\_circle\_ids | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.update\_id | numeric | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.value | string | 
action\_result\.summary\.observables\_returned | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get vulnerability'
Get vulnerability present in ThreatStream by ID number

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vulnerability\_id** |  required  | ID number of vulnerability to return | string |  `threatstream vulnerability id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.vulnerability\_id | string |  `threatstream vulnerability id` 
action\_result\.data\.\*\.aliases | string | 
action\_result\.data\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.body\_content\_type | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.cvss2\_score | string | 
action\_result\.data\.\*\.cvss3\_score | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.embedded\_content\_type | string | 
action\_result\.data\.\*\.embedded\_content\_url | string | 
action\_result\.data\.\*\.feed\_id | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.is\_system | boolean | 
action\_result\.data\.\*\.logo\_s3\_url | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.organization\.id | string | 
action\_result\.data\.\*\.organization\.name | string | 
action\_result\.data\.\*\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.organization\_id | numeric |  `threatstream organization id` 
action\_result\.data\.\*\.owner\_user\.email | string |  `email` 
action\_result\.data\.\*\.owner\_user\.id | string | 
action\_result\.data\.\*\.owner\_user\.name | string | 
action\_result\.data\.\*\.owner\_user\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_user\_id | numeric | 
action\_result\.data\.\*\.parent | string | 
action\_result\.data\.\*\.publication\_status | string | 
action\_result\.data\.\*\.published\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.starred\_by\_me | boolean | 
action\_result\.data\.\*\.starred\_total\_count | numeric | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.update\_id | string | 
action\_result\.data\.\*\.votes\.me | string | 
action\_result\.data\.\*\.votes\.total | numeric | 
action\_result\.data\.\*\.watched\_by\_me | boolean | 
action\_result\.data\.\*\.watched\_total\_count | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list vulnerabilities'
List vulnerabilities present in ThreatStream

Type: **investigate**  
Read only: **True**

<ul><li>The vulnerabilities will be listed in the latest first order on the basis of created\_ts\.</li><li>If the limit parameter is not provided, then the default value \(1000\) will be considered as the value of the limit parameter\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Total number of vulnerabilities to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.circles\.\*\.id | string | 
action\_result\.data\.\*\.circles\.\*\.name | string | 
action\_result\.data\.\*\.circles\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.circles\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.embedded\_content\_url | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `threatstream vulnerability id` 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.is\_system | boolean | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.organization\.id | string |  `threatstream organization id` 
action\_result\.data\.\*\.organization\.name | string | 
action\_result\.data\.\*\.organization\.title | string | 
action\_result\.data\.\*\.organization\_id | numeric |  `threatstream organization id` 
action\_result\.data\.\*\.owner\_user\_id | numeric | 
action\_result\.data\.\*\.publication\_status | string | 
action\_result\.data\.\*\.published\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.id | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.name | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.tags\_v2\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\_v2\.\*\.tlp | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.update\_id | numeric | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.summary\.vulnerabilities\_returned | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list incidents'
List incidents present in ThreatStream

Type: **investigate**  
Read only: **True**

<ul><li>The incidents will be listed in the latest first order on the basis of created\_ts\.</li><li>If the limit parameter is not provided, then the default value \(1000\) will be considered as the value of the limit parameter\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**intel\_value** |  optional  | Intelligence value to filter incidents \(ie\. google\.com\) | string | 
**limit** |  optional  | Total number of incidents to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.intel\_value | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.circles\.\*\.id | string | 
action\_result\.data\.\*\.circles\.\*\.name | string | 
action\_result\.data\.\*\.circles\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.end\_date | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `threatstream incident id` 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.organization\_id | numeric |  `threatstream organization id` 
action\_result\.data\.\*\.owner\_user\_id | numeric | 
action\_result\.data\.\*\.parent\.id | string | 
action\_result\.data\.\*\.parent\.name | string | 
action\_result\.data\.\*\.parent\.recource\_uri | string | 
action\_result\.data\.\*\.publication\_status | string | 
action\_result\.data\.\*\.published\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.starred\_by\_me | boolean | 
action\_result\.data\.\*\.starred\_total\_count | numeric | 
action\_result\.data\.\*\.start\_date | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.status\.display\_name | string | 
action\_result\.data\.\*\.status\.id | numeric | 
action\_result\.data\.\*\.status\.resource\_uri | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.id | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.name | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.tags\_v2\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\_v2\.\*\.tlp | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.votes\.me | string | 
action\_result\.data\.\*\.votes\.total | numeric | 
action\_result\.data\.\*\.watched\_by\_me | boolean | 
action\_result\.data\.\*\.watched\_total\_count | numeric | 
action\_result\.summary\.incidents\_returned | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete incident'
Delete incident in ThreatStream by ID number

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident\_id** |  required  | ID number of incident to delete | string |  `threatstream incident id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.incident\_id | string |  `threatstream incident id` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get incident'
Get incident in ThreatStream by ID number

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**incident\_id** |  required  | ID number of incident to return | string |  `threatstream incident id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.incident\_id | string |  `threatstream incident id` 
action\_result\.data\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.body\_content\_type | string | 
action\_result\.data\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.embedded\_content\_type | string | 
action\_result\.data\.\*\.embedded\_content\_url | string | 
action\_result\.data\.\*\.end\_date | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.asn | string | 
action\_result\.data\.\*\.intelligence\.\*\.association\_info\.\*\.comment | string | 
action\_result\.data\.\*\.intelligence\.\*\.association\_info\.\*\.created | string | 
action\_result\.data\.\*\.intelligence\.\*\.association\_info\.\*\.from\_id | string | 
action\_result\.data\.\*\.intelligence\.\*\.association\_info\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.confidence | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.country | string | 
action\_result\.data\.\*\.intelligence\.\*\.created\_by | string |  `email` 
action\_result\.data\.\*\.intelligence\.\*\.created\_ts | string | 
action\_result\.data\.\*\.intelligence\.\*\.description | string | 
action\_result\.data\.\*\.intelligence\.\*\.expiration\_ts | string | 
action\_result\.data\.\*\.intelligence\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.id | string |  `threatstream intelligence id` 
action\_result\.data\.\*\.intelligence\.\*\.import\_session\_id | string | 
action\_result\.data\.\*\.intelligence\.\*\.import\_source | string | 
action\_result\.data\.\*\.intelligence\.\*\.ip | string | 
action\_result\.data\.\*\.intelligence\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.itype | string | 
action\_result\.data\.\*\.intelligence\.\*\.latitude | string | 
action\_result\.data\.\*\.intelligence\.\*\.longitude | string | 
action\_result\.data\.\*\.intelligence\.\*\.meta\.detail2 | string | 
action\_result\.data\.\*\.intelligence\.\*\.meta\.registrant\_address | string | 
action\_result\.data\.\*\.intelligence\.\*\.meta\.registrant\_email | string | 
action\_result\.data\.\*\.intelligence\.\*\.meta\.registrant\_name | string | 
action\_result\.data\.\*\.intelligence\.\*\.meta\.registrant\_phone | string | 
action\_result\.data\.\*\.intelligence\.\*\.meta\.registration\_created | string | 
action\_result\.data\.\*\.intelligence\.\*\.meta\.registration\_updated | string | 
action\_result\.data\.\*\.intelligence\.\*\.meta\.severity | string | 
action\_result\.data\.\*\.intelligence\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.intelligence\.\*\.org | string | 
action\_result\.data\.\*\.intelligence\.\*\.owner\_organization\_id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.rdns | string | 
action\_result\.data\.\*\.intelligence\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.intelligence\.\*\.retina\_confidence | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.source | string |  `email` 
action\_result\.data\.\*\.intelligence\.\*\.source\_reported\_confidence | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.status | string | 
action\_result\.data\.\*\.intelligence\.\*\.subtype | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.category | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.org\_id | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.source\_user | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.source\_user\_id | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.tagger | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.tlp | string | 
action\_result\.data\.\*\.intelligence\.\*\.threat\_type | string | 
action\_result\.data\.\*\.intelligence\.\*\.threatscore | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.tlp | string | 
action\_result\.data\.\*\.intelligence\.\*\.trusted\_circle\_ids | string | 
action\_result\.data\.\*\.intelligence\.\*\.type | string | 
action\_result\.data\.\*\.intelligence\.\*\.update\_id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.uuid | string | 
action\_result\.data\.\*\.intelligence\.\*\.value | string |  `email` 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.logo\_s3\_url | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.organization\.id | string | 
action\_result\.data\.\*\.organization\.name | string | 
action\_result\.data\.\*\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.organization\_id | numeric |  `threatstream organization id` 
action\_result\.data\.\*\.owner\_user\.email | string |  `email` 
action\_result\.data\.\*\.owner\_user\.id | string | 
action\_result\.data\.\*\.owner\_user\.name | string | 
action\_result\.data\.\*\.owner\_user\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_user\_id | numeric | 
action\_result\.data\.\*\.parent | string | 
action\_result\.data\.\*\.publication\_status | string | 
action\_result\.data\.\*\.published\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.starred\_by\_me | boolean | 
action\_result\.data\.\*\.starred\_total\_count | numeric | 
action\_result\.data\.\*\.start\_date | string | 
action\_result\.data\.\*\.status\.display\_name | string | 
action\_result\.data\.\*\.status\.id | numeric | 
action\_result\.data\.\*\.status\.resource\_uri | string | 
action\_result\.data\.\*\.status\_desc | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.id | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.name | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.tags\_v2\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\_v2\.\*\.tlp | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.votes\.me | string | 
action\_result\.data\.\*\.votes\.total | numeric | 
action\_result\.data\.\*\.watched\_by\_me | boolean | 
action\_result\.data\.\*\.watched\_total\_count | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create incident'
Create an incident in ThreatStream

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**local\_intelligence** |  optional  | Comma\-separated list of local intelligence IDs to associate with the incident \- Note that this appends | string |  `threatstream intelligence id` 
**cloud\_intelligence** |  optional  | Comma\-separated list of remote intelligence IDs to associate with the incident \- Note that this appends | string |  `threatstream intelligence id` 
**name** |  required  | Name to give the incident | string | 
**fields** |  optional  | JSON formatted string of fields to include with the incident | string | 
**is\_public** |  optional  | Classification designation | boolean | 
**create\_on\_cloud** |  optional  | Create on remote \(cloud\)? \(applicable only for hybrid on\-prem instances\) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.cloud\_intelligence | string |  `threatstream intelligence id` 
action\_result\.parameter\.create\_on\_cloud | boolean | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.is\_public | boolean | 
action\_result\.parameter\.local\_intelligence | string |  `threatstream intelligence id` 
action\_result\.parameter\.name | string | 
action\_result\.data\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.body\_content\_type | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.embedded\_content\_type | string | 
action\_result\.data\.\*\.embedded\_content\_url | string | 
action\_result\.data\.\*\.end\_date | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.fjregnvjnj | string | 
action\_result\.data\.\*\.id | numeric |  `threatstream incident id` 
action\_result\.data\.\*\.intelligence\.\*\.id | numeric | 
action\_result\.data\.\*\.invalid field | string | 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.logo\_s3\_url | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.organization\.id | string |  `threatstream organization id` 
action\_result\.data\.\*\.organization\.name | string | 
action\_result\.data\.\*\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.organization\_id | numeric |  `threatstream organization id` 
action\_result\.data\.\*\.owner\_user\.email | string |  `email` 
action\_result\.data\.\*\.owner\_user\.id | string | 
action\_result\.data\.\*\.owner\_user\.name | string | 
action\_result\.data\.\*\.owner\_user\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_user\_id | numeric | 
action\_result\.data\.\*\.parent | string | 
action\_result\.data\.\*\.publication\_status | string | 
action\_result\.data\.\*\.published\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.starred\_by\_me | boolean | 
action\_result\.data\.\*\.starred\_total\_count | numeric | 
action\_result\.data\.\*\.start\_date | string | 
action\_result\.data\.\*\.status\.display\_name | string | 
action\_result\.data\.\*\.status\.id | numeric | 
action\_result\.data\.\*\.status\.resource\_uri | string | 
action\_result\.data\.\*\.status\_desc | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.votes\.me | string | 
action\_result\.data\.\*\.votes\.total | numeric | 
action\_result\.data\.\*\.watched\_by\_me | boolean | 
action\_result\.data\.\*\.watched\_total\_count | numeric | 
action\_result\.summary | string | 
action\_result\.summary\.created\_on\_cloud | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update incident'
Update an incident in ThreatStream by ID number

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**local\_intelligence** |  optional  | Comma\-separated list of local intelligence IDs to associate with the incident \- Note that this appends | string | 
**cloud\_intelligence** |  optional  | Comma\-separated list of remote intelligence IDs to associate with the incident \- Note that this appends | string | 
**fields** |  optional  | JSON formatted string of fields to update on the incident | string | 
**incident\_id** |  required  | ID number of incident to update | string |  `threatstream incident id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.cloud\_intelligence | string | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.incident\_id | string |  `threatstream incident id` 
action\_result\.parameter\.local\_intelligence | string | 
action\_result\.data\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.body\_content\_type | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.embedded\_content\_type | string | 
action\_result\.data\.\*\.embedded\_content\_url | string | 
action\_result\.data\.\*\.end\_date | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `threatstream incident id` 
action\_result\.data\.\*\.intelligence\.\*\.id | numeric |  `threatstream incident id` 
action\_result\.data\.\*\.invalid field | string | 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.logo\_s3\_url | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.organization\.id | string |  `threatstream organization id` 
action\_result\.data\.\*\.organization\.name | string | 
action\_result\.data\.\*\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.organization\_id | numeric |  `threatstream organization id` 
action\_result\.data\.\*\.owner\_user\.email | string |  `email` 
action\_result\.data\.\*\.owner\_user\.id | string | 
action\_result\.data\.\*\.owner\_user\.name | string | 
action\_result\.data\.\*\.owner\_user\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_user\_id | numeric | 
action\_result\.data\.\*\.parent | string | 
action\_result\.data\.\*\.publication\_status | string | 
action\_result\.data\.\*\.published\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.starred\_by\_me | boolean | 
action\_result\.data\.\*\.starred\_total\_count | numeric | 
action\_result\.data\.\*\.start\_date | string | 
action\_result\.data\.\*\.status\.display\_name | string | 
action\_result\.data\.\*\.status\.id | numeric | 
action\_result\.data\.\*\.status\.resource\_uri | string | 
action\_result\.data\.\*\.status\_desc | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.votes\.me | string | 
action\_result\.data\.\*\.votes\.total | numeric | 
action\_result\.data\.\*\.watched\_by\_me | boolean | 
action\_result\.data\.\*\.watched\_total\_count | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'import domain observable'
Import domain observable into ThreatStream

Type: **generic**  
Read only: **False**

<ul><li>For importing domain observables without approval, the user must provide indicator type in the field parameter \(e\.g \- "mal\_domain"\) whereas, for importing observables with approval, the user must provide threat type in the field parameter \(e\.g \- "malware"\)\.</li><li>The possible values of indicator type \(itype\) and threat\_type are listed at the starting of the documentation\. If the input contains any indicator type \(itype\) or threat\_type value except the ones listed, the action will behave according to the API behavior\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Value of domain | string |  `domain` 
**indicator\_type** |  required  | Type of observable to import | string | 
**source** |  optional  | Source of observable to import \(It will only be reflected on UI when observable is imported without approval\) | string | 
**classification** |  optional  | Designate classification for observable | string | 
**severity** |  optional  | Severity of the observable | string | 
**tags** |  optional  | Comma\-separated list of tags to associate with this Observable | string |  `threatstream tags` 
**create\_on\_cloud** |  optional  | Create on remote \(cloud\)? \(applicable only for hybrid on\-prem instances\) | boolean | 
**with\_approval** |  optional  | Import the observable with approvals | boolean | 
**allow\_unresolved** |  optional  | Unresolved domains will be imported if set to true | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.allow\_unresolved | boolean | 
action\_result\.parameter\.classification | string | 
action\_result\.parameter\.create\_on\_cloud | boolean | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.parameter\.indicator\_type | string | 
action\_result\.parameter\.severity | string | 
action\_result\.parameter\.source | string | 
action\_result\.parameter\.tags | string |  `threatstream tags` 
action\_result\.parameter\.with\_approval | boolean | 
action\_result\.data | string | 
action\_result\.data\.\*\.import\_session\_id | string | 
action\_result\.data\.\*\.job\_id | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.summary\.created\_on\_cloud | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'import url observable'
Import URL observable into ThreatStream

Type: **generic**  
Read only: **False**

<ul><li>For importing URL observables without approval, the user must provide indicator type in the indicator\_type parameter \(e\.g \- "phish\_url"\) whereas, for importing observables with approval, the user must provide threat type in the indicator\_type parameter \(e\.g \- "phish"\)\.</li><li>The possible values of indicator type \(itype\) and threat\_type are listed at the starting of the documentation\. If the input contains any indicator type \(itype\) or threat\_type value except the ones listed, the action will behave according to the API behavior\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | Value of URL | string |  `url` 
**indicator\_type** |  required  | Type of observable to import | string | 
**source** |  optional  | Source of observable to import \(It will only be reflected on UI when observable is imported without approval\) | string | 
**classification** |  optional  | Designate classification for observable | string | 
**severity** |  optional  | Severity of the observable | string | 
**tags** |  optional  | Comma\-separated list of tags to associate with this Observable | string |  `threatstream tags` 
**create\_on\_cloud** |  optional  | Create on remote \(cloud\)? \(applicable only for hybrid on\-prem instances\) | boolean | 
**with\_approval** |  optional  | Import the observable with approvals | boolean | 
**allow\_unresolved** |  optional  | Unresolved urls will be imported if set to true | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.allow\_unresolved | boolean | 
action\_result\.parameter\.classification | string | 
action\_result\.parameter\.create\_on\_cloud | boolean | 
action\_result\.parameter\.indicator\_type | string | 
action\_result\.parameter\.severity | string | 
action\_result\.parameter\.source | string | 
action\_result\.parameter\.tags | string |  `threatstream tags` 
action\_result\.parameter\.url | string |  `url` 
action\_result\.parameter\.with\_approval | boolean | 
action\_result\.data | string | 
action\_result\.summary\.created\_on\_cloud | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'import ip observable'
Import IP observable into ThreatStream

Type: **generic**  
Read only: **False**

<ul><li>For importing IP observables without approval, the user must provide indicator type in the indicator\_type parameter \(e\.g \- "apt\_ip"\) whereas, for importing observables with approval, the user must provide threat type in the indicator\_type parameter \(e\.g \- "apt"\)\.</li><li>The possible values of indicator type \(itype\) and threat\_type are listed at the starting of the documentation\. If the input contains any indicator type \(itype\) or threat\_type value except the ones listed, the action will behave according to the API behavior\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_address** |  required  | Value of IP | string |  `ip`  `ipv6` 
**indicator\_type** |  required  | Type of observable to import | string | 
**source** |  optional  | Source of observable to import \(It will only be reflected on UI when observable is imported without approval\) | string | 
**classification** |  optional  | Designate classification for observable | string | 
**severity** |  optional  | Severity of the observable | string | 
**tags** |  optional  | Comma\-separated list of tags to associate with this Observable | string |  `threatstream tags` 
**create\_on\_cloud** |  optional  | Create on remote \(cloud\)? \(applicable only for hybrid on\-prem instances\) | boolean | 
**with\_approval** |  optional  | Import the observable with approvals | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.classification | string | 
action\_result\.parameter\.create\_on\_cloud | boolean | 
action\_result\.parameter\.indicator\_type | string | 
action\_result\.parameter\.ip\_address | string |  `ip`  `ipv6` 
action\_result\.parameter\.severity | string | 
action\_result\.parameter\.source | string | 
action\_result\.parameter\.tags | string |  `threatstream tags` 
action\_result\.parameter\.with\_approval | boolean | 
action\_result\.data | string | 
action\_result\.summary\.created\_on\_cloud | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'import file observable'
Import file observable into ThreatStream

Type: **generic**  
Read only: **False**

<ul><li>For importing file observables without approval, the user must provide indicator type in the field parameter \(e\.g \- "crypto\_hash"\) whereas, for importing observables with approval, the user must provide threat type in the field parameter \(e\.g \- "crypto"\)\.</li><li>The possible values of indicator type \(itype\) and threat\_type are listed at the starting of the documentation\. If the input contains any indicator type \(itype\) or threat\_type value except the ones listed, the action will behave according to the API behavior\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**file\_hash** |  required  | Hash value of file | string |  `sha1`  `sha256`  `md5`  `hash` 
**indicator\_type** |  required  | Type of observable to import | string | 
**source** |  optional  | Source of observable to import \(It will only be reflected on UI when observable is imported without approval\) | string | 
**confidence** |  required  | Confidence level | numeric | 
**classification** |  optional  | Designate classification for observable | string | 
**severity** |  optional  | Severity of the observable | string | 
**tags** |  optional  | Comma\-separated list of tags to associate with this Observable | string |  `threatstream tags` 
**create\_on\_cloud** |  optional  | Create on remote \(cloud\)? \(applicable only for hybrid on\-prem instances\) | boolean | 
**with\_approval** |  optional  | Import the observable with approvals | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.classification | string | 
action\_result\.parameter\.confidence | numeric | 
action\_result\.parameter\.create\_on\_cloud | boolean | 
action\_result\.parameter\.file\_hash | string |  `sha1`  `sha256`  `md5`  `hash` 
action\_result\.parameter\.indicator\_type | string | 
action\_result\.parameter\.severity | string | 
action\_result\.parameter\.source | string | 
action\_result\.parameter\.tags | string |  `threatstream tags` 
action\_result\.parameter\.with\_approval | boolean | 
action\_result\.data | string | 
action\_result\.data\.\*\.import\_session\_id | string | 
action\_result\.data\.\*\.job\_id | string | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.summary\.created\_on\_cloud | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'import email observable'
Import email observable into ThreatStream

Type: **generic**  
Read only: **False**

<ul><li>For importing email observables without approval, the user must provide indicator type in the indicator\_type parameter \(e\.g \- "spam\_email"\) whereas, for importing observables with approval, the user must provide threat type in the indicator\_type parameter \(e\.g \- "spam"\)\.</li><li>The possible values of indicator type \(itype\) and threat\_type are listed at the starting of the documentation\. If the input contains any indicator type \(itype\) or threat\_type value except the ones listed, the action will behave according to the API behavior\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Value of email | string |  `email` 
**indicator\_type** |  required  | Type of observable to import | string | 
**source** |  optional  | Source of observable to import \(It will only be reflected on UI when observable is imported without approval\) | string | 
**confidence** |  required  | Confidence level | numeric | 
**classification** |  optional  | Designate classification for observable | string | 
**severity** |  optional  | Severity of the observable | string | 
**tags** |  optional  | Comma\-separated list of tags to associate with this Observable | string |  `threatstream tags` 
**create\_on\_cloud** |  optional  | Create on remote \(cloud\)? \(applicable only for hybrid on\-prem instances\) | boolean | 
**with\_approval** |  optional  | Import the observable with approvals | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.classification | string | 
action\_result\.parameter\.confidence | numeric | 
action\_result\.parameter\.create\_on\_cloud | boolean | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.parameter\.indicator\_type | string | 
action\_result\.parameter\.severity | string | 
action\_result\.parameter\.source | string | 
action\_result\.parameter\.tags | string |  `threatstream tags` 
action\_result\.parameter\.with\_approval | boolean | 
action\_result\.data | string | 
action\_result\.data\.\*\.import\_session\_id | string | 
action\_result\.data\.\*\.job\_id | string | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.summary\.created\_on\_cloud | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'import observables'
Import observables into ThreatStream

Type: **generic**  
Read only: **False**

<ul><li>For importing observables without approval, the user must provide indicator type in the field parameter \(e\.g \- \{"itype"\: "&lt;indicator\_type&gt;"\}\) whereas, for importing observables with approval, the user must provide threat type in the field parameter \(e\.g \- \{"threat\_type"\: "&lt;threat\_type&gt;"\}\)\.</li><li>The "allow\_unresolved" parameter will be passed in the API call if the "value" parameter is set to "domain" or "url" and "with\_approval" parameter is set to "False"\.</li><li>The possible values of indicator type \(itype\) and threat\_type are listed at the starting of the documentation\. If the input contains any indicator type \(itype\) or threat\_type value except the ones listed, the action will behave according to the API behavior\.</li><li>For importing observables of type 'URL', 'IP' and 'Domain', Threatstream itself detects the confidence value whereas, for importing observables of type 'Email', 'File', the user must provide confidence value in the field parameter \(e\.g \- \{"itype"\: "&lt;indicator\_type&gt;", "confidence"\: &lt;confidence\_value&gt;\}\)\.</li><li>If both the "itype" and "threat\_type" values are passed in the "fields" parameter when "with\_approval" is set to "True", the action will behave according to the API behavior\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**observable\_type** |  required  | Type of observable to import | string | 
**value** |  required  | Observable value | string |  `ip`  `domain`  `url`  `email`  `md5`  `sha1`  `hash` 
**classification** |  required  | Designate classification for observable | string | 
**fields** |  optional  | JSON formatted string of fields to include with the observable | string | 
**create\_on\_cloud** |  optional  | Create on remote \(cloud\)? \(applicable only for hybrid on\-prem instances\) | boolean | 
**with\_approval** |  optional  | Import the observable with approvals | boolean | 
**allow\_unresolved** |  optional  | Unresolved domains will be imported if set to true | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.allow\_unresolved | boolean | 
action\_result\.parameter\.classification | string | 
action\_result\.parameter\.create\_on\_cloud | boolean | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.observable\_type | string | 
action\_result\.parameter\.value | string |  `ip`  `domain`  `url`  `email`  `md5`  `sha1`  `hash` 
action\_result\.parameter\.with\_approval | boolean | 
action\_result\.data | string | 
action\_result\.data\.\*\.import\_session\_id | string | 
action\_result\.data\.\*\.job\_id | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.summary\.created\_on\_cloud | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'tag observable'
Add a tag to the observable

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Intelligence ID | string |  `threatstream intelligence id` 
**source\_user\_id** |  required  | ID of user to associate with tag | string | 
**tags** |  required  | Comma\-separated list of tags to associate with this Observable | string |  `threatstream tags` 
**tlp** |  optional  | TLP to assign to each tag | string |  `threatstream tlp` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `threatstream intelligence id` 
action\_result\.parameter\.source\_user\_id | string | 
action\_result\.parameter\.tags | string |  `threatstream tags` 
action\_result\.parameter\.tlp | string |  `threatstream tlp` 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.data\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.tags\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\.\*\.source\_user\_id | string | 
action\_result\.data\.\*\.tags\.\*\.tlp | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get pcap'
Download pcap file of a sample submitted to the sandbox and add it to vault

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | ID of report associated with the pcap to download | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | numeric | 
action\_result\.data\.\*\.file\_name | string | 
action\_result\.data\.\*\.vault\_id | string |  `sha1`  `vault id` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'detonate file'
Detonate file in ThreatStream

Type: **generic**  
Read only: **False**

If classification or platform parameter is added and is also mentioned in the fields parameter, the value given in the individual parameters is considered\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**platform** |  optional  | Which platform to run the detonation on \- Ex\: WINDOWS10x64\. Default is 'WINDOWS7' which will run the detonation on 'WINDOWS7' platform | string | 
**vault\_id** |  required  | Vault id of file to be detonated | string |  `vault id`  `sha1` 
**classification** |  required  | Classification of the sandbox submission \- private or public | string | 
**use\_premium\_sandbox** |  optional  | Specify whether the premium sandbox should be used for detonation \- true or false\. If you want to use the Joe Sandbox service for detonation, set this attribute to true | boolean | 
**use\_vmray\_sandbox** |  optional  | Specify whether the vmray sandbox should be used for detonation \- true or false\. If you want to use the VMRay sandbox service for detonation, set this attribute to true | boolean | 
**vmray\_max\_jobs** |  optional  | Specify the number of detonations you want VMRay to perform for the submission | numeric | 
**fields** |  optional  | JSON formatted string of additional fields to be included in the detonate file action\. e\.g\. \{"file\_has\_password"\:"true","file\_password"\:"abc123"\}\. Please check the API doc to find more information on other valid fields | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.classification | string | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.platform | string | 
action\_result\.parameter\.use\_premium\_sandbox | boolean | 
action\_result\.parameter\.use\_vmray\_sandbox | boolean | 
action\_result\.parameter\.vault\_id | string |  `vault id`  `sha1` 
action\_result\.parameter\.vmray\_max\_jobs | numeric | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.reports\.ANDROID4\.4\.detail | string | 
action\_result\.data\.\*\.reports\.ANDROID4\.4\.status | string | 
action\_result\.data\.\*\.reports\.ANDROID5\.1\.detail | string | 
action\_result\.data\.\*\.reports\.ANDROID5\.1\.status | string | 
action\_result\.data\.\*\.reports\.ANDROID6\.0\.detail | string | 
action\_result\.data\.\*\.reports\.ANDROID6\.0\.status | string | 
action\_result\.data\.\*\.reports\.MACOSX\.detail | string | 
action\_result\.data\.\*\.reports\.MACOSX\.status | string | 
action\_result\.data\.\*\.reports\.WINDOWS10\.detail | string | 
action\_result\.data\.\*\.reports\.WINDOWS10\.status | string | 
action\_result\.data\.\*\.reports\.WINDOWS10x64\.detail | string | 
action\_result\.data\.\*\.reports\.WINDOWS10x64\.status | string | 
action\_result\.data\.\*\.reports\.WINDOWS7\.detail | string | 
action\_result\.data\.\*\.reports\.WINDOWS7\.id | numeric | 
action\_result\.data\.\*\.reports\.WINDOWS7\.status | string | 
action\_result\.data\.\*\.reports\.WINDOWS7NATIVE\.detail | string | 
action\_result\.data\.\*\.reports\.WINDOWS7NATIVE\.status | string | 
action\_result\.data\.\*\.reports\.WINDOWS7OFFICE2010\.detail | string | 
action\_result\.data\.\*\.reports\.WINDOWS7OFFICE2010\.status | string | 
action\_result\.data\.\*\.reports\.WINDOWS7OFFICE2013\.detail | string | 
action\_result\.data\.\*\.reports\.WINDOWS7OFFICE2013\.status | string | 
action\_result\.data\.\*\.reports\.WINDOWSXP\.detail | string | 
action\_result\.data\.\*\.reports\.WINDOWSXP\.id | numeric | 
action\_result\.data\.\*\.reports\.WINDOWSXP\.status | string | 
action\_result\.data\.\*\.reports\.WINDOWSXPNATIVE\.detail | string | 
action\_result\.data\.\*\.reports\.WINDOWSXPNATIVE\.status | string | 
action\_result\.data\.\*\.success | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'detonate url'
Detonate URL in ThreatStream

Type: **generic**  
Read only: **False**

If classification or platform parameter is added and is also mentioned in the fields parameter, the value given in the individual parameters is considered\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**platform** |  optional  | Which platform to run the detonation on \- Ex\: WINDOWS10x64\. Default is 'WINDOWS7' which will run the detonation on 'WINDOWS7' platform | string | 
**url** |  required  | URL to be detonated | string |  `url` 
**classification** |  required  | Classification of the sandbox submission \- private or public | string | 
**use\_premium\_sandbox** |  optional  | Specify whether the premium sandbox should be used for detonation \- true or false\. If you want to use the Joe Sandbox service for detonation, set this attribute to true | boolean | 
**use\_vmray\_sandbox** |  optional  | Specify whether the vmray sandbox should be used for detonation \- true or false\. If you want to use the VMRay sandbox service for detonation, set this attribute to true | boolean | 
**vmray\_max\_jobs** |  optional  | Specify the number of detonations you want VMRay to perform for the submission | numeric | 
**fields** |  optional  | JSON formatted string of additional fields to be included in the detonate url action\. e\.g\. \{"import\_indicators"\:"true","report\_radio\-notes"\:"Credential\-Exposure,compromised\_email"\}\. Please check the API doc to find more infomation on other valid fields | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.classification | string | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.platform | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.parameter\.use\_premium\_sandbox | boolean | 
action\_result\.parameter\.use\_vmray\_sandbox | boolean | 
action\_result\.parameter\.vmray\_max\_jobs | numeric | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.reports\.WINDOWS7\.detail | string | 
action\_result\.data\.\*\.reports\.WINDOWS7\.id | numeric | 
action\_result\.data\.\*\.reports\.WINDOWS7\.status | string | 
action\_result\.data\.\*\.reports\.WINDOWSXP\.detail | string | 
action\_result\.data\.\*\.reports\.WINDOWSXP\.id | numeric | 
action\_result\.data\.\*\.reports\.WINDOWSXP\.status | string | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get status'
Retrieve detonation status present in Threatstream

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**endpoint** |  required  | Endpoint given by Detonate File/URL \(eg\: /api/v1/submit/12345/\) | string |  `threatstream endpoint status` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.endpoint | string |  `threatstream endpoint status` 
action\_result\.data\.\*\.classification | string | 
action\_result\.data\.\*\.confidence | numeric | 
action\_result\.data\.\*\.date\_added | string | 
action\_result\.data\.\*\.detail | string | 
action\_result\.data\.\*\.file | string | 
action\_result\.data\.\*\.html\_report | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.import\_indicators | boolean | 
action\_result\.data\.\*\.jobID | string | 
action\_result\.data\.\*\.maec\_report | string | 
action\_result\.data\.\*\.md5 | string | 
action\_result\.data\.\*\.message | string | 
action\_result\.data\.\*\.misc\_info | string | 
action\_result\.data\.\*\.notes | string | 
action\_result\.data\.\*\.pdf\_generated | numeric | 
action\_result\.data\.\*\.platform | string | 
action\_result\.data\.\*\.platform\_label | string | 
action\_result\.data\.\*\.priority | numeric | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.reportid | string | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.sandbox\_vendor | string | 
action\_result\.data\.\*\.sha1 | string | 
action\_result\.data\.\*\.sha256 | string | 
action\_result\.data\.\*\.starred\_by\_me | boolean | 
action\_result\.data\.\*\.starred\_total\_count | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.user\.id | numeric | 
action\_result\.data\.\*\.user\.username | string |  `email`  `user name` 
action\_result\.data\.\*\.user\_id | numeric | 
action\_result\.data\.\*\.verdict | string | 
action\_result\.data\.\*\.virustotal | string | 
action\_result\.data\.\*\.votes\.me | string | 
action\_result\.data\.\*\.votes\.total | numeric | 
action\_result\.data\.\*\.watched\_by\_me | boolean | 
action\_result\.data\.\*\.watched\_total\_count | numeric | 
action\_result\.data\.\*\.yara | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get report'
Retrieve detonation report present in Threatstream

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**endpoint** |  required  | Endpoint given by Detonate File/URL \(eg\: /api/v1/submit/141/report/\) | string |  `threatstream endpoint report` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.endpoint | string |  `threatstream endpoint report` 
action\_result\.data\.\*\.pcap | string |  `url` 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.results\.behavior\.anomaly\.\*\.category | string | 
action\_result\.data\.\*\.results\.behavior\.anomaly\.\*\.funcname | string | 
action\_result\.data\.\*\.results\.behavior\.anomaly\.\*\.message | string | 
action\_result\.data\.\*\.results\.behavior\.anomaly\.\*\.name | string | 
action\_result\.data\.\*\.results\.behavior\.anomaly\.\*\.pid | numeric | 
action\_result\.data\.\*\.results\.behavior\.enhanced\.\*\.data\.classname | string | 
action\_result\.data\.\*\.results\.behavior\.enhanced\.\*\.data\.content | string | 
action\_result\.data\.\*\.results\.behavior\.enhanced\.\*\.data\.file | string |  `file name`  `file path` 
action\_result\.data\.\*\.results\.behavior\.enhanced\.\*\.data\.moduleaddress | string | 
action\_result\.data\.\*\.results\.behavior\.enhanced\.\*\.data\.object | string | 
action\_result\.data\.\*\.results\.behavior\.enhanced\.\*\.data\.pathtofile | string | 
action\_result\.data\.\*\.results\.behavior\.enhanced\.\*\.data\.regkey | string | 
action\_result\.data\.\*\.results\.behavior\.enhanced\.\*\.data\.windowname | string | 
action\_result\.data\.\*\.results\.behavior\.enhanced\.\*\.eid | numeric | 
action\_result\.data\.\*\.results\.behavior\.enhanced\.\*\.event | string | 
action\_result\.data\.\*\.results\.behavior\.enhanced\.\*\.object | string | 
action\_result\.data\.\*\.results\.behavior\.enhanced\.\*\.timestamp | string | 
action\_result\.data\.\*\.results\.behavior\.processes\.\*\.calls\.\*\.api | string | 
action\_result\.data\.\*\.results\.behavior\.processes\.\*\.calls\.\*\.arguments\.\*\.name | string | 
action\_result\.data\.\*\.results\.behavior\.processes\.\*\.calls\.\*\.arguments\.\*\.value | string |  `file path`  `file name` 
action\_result\.data\.\*\.results\.behavior\.processes\.\*\.calls\.\*\.category | string | 
action\_result\.data\.\*\.results\.behavior\.processes\.\*\.calls\.\*\.id | numeric | 
action\_result\.data\.\*\.results\.behavior\.processes\.\*\.calls\.\*\.repeated | numeric | 
action\_result\.data\.\*\.results\.behavior\.processes\.\*\.calls\.\*\.return | string | 
action\_result\.data\.\*\.results\.behavior\.processes\.\*\.calls\.\*\.status | boolean | 
action\_result\.data\.\*\.results\.behavior\.processes\.\*\.calls\.\*\.thread\_id | string | 
action\_result\.data\.\*\.results\.behavior\.processes\.\*\.calls\.\*\.timestamp | string | 
action\_result\.data\.\*\.results\.behavior\.processes\.\*\.first\_seen | string | 
action\_result\.data\.\*\.results\.behavior\.processes\.\*\.parent\_id | numeric | 
action\_result\.data\.\*\.results\.behavior\.processes\.\*\.process\_id | numeric | 
action\_result\.data\.\*\.results\.behavior\.processes\.\*\.process\_name | string |  `file name` 
action\_result\.data\.\*\.results\.behavior\.processtree\.\*\.children\.\*\.name | string | 
action\_result\.data\.\*\.results\.behavior\.processtree\.\*\.children\.\*\.parent\_id | numeric | 
action\_result\.data\.\*\.results\.behavior\.processtree\.\*\.children\.\*\.pid | numeric | 
action\_result\.data\.\*\.results\.behavior\.processtree\.\*\.name | string |  `file name` 
action\_result\.data\.\*\.results\.behavior\.processtree\.\*\.parent\_id | numeric | 
action\_result\.data\.\*\.results\.behavior\.processtree\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.results\.behavior\.summary\.files | string |  `file path`  `file name` 
action\_result\.data\.\*\.results\.behavior\.summary\.keys | string | 
action\_result\.data\.\*\.results\.debug\.log | string | 
action\_result\.data\.\*\.results\.dropped\.\*\.crc32 | string | 
action\_result\.data\.\*\.results\.dropped\.\*\.md5 | string | 
action\_result\.data\.\*\.results\.dropped\.\*\.name | string | 
action\_result\.data\.\*\.results\.dropped\.\*\.path | string | 
action\_result\.data\.\*\.results\.dropped\.\*\.sha1 | string | 
action\_result\.data\.\*\.results\.dropped\.\*\.sha256 | string | 
action\_result\.data\.\*\.results\.dropped\.\*\.sha512 | string | 
action\_result\.data\.\*\.results\.dropped\.\*\.size | numeric | 
action\_result\.data\.\*\.results\.dropped\.\*\.ssdeep | string | 
action\_result\.data\.\*\.results\.dropped\.\*\.type | string | 
action\_result\.data\.\*\.results\.info\.category | string | 
action\_result\.data\.\*\.results\.info\.custom | string | 
action\_result\.data\.\*\.results\.info\.duration | numeric | 
action\_result\.data\.\*\.results\.info\.ended | string | 
action\_result\.data\.\*\.results\.info\.id | numeric | 
action\_result\.data\.\*\.results\.info\.machine\.id | numeric | 
action\_result\.data\.\*\.results\.info\.machine\.label | string | 
action\_result\.data\.\*\.results\.info\.machine\.manager | string | 
action\_result\.data\.\*\.results\.info\.machine\.name | string | 
action\_result\.data\.\*\.results\.info\.machine\.shutdown\_on | string | 
action\_result\.data\.\*\.results\.info\.machine\.started\_on | string | 
action\_result\.data\.\*\.results\.info\.package | string | 
action\_result\.data\.\*\.results\.info\.started | string | 
action\_result\.data\.\*\.results\.info\.version | string | 
action\_result\.data\.\*\.results\.network\.dns\.\*\.answers\.\*\.data | string | 
action\_result\.data\.\*\.results\.network\.dns\.\*\.answers\.\*\.type | string | 
action\_result\.data\.\*\.results\.network\.dns\.\*\.request | string | 
action\_result\.data\.\*\.results\.network\.dns\.\*\.type | string | 
action\_result\.data\.\*\.results\.network\.domains\.\*\.domain | string | 
action\_result\.data\.\*\.results\.network\.domains\.\*\.ip | string | 
action\_result\.data\.\*\.results\.network\.hosts | string |  `ip` 
action\_result\.data\.\*\.results\.network\.pcap\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.results\.network\.sorted\_pcap\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.results\.network\.tcp\.\*\.dport | numeric | 
action\_result\.data\.\*\.results\.network\.tcp\.\*\.dst | string |  `ip` 
action\_result\.data\.\*\.results\.network\.tcp\.\*\.offset | numeric | 
action\_result\.data\.\*\.results\.network\.tcp\.\*\.sport | numeric | 
action\_result\.data\.\*\.results\.network\.tcp\.\*\.src | string |  `ip` 
action\_result\.data\.\*\.results\.network\.tcp\.\*\.time | numeric | 
action\_result\.data\.\*\.results\.network\.udp\.\*\.dport | numeric | 
action\_result\.data\.\*\.results\.network\.udp\.\*\.dst | string |  `ip` 
action\_result\.data\.\*\.results\.network\.udp\.\*\.offset | numeric | 
action\_result\.data\.\*\.results\.network\.udp\.\*\.sport | numeric | 
action\_result\.data\.\*\.results\.network\.udp\.\*\.src | string |  `ip` 
action\_result\.data\.\*\.results\.network\.udp\.\*\.time | numeric | 
action\_result\.data\.\*\.results\.signatures\.\*\.alert | boolean | 
action\_result\.data\.\*\.results\.signatures\.\*\.data\.\*\.process\.process\_name | string | 
action\_result\.data\.\*\.results\.signatures\.\*\.data\.\*\.signs\.\*\.type | string | 
action\_result\.data\.\*\.results\.signatures\.\*\.data\.\*\.signs\.\*\.value\.category | string | 
action\_result\.data\.\*\.results\.signatures\.\*\.data\.\*\.signs\.\*\.value\.return | string | 
action\_result\.data\.\*\.results\.signatures\.\*\.data\.\*\.signs\.\*\.value\.status | boolean | 
action\_result\.data\.\*\.results\.signatures\.\*\.data\.\*\.signs\.\*\.value\.thread\_id | string | 
action\_result\.data\.\*\.results\.signatures\.\*\.data\.\*\.signs\.\*\.value\.timestamp | string | 
action\_result\.data\.\*\.results\.signatures\.\*\.name | string | 
action\_result\.data\.\*\.results\.signatures\.\*\.severity | numeric | 
action\_result\.data\.\*\.results\.target\.category | string | 
action\_result\.data\.\*\.results\.target\.file\.crc32 | string | 
action\_result\.data\.\*\.results\.target\.file\.md5 | string |  `md5` 
action\_result\.data\.\*\.results\.target\.file\.name | string | 
action\_result\.data\.\*\.results\.target\.file\.path | string | 
action\_result\.data\.\*\.results\.target\.file\.sha1 | string |  `sha1` 
action\_result\.data\.\*\.results\.target\.file\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.results\.target\.file\.sha512 | string | 
action\_result\.data\.\*\.results\.target\.file\.size | numeric | 
action\_result\.data\.\*\.results\.target\.file\.ssdeep | string | 
action\_result\.data\.\*\.results\.target\.file\.type | string | 
action\_result\.data\.\*\.results\.target\.url | string | 
action\_result\.data\.\*\.screenshots | string |  `url` 
action\_result\.data\.\*\.success | boolean | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'on poll'
Callback action for the on\_poll ingest functionality

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_id** |  optional  | Parameter ignored in this app | numeric | 
**start\_time** |  optional  | Parameter ignored in this app | numeric | 
**end\_time** |  optional  | Parameter ignored in this app | numeric | 
**container\_count** |  optional  | Maximum number of container records \(incidents\) to query for | numeric | 
**artifact\_count** |  optional  | Parameter ignored in this app | numeric | 

#### Action Output
No Output  

## action: 'run query'
Run observables query in ThreatStream

Type: **investigate**  
Read only: **True**

For providing the <b>query</b> parameter, please form a valid search string using the Anomali filter language \(as seen on the advanced search page\) and then convert it into a valid JSON string as shown in the example here\. e\.g\. Anomali filter language\-based search string = modifed\_ts\_\_gt=2018\-01\-10&status=active has to be provided in the <b>query</b> parameter as \{ "modifed\_ts\_\_gt"\: "2018\-01\-10", "status"\: "active" \}<br> If offset is provided in the 'query' parameter, it will be overwritten by the offset value provided in the 'offset' parameter\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Search string in JSON format using the Anomali filter language \(as seen on the advanced search page\) | string | 
**order\_by** |  optional  | Field by which the query results will be ordered | string | 
**offset** |  optional  | Record offset \(used with paging, when returning many results\) | numeric | 
**limit** |  optional  | Record limit | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.offset | numeric | 
action\_result\.parameter\.order\_by | string | 
action\_result\.parameter\.query | string | 
action\_result\.data\.\*\.asn | string | 
action\_result\.data\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.confidence | numeric | 
action\_result\.data\.\*\.country | string | 
action\_result\.data\.\*\.created\_by | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.expiration\_ts | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `threatstream intelligence id` 
action\_result\.data\.\*\.import\_session\_id | string | 
action\_result\.data\.\*\.import\_source | string | 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.itype | string | 
action\_result\.data\.\*\.latitude | string | 
action\_result\.data\.\*\.longitude | string | 
action\_result\.data\.\*\.meta\.detail | string | 
action\_result\.data\.\*\.meta\.detail2 | string | 
action\_result\.data\.\*\.meta\.limit | numeric | 
action\_result\.data\.\*\.meta\.maltype | string | 
action\_result\.data\.\*\.meta\.registrant\_address | string | 
action\_result\.data\.\*\.meta\.registrant\_email | string | 
action\_result\.data\.\*\.meta\.registrant\_name | string | 
action\_result\.data\.\*\.meta\.registrant\_org | string | 
action\_result\.data\.\*\.meta\.registrant\_phone | string | 
action\_result\.data\.\*\.meta\.registration\_created | string | 
action\_result\.data\.\*\.meta\.registration\_updated | string | 
action\_result\.data\.\*\.meta\.severity | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.org | string | 
action\_result\.data\.\*\.owner\_organization\_id | numeric | 
action\_result\.data\.\*\.rdns | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.retina\_confidence | numeric | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.source\_reported\_confidence | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.subtype | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.org\_id | string | 
action\_result\.data\.\*\.tags\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\.\*\.tlp | string | 
action\_result\.data\.\*\.threat\_type | string | 
action\_result\.data\.\*\.threatscore | numeric | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.trusted\_circle\_ids | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.update\_id | numeric | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.value | string | 
action\_result\.summary\.records\_returned | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list import sessions'
List all the import sessions

Type: **investigate**  
Read only: **True**

<ul><li>For a Hybrid instance, this action will return both remote and local data based on the input parameters\.</li><li>The user can use the <b>list imports</b> action to fetch only remote or local data in the response\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**date\_modified\_gte** |  optional  | Import sessions with greater than or equal to the provided modified date will be returned | string |  `threatstream date` 
**limit** |  optional  | Total number of import sessions to return | numeric | 
**offset** |  optional  | Record offset \(used with paging, when returning many results\) | numeric | 
**status\_in** |  optional  | Status to filter the records | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.date\_modified\_gte | string |  `threatstream date` 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.offset | numeric | 
action\_result\.parameter\.status\_in | string | 
action\_result\.data\.\*\.approved\_by\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.approved\_by\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.approved\_by\.email | string |  `email` 
action\_result\.data\.\*\.approved\_by\.id | string | 
action\_result\.data\.\*\.approved\_by\.is\_active | boolean | 
action\_result\.data\.\*\.approved\_by\.is\_readonly | boolean | 
action\_result\.data\.\*\.approved\_by\.must\_change\_password | boolean | 
action\_result\.data\.\*\.approved\_by\.name | string | 
action\_result\.data\.\*\.approved\_by\.nickname | string | 
action\_result\.data\.\*\.approved\_by\.organization\.id | string | 
action\_result\.data\.\*\.approved\_by\.organization\.name | string | 
action\_result\.data\.\*\.approved\_by\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.approved\_by\.resource\_uri | string | 
action\_result\.data\.\*\.approved\_by\_id | string | 
action\_result\.data\.\*\.confidence | numeric | 
action\_result\.data\.\*\.date | string | 
action\_result\.data\.\*\.date\_modified | string | 
action\_result\.data\.\*\.default\_comment | string | 
action\_result\.data\.\*\.email | string |  `email` 
action\_result\.data\.\*\.expiration\_ts | string | 
action\_result\.data\.\*\.fileName | string |  `url` 
action\_result\.data\.\*\.fileType | string | 
action\_result\.data\.\*\.file\_name\_label | string | 
action\_result\.data\.\*\.id | numeric |  `threatstream import session id` 
action\_result\.data\.\*\.intelligence\_source | string |  `url` 
action\_result\.data\.\*\.investigations\.\*\.id | string | 
action\_result\.data\.\*\.investigations\.\*\.name | string | 
action\_result\.data\.\*\.investigations\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.jobID | string | 
action\_result\.data\.\*\.messages | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.notes | string | 
action\_result\.data\.\*\.numIndicators | numeric | 
action\_result\.data\.\*\.numRejected | numeric | 
action\_result\.data\.\*\.num\_private | numeric | 
action\_result\.data\.\*\.num\_public | numeric | 
action\_result\.data\.\*\.organization\.id | string | 
action\_result\.data\.\*\.organization\.name | string | 
action\_result\.data\.\*\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.orginal\_intelligence | string | 
action\_result\.data\.\*\.processed\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.sandbox\_submit | string | 
action\_result\.data\.\*\.source\_confidence\_weight | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.tags\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\.\*\.tlp | string | 
action\_result\.data\.\*\.threat\_type | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.trusted\_circles\.\*\.anonymous\_sharing | boolean | 
action\_result\.data\.\*\.trusted\_circles\.\*\.can\_override\_confidence | boolean | 
action\_result\.data\.\*\.trusted\_circles\.\*\.description | string | 
action\_result\.data\.\*\.trusted\_circles\.\*\.id | numeric | 
action\_result\.data\.\*\.trusted\_circles\.\*\.is\_freemium | boolean | 
action\_result\.data\.\*\.trusted\_circles\.\*\.mattermost\_team\_id | string | 
action\_result\.data\.\*\.trusted\_circles\.\*\.name | string | 
action\_result\.data\.\*\.trusted\_circles\.\*\.openinvite | boolean | 
action\_result\.data\.\*\.trusted\_circles\.\*\.partner | string | 
action\_result\.data\.\*\.trusted\_circles\.\*\.premium\_channel | string | 
action\_result\.data\.\*\.trusted\_circles\.\*\.public | boolean | 
action\_result\.data\.\*\.trusted\_circles\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.trusted\_circles\.\*\.restricted\_publishing | boolean | 
action\_result\.data\.\*\.trusted\_circles\.\*\.subscription\_model | string | 
action\_result\.data\.\*\.trusted\_circles\.\*\.use\_chat | boolean | 
action\_result\.data\.\*\.trusted\_circles\.\*\.validate\_subscriptions | boolean | 
action\_result\.data\.\*\.user\_id | numeric | 
action\_result\.data\.\*\.visibleForReview | boolean | 
action\_result\.summary\.import\_sessions\_returned | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update import session'
This action updates the fields of the provided item id

Type: **generic**  
Read only: **False**

If "null" is provided in the expire time parameter, then expiration time will be set to "9999\-12\-31T00\:00\:00"\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**item\_id** |  required  | ID of the import session to update | numeric |  `threatstream import session id` 
**intelligence\_source** |  optional  | Intelligence Source to update | string | 
**tlp** |  optional  | Traffic Light Protocol value to update | string |  `threatstream tlp` 
**tags** |  optional  | Comma\-separated list of tags to update | string |  `threatstream tags` 
**comment** |  optional  | Comment to update | string | 
**expire\_time** |  optional  | Expiration time to update \(Format \: YYYY\-MM\-DD HH\:MM\[\:ss\[\.uuuuuu\]\]\[TZ\]\) | string |  `threatstream date` 
**threat\_model\_type** |  optional  | Comma\-separated list of threat model types to associate | string | 
**threat\_model\_to\_associate** |  optional  | Comma\-separated list of threat model IDs to associate | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.expire\_time | string |  `threatstream date` 
action\_result\.parameter\.intelligence\_source | string | 
action\_result\.parameter\.item\_id | numeric |  `threatstream import session id` 
action\_result\.parameter\.tags | string |  `threatstream tags` 
action\_result\.parameter\.threat\_model\_to\_associate | string | 
action\_result\.parameter\.threat\_model\_type | string | 
action\_result\.parameter\.tlp | string |  `threatstream tlp` 
action\_result\.data\.\*\.approved\_by\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.approved\_by\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.approved\_by\.email | string | 
action\_result\.data\.\*\.approved\_by\.id | string | 
action\_result\.data\.\*\.approved\_by\.is\_active | boolean | 
action\_result\.data\.\*\.approved\_by\.is\_readonly | boolean | 
action\_result\.data\.\*\.approved\_by\.must\_change\_password | boolean | 
action\_result\.data\.\*\.approved\_by\.name | string | 
action\_result\.data\.\*\.approved\_by\.nickname | string | 
action\_result\.data\.\*\.approved\_by\.organization\.id | string | 
action\_result\.data\.\*\.approved\_by\.organization\.name | string | 
action\_result\.data\.\*\.approved\_by\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.approved\_by\.resource\_uri | string | 
action\_result\.data\.\*\.approved\_by\_id | numeric | 
action\_result\.data\.\*\.associations\.actors\.\*\.id | string | 
action\_result\.data\.\*\.associations\.actors\.\*\.name | string | 
action\_result\.data\.\*\.associations\.actors\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.associations\.incidents\.\*\.id | string | 
action\_result\.data\.\*\.associations\.incidents\.\*\.name | string | 
action\_result\.data\.\*\.associations\.incidents\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.associations\.malware\.\*\.id | string | 
action\_result\.data\.\*\.associations\.malware\.\*\.name | string | 
action\_result\.data\.\*\.associations\.malware\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.associations\.tip\_reports\.\*\.id | string | 
action\_result\.data\.\*\.associations\.tip\_reports\.\*\.name | string | 
action\_result\.data\.\*\.associations\.tip\_reports\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.associations\.ttps\.\*\.id | string | 
action\_result\.data\.\*\.associations\.ttps\.\*\.name | string | 
action\_result\.data\.\*\.associations\.ttps\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.associations\.vulnerabilities\.\*\.id | string | 
action\_result\.data\.\*\.associations\.vulnerabilities\.\*\.name | string | 
action\_result\.data\.\*\.associations\.vulnerabilities\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.confidence | numeric | 
action\_result\.data\.\*\.date | string | 
action\_result\.data\.\*\.date\_modified | string | 
action\_result\.data\.\*\.default\_comment | string | 
action\_result\.data\.\*\.email | string |  `email` 
action\_result\.data\.\*\.expiration\_ts | string | 
action\_result\.data\.\*\.fileName | string | 
action\_result\.data\.\*\.fileType | string | 
action\_result\.data\.\*\.file\_name\_label | string | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.intelligence\_source | string |  `url` 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.jobID | string | 
action\_result\.data\.\*\.messages | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.notes | string | 
action\_result\.data\.\*\.numIndicators | numeric | 
action\_result\.data\.\*\.numRejected | numeric | 
action\_result\.data\.\*\.num\_private | numeric | 
action\_result\.data\.\*\.num\_public | numeric | 
action\_result\.data\.\*\.organization\.id | string | 
action\_result\.data\.\*\.organization\.name | string | 
action\_result\.data\.\*\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.orginal\_intelligence | string | 
action\_result\.data\.\*\.processed\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.created\_ts | string | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.end\_date | string | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.id | numeric | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.name | string | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.organization\_id | numeric | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.owner\_user\_id | numeric | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.publication\_status | string | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.published\_ts | string | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.source\_created | string | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.source\_modified | string | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.start\_date | string | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.status\.display\_name | string | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.status\.id | numeric | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.status\.resource\_uri | string | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.tlp | string | 
action\_result\.data\.\*\.remote\_associations\.incidents\.\*\.uuid | string | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.sandbox\_submit | string | 
action\_result\.data\.\*\.source\_confidence\_weight | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.tags\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\.\*\.tlp | string |  `threatstream tlp` 
action\_result\.data\.\*\.threat\_type | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.user\_id | numeric | 
action\_result\.data\.\*\.visibleForReview | boolean | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list threat models'
List all the threat models

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**modified\_ts\_\_gte** |  optional  | Threat models with greater than or equal to the provided modified time stamp will be returned | string | 
**limit** |  optional  | Total number of threat models to return | numeric | 
**model\_type** |  optional  | Model type to filter the records | string | 
**tags\_name** |  optional  | Tag name to filter the records | string |  `threatstream tags` 
**publication\_status** |  optional  | Publication status to filter the records | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.model\_type | string | 
action\_result\.parameter\.modified\_ts\_\_gte | string | 
action\_result\.parameter\.publication\_status | string | 
action\_result\.parameter\.tags\_name | string |  `threatstream tags` 
action\_result\.data\.\*\.aliases | string | 
action\_result\.data\.\*\.assignee\_user\.email | string | 
action\_result\.data\.\*\.assignee\_user\.id | numeric | 
action\_result\.data\.\*\.assignee\_user\.name | string | 
action\_result\.data\.\*\.circles\.\*\.id | numeric | 
action\_result\.data\.\*\.circles\.\*\.name | string | 
action\_result\.data\.\*\.circles\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.cvss2\_score | string | 
action\_result\.data\.\*\.cvss3\_score | string | 
action\_result\.data\.\*\.end\_date | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id` 
action\_result\.data\.\*\.is\_email | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.model\_type | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string |  `email` 
action\_result\.data\.\*\.organization\.id | numeric | 
action\_result\.data\.\*\.organization\.title | string | 
action\_result\.data\.\*\.owner\_user\.email | string |  `email` 
action\_result\.data\.\*\.owner\_user\.id | numeric | 
action\_result\.data\.\*\.owner\_user\.name | string | 
action\_result\.data\.\*\.publication\_status | string | 
action\_result\.data\.\*\.published\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.sort | numeric | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.start\_date | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.tags\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\.\*\.tlp | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.summary\.threat\_models\_returned | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create threat bulletin'
Create a threat bulletin in ThreatStream

Type: **generic**  
Read only: **False**

<ul><li>Circles parameter will only be applicable when a threat bulletin will be created on the cloud\.</li><li>If the body\_content\_type parameter is not provided, then the default value \(markdown\) will be considered as the value of the body\_content\_type parameter\. Once created, body\_content\_type cannot be modified\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | Name to give the threat bulletin | string | 
**status** |  optional  | Status to give the threat bulletin | string | 
**source** |  optional  | Source of the threat bulletin | string | 
**tags** |  optional  | Comma\-separated list of tags for the threat bulletin | string | 
**tlp** |  optional  | Tlp to give the threat bulletin | string | 
**assignee\_user\_id** |  optional  | Assignee to give the threat bulletin | numeric | 
**body** |  optional  | Body content to give the threat bulletin | string | 
**body\_content\_type** |  optional  | Body content type to give the threat bulletin \(Once specified, body\_content\_type cannot be modified, Default is 'markdown'\) | string | 
**comments** |  optional  | Comments to give the threat bulletin\(JSON format containing body, title, etc\.\) | string | 
**attachments** |  optional  | Vault id of an attachment to add on the threat bulletin | string |  `vault id`  `sha1` 
**local\_intelligence** |  optional  | Comma\-separated list of local intelligence IDs to associate with the threat bulletin \- Note that this appends | string |  `threatstream intelligence id` 
**cloud\_intelligence** |  optional  | Comma\-separated list of remote intelligence IDs to associate with the threat bulletin \- Note that this appends | string |  `threatstream intelligence id` 
**circles** |  optional  | Comma\-separated list of circles to give the threat bulletin \(Applicable only when a cloud threat bulletin will be created\) | string | 
**import\_sessions** |  optional  | Comma\-separated list of sessions to give the threat bulletin | string | 
**create\_on\_cloud** |  optional  | Create on remote \(cloud\)? \(applicable only for hybrid on\-prem instances\) | boolean | 
**is\_public** |  optional  | Classification designation | boolean | 
**is\_anonymous** |  optional  | Whether the threat bulletin user and organization information is anonymized | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.assignee\_user\_id | numeric | 
action\_result\.parameter\.attachments | string |  `vault id`  `sha1` 
action\_result\.parameter\.body | string | 
action\_result\.parameter\.body\_content\_type | string | 
action\_result\.parameter\.circles | string | 
action\_result\.parameter\.cloud\_intelligence | string |  `threatstream intelligence id` 
action\_result\.parameter\.comments | string | 
action\_result\.parameter\.create\_on\_cloud | boolean | 
action\_result\.parameter\.import\_sessions | string | 
action\_result\.parameter\.is\_anonymous | boolean | 
action\_result\.parameter\.is\_public | boolean | 
action\_result\.parameter\.local\_intelligence | string |  `threatstream intelligence id` 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.source | string | 
action\_result\.parameter\.status | string | 
action\_result\.parameter\.tags | string | 
action\_result\.parameter\.tlp | string | 
action\_result\.data\.\*\.all\_circles\_visible | boolean | 
action\_result\.data\.\*\.assignee\_org | string | 
action\_result\.data\.\*\.assignee\_org\_id | string | 
action\_result\.data\.\*\.assignee\_org\_name | string | 
action\_result\.data\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.assignee\_user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.assignee\_user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.assignee\_user\.email | string |  `email` 
action\_result\.data\.\*\.assignee\_user\.id | string | 
action\_result\.data\.\*\.assignee\_user\.is\_active | boolean | 
action\_result\.data\.\*\.assignee\_user\.is\_readonly | boolean | 
action\_result\.data\.\*\.assignee\_user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.assignee\_user\.name | string | 
action\_result\.data\.\*\.assignee\_user\.nickname | string | 
action\_result\.data\.\*\.assignee\_user\.organization\.id | string | 
action\_result\.data\.\*\.assignee\_user\.organization\.name | string | 
action\_result\.data\.\*\.assignee\_user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.assignee\_user\.resource\_uri | string | 
action\_result\.data\.\*\.assignee\_user\_id | numeric | 
action\_result\.data\.\*\.assignee\_user\_name | string | 
action\_result\.data\.\*\.attachments | string | 
action\_result\.data\.\*\.body | string | 
action\_result\.data\.\*\.body\_content\_type | string | 
action\_result\.data\.\*\.campaign | string | 
action\_result\.data\.\*\.comments\.body | string | 
action\_result\.data\.\*\.comments\.created\_ts | string | 
action\_result\.data\.\*\.comments\.id | string | 
action\_result\.data\.\*\.comments\.modified\_ts | string | 
action\_result\.data\.\*\.comments\.remote\_api | boolean | 
action\_result\.data\.\*\.comments\.tip\_report | numeric | 
action\_result\.data\.\*\.comments\.title | string | 
action\_result\.data\.\*\.comments\.tlp | string | 
action\_result\.data\.\*\.comments\.user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.comments\.user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.comments\.user\.email | string |  `email` 
action\_result\.data\.\*\.comments\.user\.id | string | 
action\_result\.data\.\*\.comments\.user\.is\_active | boolean | 
action\_result\.data\.\*\.comments\.user\.is\_readonly | boolean | 
action\_result\.data\.\*\.comments\.user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.comments\.user\.name | string | 
action\_result\.data\.\*\.comments\.user\.nickname | string | 
action\_result\.data\.\*\.comments\.user\.organization\.id | string | 
action\_result\.data\.\*\.comments\.user\.organization\.name | string | 
action\_result\.data\.\*\.comments\.user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.comments\.user\.resource\_uri | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.embedded\_content\_type | string | 
action\_result\.data\.\*\.embedded\_content\_url | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.history\.\*\.action | string | 
action\_result\.data\.\*\.history\.\*\.detail | string | 
action\_result\.data\.\*\.history\.\*\.id | string | 
action\_result\.data\.\*\.history\.\*\.quantity | string | 
action\_result\.data\.\*\.history\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.history\.\*\.tip\_report | numeric | 
action\_result\.data\.\*\.history\.\*\.ts | string | 
action\_result\.data\.\*\.history\.\*\.user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.history\.\*\.user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.history\.\*\.user\.email | string |  `email` 
action\_result\.data\.\*\.history\.\*\.user\.id | string | 
action\_result\.data\.\*\.history\.\*\.user\.is\_active | boolean | 
action\_result\.data\.\*\.history\.\*\.user\.is\_readonly | boolean | 
action\_result\.data\.\*\.history\.\*\.user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.history\.\*\.user\.name | string | 
action\_result\.data\.\*\.history\.\*\.user\.nickname | string | 
action\_result\.data\.\*\.history\.\*\.user\.organization\.id | string | 
action\_result\.data\.\*\.history\.\*\.user\.organization\.name | string | 
action\_result\.data\.\*\.history\.\*\.user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.history\.\*\.user\.resource\_uri | string | 
action\_result\.data\.\*\.id | string |  `threatstream threatbulletin id` 
action\_result\.data\.\*\.intelligence\.\*\.id | numeric | 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.is\_email | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.logo\_s3\_url | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.original\_source | string | 
action\_result\.data\.\*\.original\_source\_id | string | 
action\_result\.data\.\*\.owner\_org\.id | string | 
action\_result\.data\.\*\.owner\_org\.name | string | 
action\_result\.data\.\*\.owner\_org\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_org\_id | numeric | 
action\_result\.data\.\*\.owner\_org\_name | string | 
action\_result\.data\.\*\.owner\_user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.owner\_user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.owner\_user\.email | string |  `email` 
action\_result\.data\.\*\.owner\_user\.id | string | 
action\_result\.data\.\*\.owner\_user\.is\_active | boolean | 
action\_result\.data\.\*\.owner\_user\.is\_readonly | boolean | 
action\_result\.data\.\*\.owner\_user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.owner\_user\.name | string | 
action\_result\.data\.\*\.owner\_user\.nickname | string | 
action\_result\.data\.\*\.owner\_user\.organization\.id | string | 
action\_result\.data\.\*\.owner\_user\.organization\.name | string | 
action\_result\.data\.\*\.owner\_user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_user\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_user\_id | numeric | 
action\_result\.data\.\*\.owner\_user\_name | string | 
action\_result\.data\.\*\.parent | string | 
action\_result\.data\.\*\.private\_status\_id | string | 
action\_result\.data\.\*\.published\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.starred\_by\_me | boolean | 
action\_result\.data\.\*\.starred\_total\_count | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.threat\_actor | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.ttp | string | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.votes\.me | string | 
action\_result\.data\.\*\.votes\.total | numeric | 
action\_result\.data\.\*\.watched\_by\_me | boolean | 
action\_result\.data\.\*\.watched\_total\_count | numeric | 
action\_result\.summary\.created\_on\_cloud | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update threat bulletin'
Update a threat bulletin in ThreatStream

Type: **generic**  
Read only: **False**

Circles parameter will only be applicable when a cloud threat bulletin will be updated\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | ID of the threat bulletin | string |  `threatstream threatbulletin id` 
**status** |  optional  | Status to give the threat bulletin | string | 
**source** |  optional  | Source of the threat bulletin | string | 
**tags** |  optional  | Comma\-separated list of tags for the threat bulletin | string | 
**tlp** |  optional  | Tlp to give the threat bulletin | string | 
**assignee\_user\_id** |  optional  | Assignee to give the threat bulletin | numeric | 
**body** |  optional  | Body content to give the threat bulletin | string | 
**comments** |  optional  | Comments to give the threat bulletin\(JSON format containing body, title, etc\.\) | string | 
**local\_intelligence** |  optional  | Comma\-separated list of local intelligence IDs to associate with the threat bulletin \- Note that this appends | string |  `threatstream intelligence id` 
**cloud\_intelligence** |  optional  | Comma\-separated list of remote intelligence IDs to associate with the threat bulletin \- Note that this appends | string |  `threatstream intelligence id` 
**attachments** |  optional  | Vault id of an attachment to add on the threat bulletin | string |  `vault id`  `sha1` 
**circles** |  optional  | Comma\-separated list of circles to give the threat bulletin \(Applicable only when a cloud threat bulletin will be updated\) | string | 
**import\_sessions** |  optional  | Comma\-separated list of sessions to give the threat bulletin | string | 
**is\_public** |  optional  | Classification designation | boolean | 
**is\_anonymous** |  optional  | Whether the threat bulletin user and organization information is anonymized | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.assignee\_user\_id | numeric | 
action\_result\.parameter\.attachments | string |  `vault id`  `sha1` 
action\_result\.parameter\.body | string | 
action\_result\.parameter\.circles | string | 
action\_result\.parameter\.cloud\_intelligence | string |  `threatstream intelligence id` 
action\_result\.parameter\.comments | string | 
action\_result\.parameter\.id | string |  `threatstream threatbulletin id` 
action\_result\.parameter\.import\_sessions | string | 
action\_result\.parameter\.is\_anonymous | boolean | 
action\_result\.parameter\.is\_public | boolean | 
action\_result\.parameter\.local\_intelligence | string |  `threatstream intelligence id` 
action\_result\.parameter\.source | string | 
action\_result\.parameter\.status | string | 
action\_result\.parameter\.tags | string | 
action\_result\.parameter\.tlp | string | 
action\_result\.data\.\*\.all\_circles\_visible | boolean | 
action\_result\.data\.\*\.assignee\_org | string | 
action\_result\.data\.\*\.assignee\_org\_id | string | 
action\_result\.data\.\*\.assignee\_org\_name | string | 
action\_result\.data\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.assignee\_user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.assignee\_user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.assignee\_user\.email | string | 
action\_result\.data\.\*\.assignee\_user\.id | string | 
action\_result\.data\.\*\.assignee\_user\.is\_active | boolean | 
action\_result\.data\.\*\.assignee\_user\.is\_readonly | boolean | 
action\_result\.data\.\*\.assignee\_user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.assignee\_user\.name | string | 
action\_result\.data\.\*\.assignee\_user\.nickname | string | 
action\_result\.data\.\*\.assignee\_user\.organization\.id | string | 
action\_result\.data\.\*\.assignee\_user\.organization\.name | string | 
action\_result\.data\.\*\.assignee\_user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.assignee\_user\.resource\_uri | string | 
action\_result\.data\.\*\.assignee\_user\_id | string | 
action\_result\.data\.\*\.assignee\_user\_name | string | 
action\_result\.data\.\*\.attachments\.\*\.content\_type | string | 
action\_result\.data\.\*\.attachments\.\*\.created\_ts | string | 
action\_result\.data\.\*\.attachments\.\*\.filename | string | 
action\_result\.data\.\*\.attachments\.\*\.id | string | 
action\_result\.data\.\*\.attachments\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.attachments\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.attachments\.\*\.s3\_thumbnail\_url | string | 
action\_result\.data\.\*\.attachments\.\*\.s3\_url | string | 
action\_result\.data\.\*\.attachments\.\*\.signed\_thumbnail\_url | string | 
action\_result\.data\.\*\.attachments\.\*\.signed\_url | string | 
action\_result\.data\.\*\.attachments\.\*\.tip\_report | numeric | 
action\_result\.data\.\*\.attachments\.\*\.user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.attachments\.\*\.user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.attachments\.\*\.user\.email | string | 
action\_result\.data\.\*\.attachments\.\*\.user\.id | string | 
action\_result\.data\.\*\.attachments\.\*\.user\.is\_active | boolean | 
action\_result\.data\.\*\.attachments\.\*\.user\.is\_readonly | boolean | 
action\_result\.data\.\*\.attachments\.\*\.user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.attachments\.\*\.user\.name | string | 
action\_result\.data\.\*\.attachments\.\*\.user\.nickname | string | 
action\_result\.data\.\*\.attachments\.\*\.user\.organization\.id | string | 
action\_result\.data\.\*\.attachments\.\*\.user\.organization\.name | string | 
action\_result\.data\.\*\.attachments\.\*\.user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.attachments\.\*\.user\.resource\_uri | string | 
action\_result\.data\.\*\.attachments\.content\_type | string | 
action\_result\.data\.\*\.attachments\.created\_ts | string | 
action\_result\.data\.\*\.attachments\.filename | string | 
action\_result\.data\.\*\.attachments\.id | string | 
action\_result\.data\.\*\.attachments\.modified\_ts | string | 
action\_result\.data\.\*\.attachments\.remote\_api | boolean | 
action\_result\.data\.\*\.attachments\.s3\_thumbnail\_url | string | 
action\_result\.data\.\*\.attachments\.s3\_url | string |  `url` 
action\_result\.data\.\*\.attachments\.signed\_thumbnail\_url | string | 
action\_result\.data\.\*\.attachments\.signed\_url | string |  `url` 
action\_result\.data\.\*\.attachments\.tip\_report | numeric | 
action\_result\.data\.\*\.attachments\.user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.attachments\.user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.attachments\.user\.email | string |  `email` 
action\_result\.data\.\*\.attachments\.user\.id | string | 
action\_result\.data\.\*\.attachments\.user\.is\_active | boolean | 
action\_result\.data\.\*\.attachments\.user\.is\_readonly | boolean | 
action\_result\.data\.\*\.attachments\.user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.attachments\.user\.name | string | 
action\_result\.data\.\*\.attachments\.user\.nickname | string | 
action\_result\.data\.\*\.attachments\.user\.organization\.id | string | 
action\_result\.data\.\*\.attachments\.user\.organization\.name | string | 
action\_result\.data\.\*\.attachments\.user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.attachments\.user\.resource\_uri | string | 
action\_result\.data\.\*\.body | string | 
action\_result\.data\.\*\.body\_content\_type | string | 
action\_result\.data\.\*\.campaign | string | 
action\_result\.data\.\*\.comments\.\*\.body | string | 
action\_result\.data\.\*\.comments\.\*\.created\_ts | string | 
action\_result\.data\.\*\.comments\.\*\.id | string | 
action\_result\.data\.\*\.comments\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.comments\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.comments\.\*\.tip\_report | numeric | 
action\_result\.data\.\*\.comments\.\*\.title | string | 
action\_result\.data\.\*\.comments\.\*\.tlp | string | 
action\_result\.data\.\*\.comments\.\*\.user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.comments\.\*\.user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.comments\.\*\.user\.email | string | 
action\_result\.data\.\*\.comments\.\*\.user\.id | string | 
action\_result\.data\.\*\.comments\.\*\.user\.is\_active | boolean | 
action\_result\.data\.\*\.comments\.\*\.user\.is\_readonly | boolean | 
action\_result\.data\.\*\.comments\.\*\.user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.comments\.\*\.user\.name | string | 
action\_result\.data\.\*\.comments\.\*\.user\.nickname | string | 
action\_result\.data\.\*\.comments\.\*\.user\.organization\.id | string | 
action\_result\.data\.\*\.comments\.\*\.user\.organization\.name | string | 
action\_result\.data\.\*\.comments\.\*\.user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.comments\.\*\.user\.resource\_uri | string | 
action\_result\.data\.\*\.comments\.body | string | 
action\_result\.data\.\*\.comments\.created\_ts | string | 
action\_result\.data\.\*\.comments\.id | string | 
action\_result\.data\.\*\.comments\.modified\_ts | string | 
action\_result\.data\.\*\.comments\.remote\_api | boolean | 
action\_result\.data\.\*\.comments\.tip\_report | numeric | 
action\_result\.data\.\*\.comments\.title | string | 
action\_result\.data\.\*\.comments\.tlp | string | 
action\_result\.data\.\*\.comments\.user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.comments\.user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.comments\.user\.email | string |  `email` 
action\_result\.data\.\*\.comments\.user\.id | string | 
action\_result\.data\.\*\.comments\.user\.is\_active | boolean | 
action\_result\.data\.\*\.comments\.user\.is\_readonly | boolean | 
action\_result\.data\.\*\.comments\.user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.comments\.user\.name | string | 
action\_result\.data\.\*\.comments\.user\.nickname | string | 
action\_result\.data\.\*\.comments\.user\.organization\.id | string | 
action\_result\.data\.\*\.comments\.user\.organization\.name | string | 
action\_result\.data\.\*\.comments\.user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.comments\.user\.resource\_uri | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.embedded\_content\_type | string | 
action\_result\.data\.\*\.embedded\_content\_url | string | 
action\_result\.data\.\*\.feed\_id | string | 
action\_result\.data\.\*\.history\.\*\.action | string | 
action\_result\.data\.\*\.history\.\*\.detail | string | 
action\_result\.data\.\*\.history\.\*\.id | string | 
action\_result\.data\.\*\.history\.\*\.quantity | string | 
action\_result\.data\.\*\.history\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.history\.\*\.tip\_report | numeric | 
action\_result\.data\.\*\.history\.\*\.ts | string | 
action\_result\.data\.\*\.history\.\*\.user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.history\.\*\.user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.history\.\*\.user\.email | string |  `email` 
action\_result\.data\.\*\.history\.\*\.user\.id | string | 
action\_result\.data\.\*\.history\.\*\.user\.is\_active | boolean | 
action\_result\.data\.\*\.history\.\*\.user\.is\_readonly | boolean | 
action\_result\.data\.\*\.history\.\*\.user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.history\.\*\.user\.name | string | 
action\_result\.data\.\*\.history\.\*\.user\.nickname | string | 
action\_result\.data\.\*\.history\.\*\.user\.organization\.id | string | 
action\_result\.data\.\*\.history\.\*\.user\.organization\.name | string | 
action\_result\.data\.\*\.history\.\*\.user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.history\.\*\.user\.resource\_uri | string | 
action\_result\.data\.\*\.id | string |  `threatstream threatbulletin id` 
action\_result\.data\.\*\.intelligence\.\*\.id | numeric | 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.is\_email | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.logo\_s3\_url | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.original\_source | string | 
action\_result\.data\.\*\.original\_source\_id | string | 
action\_result\.data\.\*\.owner\_org\.id | string | 
action\_result\.data\.\*\.owner\_org\.name | string | 
action\_result\.data\.\*\.owner\_org\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_org\_id | numeric | 
action\_result\.data\.\*\.owner\_org\_name | string | 
action\_result\.data\.\*\.owner\_user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.owner\_user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.owner\_user\.email | string |  `email` 
action\_result\.data\.\*\.owner\_user\.id | string | 
action\_result\.data\.\*\.owner\_user\.is\_active | boolean | 
action\_result\.data\.\*\.owner\_user\.is\_readonly | boolean | 
action\_result\.data\.\*\.owner\_user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.owner\_user\.name | string | 
action\_result\.data\.\*\.owner\_user\.nickname | string | 
action\_result\.data\.\*\.owner\_user\.organization\.id | string | 
action\_result\.data\.\*\.owner\_user\.organization\.name | string | 
action\_result\.data\.\*\.owner\_user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_user\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_user\_id | numeric | 
action\_result\.data\.\*\.owner\_user\_name | string | 
action\_result\.data\.\*\.parent | string | 
action\_result\.data\.\*\.private\_status\_id | string | 
action\_result\.data\.\*\.published\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.starred\_by\_me | boolean | 
action\_result\.data\.\*\.starred\_total\_count | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.threat\_actor | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.ttp | string | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.votes\.me | string | 
action\_result\.data\.\*\.votes\.total | numeric | 
action\_result\.data\.\*\.watched\_by\_me | boolean | 
action\_result\.data\.\*\.watched\_total\_count | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list threat bulletins'
List threat bulletins present in ThreatStream

Type: **investigate**  
Read only: **True**

<ul><li>This action will list the threat bulletins in oldest first format\.</li><li>is\_public parameter will only be applicable as filter when its value will be set to "true" or "false"\. It wont be applied as a filter and will list all the threat bulletins when the value of is\_public parameter is set to "all"\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Total number of threat bulletins to return | numeric | 
**name** |  optional  | Name to filter the threat bulletins | string | 
**status** |  optional  | Status to filter the threat bulletins | string | 
**source** |  optional  | Source to filter the threat bulletins | string | 
**assignee\_user\_id** |  optional  | Assignee to filter the threat bulletins | numeric | 
**is\_public** |  optional  | Classification designation | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.assignee\_user\_id | numeric | 
action\_result\.parameter\.is\_public | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.source | string | 
action\_result\.parameter\.status | string | 
action\_result\.data\.\*\.\*\.all\_circles\_visible | boolean | 
action\_result\.data\.\*\.\*\.assignee\_org | string | 
action\_result\.data\.\*\.\*\.assignee\_org\_id | string | 
action\_result\.data\.\*\.\*\.assignee\_org\_name | string | 
action\_result\.data\.\*\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.\*\.assignee\_user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.\*\.assignee\_user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.\*\.assignee\_user\.email | string | 
action\_result\.data\.\*\.\*\.assignee\_user\.id | string | 
action\_result\.data\.\*\.\*\.assignee\_user\.is\_active | boolean | 
action\_result\.data\.\*\.\*\.assignee\_user\.is\_readonly | boolean | 
action\_result\.data\.\*\.\*\.assignee\_user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.\*\.assignee\_user\.name | string | 
action\_result\.data\.\*\.\*\.assignee\_user\.nickname | string | 
action\_result\.data\.\*\.\*\.assignee\_user\.organization\.id | string | 
action\_result\.data\.\*\.\*\.assignee\_user\.organization\.name | string | 
action\_result\.data\.\*\.\*\.assignee\_user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.\*\.assignee\_user\.resource\_uri | string | 
action\_result\.data\.\*\.\*\.assignee\_user\_id | numeric | 
action\_result\.data\.\*\.\*\.assignee\_user\_name | string | 
action\_result\.data\.\*\.\*\.body\_content\_type | string | 
action\_result\.data\.\*\.\*\.campaign | string | 
action\_result\.data\.\*\.\*\.can\_add\_public\_tags | string | 
action\_result\.data\.\*\.\*\.created\_ts | string | 
action\_result\.data\.\*\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.\*\.id | string | 
action\_result\.data\.\*\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.\*\.is\_email | boolean | 
action\_result\.data\.\*\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.\*\.name | string | 
action\_result\.data\.\*\.\*\.original\_source | string | 
action\_result\.data\.\*\.\*\.original\_source\_id | string | 
action\_result\.data\.\*\.\*\.owner\_org | string | 
action\_result\.data\.\*\.\*\.owner\_org\.id | string | 
action\_result\.data\.\*\.\*\.owner\_org\.name | string | 
action\_result\.data\.\*\.\*\.owner\_org\.resource\_uri | string | 
action\_result\.data\.\*\.\*\.owner\_org\.title | string | 
action\_result\.data\.\*\.\*\.owner\_org\_id | string | 
action\_result\.data\.\*\.\*\.owner\_org\_name | string | 
action\_result\.data\.\*\.\*\.owner\_user | string | 
action\_result\.data\.\*\.\*\.owner\_user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.\*\.owner\_user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.\*\.owner\_user\.email | string | 
action\_result\.data\.\*\.\*\.owner\_user\.id | string | 
action\_result\.data\.\*\.\*\.owner\_user\.is\_active | boolean | 
action\_result\.data\.\*\.\*\.owner\_user\.is\_readonly | boolean | 
action\_result\.data\.\*\.\*\.owner\_user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.\*\.owner\_user\.name | string | 
action\_result\.data\.\*\.\*\.owner\_user\.nickname | string | 
action\_result\.data\.\*\.\*\.owner\_user\.organization\.id | string | 
action\_result\.data\.\*\.\*\.owner\_user\.organization\.name | string | 
action\_result\.data\.\*\.\*\.owner\_user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.\*\.owner\_user\.resource\_uri | string | 
action\_result\.data\.\*\.\*\.owner\_user\_id | string | 
action\_result\.data\.\*\.\*\.owner\_user\_name | string | 
action\_result\.data\.\*\.\*\.parent | string | 
action\_result\.data\.\*\.\*\.published\_ts | string | 
action\_result\.data\.\*\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.\*\.source | string | 
action\_result\.data\.\*\.\*\.source\_created | string | 
action\_result\.data\.\*\.\*\.source\_modified | string | 
action\_result\.data\.\*\.\*\.starred\_by\_me | boolean | 
action\_result\.data\.\*\.\*\.starred\_total\_count | numeric | 
action\_result\.data\.\*\.\*\.status | string | 
action\_result\.data\.\*\.\*\.tags\_v2\.\*\.id | string | 
action\_result\.data\.\*\.\*\.tags\_v2\.\*\.name | string | 
action\_result\.data\.\*\.\*\.tags\_v2\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.\*\.tags\_v2\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.\*\.tags\_v2\.\*\.tlp | string | 
action\_result\.data\.\*\.\*\.threat\_actor | string | 
action\_result\.data\.\*\.\*\.tlp | string | 
action\_result\.data\.\*\.\*\.ttp | string | 
action\_result\.data\.\*\.\*\.uuid | string | 
action\_result\.data\.\*\.\*\.votes\.me | string | 
action\_result\.data\.\*\.\*\.votes\.total | numeric | 
action\_result\.data\.\*\.\*\.watched\_by\_me | boolean | 
action\_result\.data\.\*\.\*\.watched\_total\_count | numeric | 
action\_result\.data\.\*\.all\_circles\_visible | boolean | 
action\_result\.data\.\*\.assignee\_org | string | 
action\_result\.data\.\*\.assignee\_org\_id | string | 
action\_result\.data\.\*\.assignee\_org\_name | string | 
action\_result\.data\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.assignee\_user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.assignee\_user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.assignee\_user\.email | string |  `email` 
action\_result\.data\.\*\.assignee\_user\.id | string | 
action\_result\.data\.\*\.assignee\_user\.is\_active | boolean | 
action\_result\.data\.\*\.assignee\_user\.is\_readonly | boolean | 
action\_result\.data\.\*\.assignee\_user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.assignee\_user\.name | string | 
action\_result\.data\.\*\.assignee\_user\.nickname | string | 
action\_result\.data\.\*\.assignee\_user\.organization\.id | string | 
action\_result\.data\.\*\.assignee\_user\.organization\.name | string | 
action\_result\.data\.\*\.assignee\_user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.assignee\_user\.resource\_uri | string | 
action\_result\.data\.\*\.assignee\_user\_id | numeric | 
action\_result\.data\.\*\.assignee\_user\_name | string | 
action\_result\.data\.\*\.body\_content\_type | string | 
action\_result\.data\.\*\.campaign | string | 
action\_result\.data\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.circles\.\*\.anonymous\_sharing | boolean | 
action\_result\.data\.\*\.circles\.\*\.can\_edit | boolean | 
action\_result\.data\.\*\.circles\.\*\.can\_invite | boolean | 
action\_result\.data\.\*\.circles\.\*\.can\_override\_confidence | boolean | 
action\_result\.data\.\*\.circles\.\*\.description | string | 
action\_result\.data\.\*\.circles\.\*\.disable\_vendor\_emails | string | 
action\_result\.data\.\*\.circles\.\*\.id | numeric | 
action\_result\.data\.\*\.circles\.\*\.is\_freemium | boolean | 
action\_result\.data\.\*\.circles\.\*\.mattermost\_team\_id | string | 
action\_result\.data\.\*\.circles\.\*\.member | boolean | 
action\_result\.data\.\*\.circles\.\*\.name | string | 
action\_result\.data\.\*\.circles\.\*\.num\_administrators | numeric | 
action\_result\.data\.\*\.circles\.\*\.num\_members | numeric | 
action\_result\.data\.\*\.circles\.\*\.openinvite | boolean | 
action\_result\.data\.\*\.circles\.\*\.pending | boolean | 
action\_result\.data\.\*\.circles\.\*\.public | boolean | 
action\_result\.data\.\*\.circles\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.circles\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.circles\.\*\.restricted\_publishing | boolean | 
action\_result\.data\.\*\.circles\.\*\.subscription\_model | string | 
action\_result\.data\.\*\.circles\.\*\.use\_chat | boolean | 
action\_result\.data\.\*\.circles\.\*\.validate\_subscriptions | boolean | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | string |  `threatstream threatbulletin id` 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.is\_email | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.original\_source | string | 
action\_result\.data\.\*\.original\_source\_id | string | 
action\_result\.data\.\*\.owner\_org | string | 
action\_result\.data\.\*\.owner\_org\.id | string | 
action\_result\.data\.\*\.owner\_org\.name | string | 
action\_result\.data\.\*\.owner\_org\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_org\.title | string | 
action\_result\.data\.\*\.owner\_org\_id | numeric | 
action\_result\.data\.\*\.owner\_org\_name | string | 
action\_result\.data\.\*\.owner\_user | string | 
action\_result\.data\.\*\.owner\_user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.owner\_user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.owner\_user\.email | string |  `email` 
action\_result\.data\.\*\.owner\_user\.id | string | 
action\_result\.data\.\*\.owner\_user\.is\_active | boolean | 
action\_result\.data\.\*\.owner\_user\.is\_readonly | boolean | 
action\_result\.data\.\*\.owner\_user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.owner\_user\.name | string | 
action\_result\.data\.\*\.owner\_user\.nickname | string | 
action\_result\.data\.\*\.owner\_user\.organization\.id | string | 
action\_result\.data\.\*\.owner\_user\.organization\.name | string | 
action\_result\.data\.\*\.owner\_user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_user\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_user\_id | numeric | 
action\_result\.data\.\*\.owner\_user\_name | string | 
action\_result\.data\.\*\.parent | string | 
action\_result\.data\.\*\.published\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.starred\_by\_me | boolean | 
action\_result\.data\.\*\.starred\_total\_count | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.id | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.name | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.tags\_v2\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\_v2\.\*\.tlp | string | 
action\_result\.data\.\*\.threat\_actor | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.ttp | string | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.votes\.me | string | 
action\_result\.data\.\*\.votes\.total | numeric | 
action\_result\.data\.\*\.watched\_by\_me | boolean | 
action\_result\.data\.\*\.watched\_total\_count | numeric | 
action\_result\.summary\.threat\_bulletins\_returned | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list associations'
List associations of an entity present in ThreatStream

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**entity\_id** |  required  | ID of the entity | string |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id` 
**limit** |  optional  | Total number of associations to return | numeric | 
**entity\_type** |  required  | Type of threat model entity to list the associations | string | 
**associated\_entity\_type** |  required  | Type of associations of the enitity to list | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.associated\_entity\_type | string | 
action\_result\.parameter\.entity\_id | string |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id` 
action\_result\.parameter\.entity\_type | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.all\_circles\_visible | boolean | 
action\_result\.data\.\*\.asn | string | 
action\_result\.data\.\*\.assignee\_org | string | 
action\_result\.data\.\*\.assignee\_org\_id | string | 
action\_result\.data\.\*\.assignee\_org\_name | string | 
action\_result\.data\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.assignee\_user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.assignee\_user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.assignee\_user\.email | string | 
action\_result\.data\.\*\.assignee\_user\.id | string | 
action\_result\.data\.\*\.assignee\_user\.is\_active | boolean | 
action\_result\.data\.\*\.assignee\_user\.is\_readonly | boolean | 
action\_result\.data\.\*\.assignee\_user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.assignee\_user\.name | string | 
action\_result\.data\.\*\.assignee\_user\.nickname | string | 
action\_result\.data\.\*\.assignee\_user\.organization\.id | string | 
action\_result\.data\.\*\.assignee\_user\.organization\.name | string | 
action\_result\.data\.\*\.assignee\_user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.assignee\_user\.resource\_uri | string | 
action\_result\.data\.\*\.assignee\_user\_id | string | 
action\_result\.data\.\*\.assignee\_user\_name | string | 
action\_result\.data\.\*\.association\_info\.\*\.comment | string | 
action\_result\.data\.\*\.association\_info\.\*\.created | string | 
action\_result\.data\.\*\.association\_info\.\*\.from\_id | string | 
action\_result\.data\.\*\.association\_info\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.body\_content\_type | string | 
action\_result\.data\.\*\.campaign | string | 
action\_result\.data\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.circles\.\*\.anonymous\_sharing | boolean | 
action\_result\.data\.\*\.circles\.\*\.can\_edit | boolean | 
action\_result\.data\.\*\.circles\.\*\.can\_invite | boolean | 
action\_result\.data\.\*\.circles\.\*\.can\_override\_confidence | boolean | 
action\_result\.data\.\*\.circles\.\*\.description | string | 
action\_result\.data\.\*\.circles\.\*\.disable\_vendor\_emails | string | 
action\_result\.data\.\*\.circles\.\*\.id | string | 
action\_result\.data\.\*\.circles\.\*\.is\_freemium | boolean | 
action\_result\.data\.\*\.circles\.\*\.mattermost\_team\_id | string | 
action\_result\.data\.\*\.circles\.\*\.member | boolean | 
action\_result\.data\.\*\.circles\.\*\.name | string | 
action\_result\.data\.\*\.circles\.\*\.num\_administrators | numeric | 
action\_result\.data\.\*\.circles\.\*\.num\_members | numeric | 
action\_result\.data\.\*\.circles\.\*\.openinvite | boolean | 
action\_result\.data\.\*\.circles\.\*\.pending | boolean | 
action\_result\.data\.\*\.circles\.\*\.public | boolean | 
action\_result\.data\.\*\.circles\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.circles\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.circles\.\*\.restricted\_publishing | boolean | 
action\_result\.data\.\*\.circles\.\*\.subscription\_model | string | 
action\_result\.data\.\*\.circles\.\*\.use\_chat | boolean | 
action\_result\.data\.\*\.circles\.\*\.validate\_subscriptions | boolean | 
action\_result\.data\.\*\.confidence | numeric | 
action\_result\.data\.\*\.country | string | 
action\_result\.data\.\*\.created\_by | string |  `email` 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.end\_date | string | 
action\_result\.data\.\*\.expiration\_ts | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id` 
action\_result\.data\.\*\.import\_session\_id | numeric | 
action\_result\.data\.\*\.import\_source | string | 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_category | boolean | 
action\_result\.data\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.is\_email | boolean | 
action\_result\.data\.\*\.is\_mitre | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.is\_system | boolean | 
action\_result\.data\.\*\.itype | string | 
action\_result\.data\.\*\.latitude | string | 
action\_result\.data\.\*\.longitude | string | 
action\_result\.data\.\*\.meta\.detail2 | string | 
action\_result\.data\.\*\.meta\.severity | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.objective | string | 
action\_result\.data\.\*\.org | string | 
action\_result\.data\.\*\.organization\_id | numeric | 
action\_result\.data\.\*\.original\_source | string | 
action\_result\.data\.\*\.original\_source\_id | string | 
action\_result\.data\.\*\.owner\_org\.id | string | 
action\_result\.data\.\*\.owner\_org\.name | string | 
action\_result\.data\.\*\.owner\_org\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_org\_id | numeric | 
action\_result\.data\.\*\.owner\_org\_name | string | 
action\_result\.data\.\*\.owner\_organization\_id | numeric | 
action\_result\.data\.\*\.owner\_user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.owner\_user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.owner\_user\.email | string | 
action\_result\.data\.\*\.owner\_user\.id | string | 
action\_result\.data\.\*\.owner\_user\.is\_active | boolean | 
action\_result\.data\.\*\.owner\_user\.is\_readonly | boolean | 
action\_result\.data\.\*\.owner\_user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.owner\_user\.name | string | 
action\_result\.data\.\*\.owner\_user\.nickname | string | 
action\_result\.data\.\*\.owner\_user\.organization\.id | string | 
action\_result\.data\.\*\.owner\_user\.organization\.name | string | 
action\_result\.data\.\*\.owner\_user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_user\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_user\_id | numeric | 
action\_result\.data\.\*\.owner\_user\_name | string | 
action\_result\.data\.\*\.parent | string | 
action\_result\.data\.\*\.publication\_status | string | 
action\_result\.data\.\*\.published\_ts | string | 
action\_result\.data\.\*\.rdns | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.retina\_confidence | numeric | 
action\_result\.data\.\*\.s\_type | string | 
action\_result\.data\.\*\.sort | string | 
action\_result\.data\.\*\.source | string |  `email` 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.source\_reported\_confidence | numeric | 
action\_result\.data\.\*\.starred\_by\_me | boolean | 
action\_result\.data\.\*\.starred\_total\_count | numeric | 
action\_result\.data\.\*\.start\_date | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.status\.display\_name | string | 
action\_result\.data\.\*\.status\.id | numeric | 
action\_result\.data\.\*\.status\.resource\_uri | string | 
action\_result\.data\.\*\.subtype | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.tags\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\.\*\.source\_user\_id | string | 
action\_result\.data\.\*\.tags\.\*\.tlp | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.id | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.name | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.tags\_v2\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\_v2\.\*\.tlp | string | 
action\_result\.data\.\*\.threat\_actor | string | 
action\_result\.data\.\*\.threat\_type | string | 
action\_result\.data\.\*\.threatscore | numeric | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.trusted\_circle\_ids | string | 
action\_result\.data\.\*\.ttp | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.update\_id | string | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.value | string |  `email`  `ip`  `sha256` 
action\_result\.data\.\*\.votes\.me | string | 
action\_result\.data\.\*\.votes\.total | numeric | 
action\_result\.data\.\*\.watched\_by\_me | boolean | 
action\_result\.data\.\*\.watched\_total\_count | numeric | 
action\_result\.summary\.associations\_returned | numeric | 
action\_result\.summary\.threat\_bulletin\_observables\_returned | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create rule'
Creates a new rule in Threatstream

Type: **generic**  
Read only: **False**

<li> In the field param, tags, actors, malware, campaigns, incidents, signature, tips, ttps, vulnerabilities accepts list of IDs as an example\: \{“incidents”\: \[1000000001\], “actors”\: \[1000000001\], “vulnerabilities”\: \[1000000001, 1000000002\], “campaigns”\: \[1000000001\], “signatures”\: \[1000000001\], “tags”\: \[\{“name”\:“test\_tag”,“tlp”\:“white”\}\], “match\_impacts”\: \[ “actor\_ip”, “actor\_ipv6” \]\} </li> <li> In field param, at least one Match Within parameter \(match\_observables, match\_reportedfiles, match\_signatures, match\_tips, or match\_vulnerabilities\) should be true\. Otherwise, the action will pass and a rule will be created but it will throw an error while updating it from the UI\. </li> <li>Do not specify values for both match\_impacts and exclude\_impacts in the same request\. Indicator types specified in match\_impacts are filtered out if also specified in exclude\_impacts\.</li>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | Name of the rule | string | 
**keywords** |  required  | List of keywords for which you want the rule to match\. i\.e \["keyword1", "keyword2"\] | string | 
**fields** |  optional  | JSON formatted string of fields to include with the rule | string | 
**create\_on\_cloud** |  optional  | Create on remote \(cloud\)? \(applicable only for hybrid on\-prem instances\) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.create\_on\_cloud | boolean | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.keywords | string | 
action\_result\.parameter\.name | string | 
action\_result\.data\.\*\.actors\.\*\.id | string |  `threatstream actor id` 
action\_result\.data\.\*\.actors\.\*\.name | string | 
action\_result\.data\.\*\.actors\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.actors\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.campaigns\.\*\.id | string |  `threatstream campaign id` 
action\_result\.data\.\*\.campaigns\.\*\.name | string | 
action\_result\.data\.\*\.campaigns\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.campaigns\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.create\_investigation | boolean | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.exclude\_notify\_org\_whitelisted | boolean | 
action\_result\.data\.\*\.exclude\_notify\_owner\_org | boolean | 
action\_result\.data\.\*\.id | numeric |  `threatstream rule id` 
action\_result\.data\.\*\.investigation | string | 
action\_result\.data\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.is\_enabled | boolean | 
action\_result\.data\.\*\.keyword | string | 
action\_result\.data\.\*\.keywords | string | 
action\_result\.data\.\*\.match\_actors | boolean | 
action\_result\.data\.\*\.match\_campaigns | boolean | 
action\_result\.data\.\*\.match\_impact | string | 
action\_result\.data\.\*\.match\_incidents | boolean | 
action\_result\.data\.\*\.match\_malware | boolean | 
action\_result\.data\.\*\.match\_observables | boolean | 
action\_result\.data\.\*\.match\_reportedfiles | boolean | 
action\_result\.data\.\*\.match\_signatures | boolean | 
action\_result\.data\.\*\.match\_tips | boolean | 
action\_result\.data\.\*\.match\_ttps | boolean | 
action\_result\.data\.\*\.match\_vulnerabilities | boolean | 
action\_result\.data\.\*\.matches | numeric | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.notify\_me | boolean | 
action\_result\.data\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.org\_shared | boolean | 
action\_result\.data\.\*\.organization\.id | string | 
action\_result\.data\.\*\.organization\.name | string | 
action\_result\.data\.\*\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\.\*\.tlp | string | 
action\_result\.data\.\*\.user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.user\.email | string |  `email` 
action\_result\.data\.\*\.user\.id | string | 
action\_result\.data\.\*\.user\.is\_active | boolean | 
action\_result\.data\.\*\.user\.is\_readonly | boolean | 
action\_result\.data\.\*\.user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.user\.name | string | 
action\_result\.data\.\*\.user\.nickname | string | 
action\_result\.data\.\*\.user\.organization\.id | string | 
action\_result\.data\.\*\.user\.organization\.name | string | 
action\_result\.data\.\*\.user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.user\.resource\_uri | string | 
action\_result\.data\.\*\.user\_id | numeric | 
action\_result\.data\.\*\.vulnerabilities\.\*\.id | string |  `threatstream vulnerability id` 
action\_result\.data\.\*\.vulnerabilities\.\*\.name | string | 
action\_result\.data\.\*\.vulnerabilities\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.vulnerabilities\.\*\.resource\_uri | string | 
action\_result\.summary\.id | numeric | 
action\_result\.summary\.message | string | 
action\_result\.message | string | 
summary\.message | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update rule'
Update a rule in ThreatStream by ID number

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**fields** |  required  | JSON formatted string of fields to update on the incident | string | 
**rule\_id** |  required  | ID number of rule to update | string |  `threatstream rule id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.rule\_id | string |  `threatstream rule id` 
action\_result\.data\.\*\.actors\.\*\.id | string |  `threatstream actor id` 
action\_result\.data\.\*\.actors\.\*\.name | string | 
action\_result\.data\.\*\.actors\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.actors\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.campaigns\.\*\.id | string |  `threatstream campaign id` 
action\_result\.data\.\*\.campaigns\.\*\.name | string | 
action\_result\.data\.\*\.campaigns\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.campaigns\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.create\_investigation | boolean | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.exclude\_notify\_org\_whitelisted | boolean | 
action\_result\.data\.\*\.exclude\_notify\_owner\_org | boolean | 
action\_result\.data\.\*\.id | numeric |  `threatstream rule id` 
action\_result\.data\.\*\.incidents\.\*\.id | string |  `threatstream incident id` 
action\_result\.data\.\*\.incidents\.\*\.name | string | 
action\_result\.data\.\*\.incidents\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.incidents\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.investigation | string | 
action\_result\.data\.\*\.investigation\.id | string | 
action\_result\.data\.\*\.investigation\.name | string | 
action\_result\.data\.\*\.investigation\.resource\_uri | string | 
action\_result\.data\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.is\_enabled | boolean | 
action\_result\.data\.\*\.keyword | string | 
action\_result\.data\.\*\.keywords | string | 
action\_result\.data\.\*\.match\_actors | boolean | 
action\_result\.data\.\*\.match\_campaigns | boolean | 
action\_result\.data\.\*\.match\_impact | string | 
action\_result\.data\.\*\.match\_impacts | string | 
action\_result\.data\.\*\.match\_incidents | boolean | 
action\_result\.data\.\*\.match\_malware | boolean | 
action\_result\.data\.\*\.match\_observables | boolean | 
action\_result\.data\.\*\.match\_reportedfiles | boolean | 
action\_result\.data\.\*\.match\_signatures | boolean | 
action\_result\.data\.\*\.match\_tips | boolean | 
action\_result\.data\.\*\.match\_ttps | boolean | 
action\_result\.data\.\*\.match\_vulnerabilities | boolean | 
action\_result\.data\.\*\.matches | numeric | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.notify\_me | boolean | 
action\_result\.data\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.org\_shared | boolean | 
action\_result\.data\.\*\.organization\.id | string | 
action\_result\.data\.\*\.organization\.name | string | 
action\_result\.data\.\*\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\.\*\.tlp | string | 
action\_result\.data\.\*\.ttps\.\*\.id | string |  `threatstream ttp id` 
action\_result\.data\.\*\.ttps\.\*\.name | string | 
action\_result\.data\.\*\.ttps\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.user\.email | string |  `email` 
action\_result\.data\.\*\.user\.id | string | 
action\_result\.data\.\*\.user\.is\_active | boolean | 
action\_result\.data\.\*\.user\.is\_readonly | boolean | 
action\_result\.data\.\*\.user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.user\.name | string | 
action\_result\.data\.\*\.user\.nickname | string | 
action\_result\.data\.\*\.user\.organization\.id | string | 
action\_result\.data\.\*\.user\.organization\.name | string | 
action\_result\.data\.\*\.user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.user\.resource\_uri | string | 
action\_result\.data\.\*\.user\_id | numeric | 
action\_result\.data\.\*\.vulnerabilities\.\*\.id | string |  `threatstream vulnerability id` 
action\_result\.data\.\*\.vulnerabilities\.\*\.name | string | 
action\_result\.data\.\*\.vulnerabilities\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.vulnerabilities\.\*\.resource\_uri | string | 
action\_result\.summary | string | 
action\_result\.summary\.id | numeric | 
action\_result\.summary\.message | string | 
action\_result\.message | string | 
summary\.message | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list rules'
List rules present in ThreatStream

Type: **investigate**  
Read only: **True**

<ul><li>The rules will be listed in the latest first order on the basis of created\_ts\.</li><li>If the limit parameter is not provided, then the default value \(1000\) will be considered as the value of the limit parameter\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Total number of rules to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.create\_investigation | boolean | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.exclude\_notify\_org\_whitelisted | boolean | 
action\_result\.data\.\*\.exclude\_notify\_owner\_org | boolean | 
action\_result\.data\.\*\.has\_associations | boolean | 
action\_result\.data\.\*\.id | numeric |  `threatstream rule id` 
action\_result\.data\.\*\.investigation | string | 
action\_result\.data\.\*\.investigation\.id | string | 
action\_result\.data\.\*\.investigation\.name | string | 
action\_result\.data\.\*\.investigation\.resource\_uri | string | 
action\_result\.data\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.is\_enabled | boolean | 
action\_result\.data\.\*\.keyword | string | 
action\_result\.data\.\*\.keywords | string | 
action\_result\.data\.\*\.match\_actors | boolean | 
action\_result\.data\.\*\.match\_campaigns | boolean | 
action\_result\.data\.\*\.match\_incidents | boolean | 
action\_result\.data\.\*\.match\_malware | boolean | 
action\_result\.data\.\*\.match\_observables | boolean | 
action\_result\.data\.\*\.match\_reportedfiles | boolean | 
action\_result\.data\.\*\.match\_signatures | boolean | 
action\_result\.data\.\*\.match\_tips | boolean | 
action\_result\.data\.\*\.match\_ttps | boolean | 
action\_result\.data\.\*\.match\_vulnerabilities | boolean | 
action\_result\.data\.\*\.matches | numeric | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.notify\_me | boolean | 
action\_result\.data\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.org\_shared | boolean | 
action\_result\.data\.\*\.organization\.id | string | 
action\_result\.data\.\*\.organization\.name | string | 
action\_result\.data\.\*\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.tags\.\*\.tlp | string | 
action\_result\.data\.\*\.user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.user\.email | string |  `email` 
action\_result\.data\.\*\.user\.id | string | 
action\_result\.data\.\*\.user\.is\_active | boolean | 
action\_result\.data\.\*\.user\.is\_readonly | boolean | 
action\_result\.data\.\*\.user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.user\.name | string | 
action\_result\.data\.\*\.user\.nickname | string | 
action\_result\.data\.\*\.user\.organization\.id | string | 
action\_result\.data\.\*\.user\.organization\.name | string | 
action\_result\.data\.\*\.user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.user\.resource\_uri | string | 
action\_result\.data\.\*\.user\_id | numeric | 
action\_result\.summary\.rules\_returned | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete rule'
Delete rule in ThreatStream by ID number

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**rule\_id** |  required  | ID number of rule to delete | string |  `threatstream rule id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.rule\_id | string |  `threatstream rule id` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add association'
Create associations between threat model entities on the ThreatStream platform

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**entity\_type** |  required  | The type of the threat model entity on which want to add the association | string | 
**entity\_id** |  required  | The ID of the threat model entity on which want to add the association | numeric |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id` 
**associated\_entity\_type** |  required  | The type of threat model entity which will associate the initial entity | string | 
**local\_ids** |  optional  |  Comma\-separated list of local entity IDs to associate with the entity \(this will appends on the existing\) | string |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id`  `threatstream intelligence id` 
**remote\_ids** |  optional  | Comma\-separated list of remote enitity IDs to associate with the entity \(this will appends on the existing\) | string |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id`  `threatstream intelligence id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.associated\_entity\_type | string | 
action\_result\.parameter\.entity\_id | numeric |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id` 
action\_result\.parameter\.entity\_type | string | 
action\_result\.parameter\.local\_ids | string |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id`  `threatstream intelligence id` 
action\_result\.parameter\.remote\_ids | string |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id`  `threatstream intelligence id` 
action\_result\.data\.\* | string |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'remove association'
Remove associations between threat model entities on the ThreatStream platform

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**entity\_type** |  required  | Type of threat model entity from which you are removing the association | string | 
**entity\_id** |  required  | ID of the threat model entity from which you are removing the association | numeric |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id` 
**associated\_entity\_type** |  required  | Type of threat model entity with which you are associating the initial entity | string | 
**local\_ids** |  optional  | Comma\-separated list of local enitity IDs to associate with the entity \- Note that this appends | string |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id`  `threatstream intelligence id` 
**remote\_ids** |  optional  | Comma\-separated list of remote enitity IDs to associate with the entity \- Note that this appends | string |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id`  `threatstream intelligence id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.associated\_entity\_type | string | 
action\_result\.parameter\.entity\_id | numeric |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id` 
action\_result\.parameter\.entity\_type | string | 
action\_result\.parameter\.local\_ids | string |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id`  `threatstream intelligence id` 
action\_result\.parameter\.remote\_ids | string |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id`  `threatstream intelligence id` 
action\_result\.data\.\* | string |  `threatstream actor id`  `threatstream campaign id`  `threatstream incident id`  `threatstream vulnerability id`  `threatstream ttp id`  `threatstream threatbulletin id`  `threatstream signature id` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list actors'
List actors present in ThreatStream

Type: **investigate**  
Read only: **True**

<ul><li>The actors will be listed in the latest first order on the basis of created\_ts\.</li><li>If the limit parameter is not provided, then the default value \(1000\) will be considered as the value of the limit parameter\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Total number of actors to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.aliases\.\*\.name | string | 
action\_result\.data\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.circles\.\*\.id | numeric | 
action\_result\.data\.\*\.circles\.\*\.name | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.end\_date | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `threatstream actor id` 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.is\_email | string | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.is\_team | boolean | 
action\_result\.data\.\*\.model\_type | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.organization\.id | numeric | 
action\_result\.data\.\*\.organization\.title | string | 
action\_result\.data\.\*\.organization\_id | numeric | 
action\_result\.data\.\*\.owner\_user\.email | string |  `email` 
action\_result\.data\.\*\.owner\_user\.id | numeric | 
action\_result\.data\.\*\.owner\_user\.name | string | 
action\_result\.data\.\*\.owner\_user\_id | numeric | 
action\_result\.data\.\*\.primary\_motivation | string | 
action\_result\.data\.\*\.publication\_status | string | 
action\_result\.data\.\*\.published\_ts | string | 
action\_result\.data\.\*\.resource\_level | string | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.sort | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.start\_date | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.tags\.\*\.tlp | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.id | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.name | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.tags\_v2\.\*\.tlp | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.summary\.actors\_returned | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list imports'
List imports present in ThreatStream

Type: **investigate**  
Read only: **True**

<ul><li>The imports will be listed in the latest first order on the basis of created\_ts\.</li><li>If the limit parameter is not provided, then the default value \(1000\) will be considered as the value of the limit parameter\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Total number of imports to return | numeric | 
**status** |  optional  | Status of imports | string | 
**list\_from\_remote** |  optional  | List from remote? \(applicable only for hybrid on\-prem instances\) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.list\_from\_remote | boolean | 
action\_result\.parameter\.status | string | 
action\_result\.data\.\*\.confidence | numeric | 
action\_result\.data\.\*\.data | string | 
action\_result\.data\.\*\.date | string | 
action\_result\.data\.\*\.date\_modified | string | 
action\_result\.data\.\*\.expiration\_ts | string | 
action\_result\.data\.\*\.fileName | string |  `sha1`  `url` 
action\_result\.data\.\*\.fileType | string | 
action\_result\.data\.\*\.file\_name\_label | string | 
action\_result\.data\.\*\.id | numeric |  `threatstream import session id` 
action\_result\.data\.\*\.intelligence\_source | string |  `sha1`  `url` 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.jobID | string | 
action\_result\.data\.\*\.messages | string | 
action\_result\.data\.\*\.notes | string | 
action\_result\.data\.\*\.numIndicators | numeric | 
action\_result\.data\.\*\.numRejected | numeric | 
action\_result\.data\.\*\.num\_private | numeric | 
action\_result\.data\.\*\.num\_public | numeric | 
action\_result\.data\.\*\.orginal\_intelligence | string | 
action\_result\.data\.\*\.processed\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.source\_confidence\_weight | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.threat\_type | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.visibleForReview | boolean | 
action\_result\.summary\.import\_returned | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create vulnerability'
Create a vulnerability in ThreatStream

Type: **generic**  
Read only: **False**

<ul><li>The "is\_public" parameter can not be set as "true" if the "create\_on\_cloud" parameter is "false" for hybride on\-prem instances\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | Name to give the vulnerability | string | 
**fields** |  optional  | JSON formatted string of fields to include with the vulnerability | string | 
**local\_intelligence** |  optional  | Comma\-separated list of local intelligence IDs to associate with the vulnerability \- Note that this appends | string |  `threatstream intelligence id` 
**cloud\_intelligence** |  optional  | Comma\-separated list of remote intelligence IDs to associate with the vulnerability \- Note that this appends | string |  `threatstream intelligence id` 
**comment** |  optional  | Comment to give the vulnerability \(JSON format containing body, title, etc\.\) | string | 
**attachment** |  optional  | Vault id of an attachment to add on the vulnerability | string |  `vault id`  `sha1` 
**is\_public** |  optional  | Classification designation | boolean | 
**create\_on\_cloud** |  optional  | Create on remote \(cloud\)? \(applicable only for hybrid on\-prem instances\) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.attachment | string |  `vault id`  `sha1` 
action\_result\.parameter\.cloud\_intelligence | string |  `threatstream intelligence id` 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.create\_on\_cloud | boolean | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.is\_public | boolean | 
action\_result\.parameter\.local\_intelligence | string |  `threatstream intelligence id` 
action\_result\.parameter\.name | string | 
action\_result\.data\.\*\.aliases | string | 
action\_result\.data\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.attachment | string | 
action\_result\.data\.\*\.attachments\.filename | string | 
action\_result\.data\.\*\.attachments\.id | numeric | 
action\_result\.data\.\*\.attachments\.r\_type | string | 
action\_result\.data\.\*\.attachments\.remote\_api | boolean | 
action\_result\.data\.\*\.attachments\.resource\_uri | string | 
action\_result\.data\.\*\.attachments\.s3\_url | string | 
action\_result\.data\.\*\.attachments\.title | string | 
action\_result\.data\.\*\.attachments\.url | string | 
action\_result\.data\.\*\.body\_content\_type | string | 
action\_result\.data\.\*\.campaigns\.\*\.id | numeric | 
action\_result\.data\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.circles\.\*\.id | string | 
action\_result\.data\.\*\.circles\.\*\.name | string | 
action\_result\.data\.\*\.circles\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.comment\.\!\@\#$%^ | string | 
action\_result\.data\.\*\.comment\.body | string | 
action\_result\.data\.\*\.comment\.created\_ts | string | 
action\_result\.data\.\*\.comment\.id | numeric | 
action\_result\.data\.\*\.comment\.invalid | string | 
action\_result\.data\.\*\.comment\.modified\_ts | string | 
action\_result\.data\.\*\.comment\.remote\_api | boolean | 
action\_result\.data\.\*\.comment\.resource\_uri | string | 
action\_result\.data\.\*\.comment\.title | string | 
action\_result\.data\.\*\.comment\.tlp | string | 
action\_result\.data\.\*\.comment\.user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.comment\.user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.comment\.user\.email | string |  `email` 
action\_result\.data\.\*\.comment\.user\.id | string | 
action\_result\.data\.\*\.comment\.user\.is\_active | boolean | 
action\_result\.data\.\*\.comment\.user\.is\_readonly | boolean | 
action\_result\.data\.\*\.comment\.user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.comment\.user\.name | string | 
action\_result\.data\.\*\.comment\.user\.nickname | string | 
action\_result\.data\.\*\.comment\.user\.organization\.id | string | 
action\_result\.data\.\*\.comment\.user\.organization\.name | string | 
action\_result\.data\.\*\.comment\.user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.comment\.user\.resource\_uri | string | 
action\_result\.data\.\*\.comments | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.cvss2\_score | string | 
action\_result\.data\.\*\.cvss3\_score | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.embedded\_content\_type | string | 
action\_result\.data\.\*\.embedded\_content\_url | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.incidents\.\*\.id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.id | numeric | 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.is\_system | boolean | 
action\_result\.data\.\*\.logo\_s3\_url | string | 
action\_result\.data\.\*\.mitre\_cve\_url | string |  `url` 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.organization\.id | string | 
action\_result\.data\.\*\.organization\.name | string | 
action\_result\.data\.\*\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.organization\_id | numeric | 
action\_result\.data\.\*\.owner\_user\.email | string |  `email` 
action\_result\.data\.\*\.owner\_user\.id | string | 
action\_result\.data\.\*\.owner\_user\.name | string | 
action\_result\.data\.\*\.owner\_user\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_user\_id | numeric | 
action\_result\.data\.\*\.parent | string | 
action\_result\.data\.\*\.publication\_status | string | 
action\_result\.data\.\*\.published\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.signatures\.\*\.id | numeric | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.starred\_by\_me | boolean | 
action\_result\.data\.\*\.starred\_total\_count | numeric | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.ttps\.\*\.id | numeric | 
action\_result\.data\.\*\.update\_id | string | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.votes\.me | string | 
action\_result\.data\.\*\.votes\.total | numeric | 
action\_result\.data\.\*\.vulnerability\.\*\.id | numeric | 
action\_result\.data\.\*\.watched\_by\_me | boolean | 
action\_result\.data\.\*\.watched\_total\_count | numeric | 
action\_result\.summary\.created\_on\_cloud | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update vulnerability'
Update the vulnerability in ThreatStream

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | ID of the vulnerability | string |  `threatstream vulnerability id` 
**fields** |  optional  | JSON formatted string of fields to include with the vulnerability | string | 
**local\_intelligence** |  optional  | Comma\-separated list of local intelligence IDs to associate with the vulnerability \- Note that this appends | string |  `threatstream intelligence id` 
**cloud\_intelligence** |  optional  | Comma\-separated list of remote intelligence IDs to associate with the vulnerability \- Note that this appends | string |  `threatstream intelligence id` 
**comment** |  optional  | Comment to give the vulnerability \(JSON format containing body, title, etc\.\) | string | 
**attachment** |  optional  | Vault id of an attachment to add on the vulnerability | string |  `vault id`  `sha1` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.attachment | string |  `vault id`  `sha1` 
action\_result\.parameter\.cloud\_intelligence | string |  `threatstream intelligence id` 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.id | string |  `threatstream vulnerability id` 
action\_result\.parameter\.local\_intelligence | string |  `threatstream intelligence id` 
action\_result\.data\.\*\.aliases | string | 
action\_result\.data\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.attachment | string | 
action\_result\.data\.\*\.attachments\.filename | string | 
action\_result\.data\.\*\.attachments\.id | numeric | 
action\_result\.data\.\*\.attachments\.r\_type | string | 
action\_result\.data\.\*\.attachments\.remote\_api | boolean | 
action\_result\.data\.\*\.attachments\.resource\_uri | string | 
action\_result\.data\.\*\.attachments\.s3\_url | string | 
action\_result\.data\.\*\.attachments\.title | string | 
action\_result\.data\.\*\.attachments\.url | string | 
action\_result\.data\.\*\.body\_content\_type | string | 
action\_result\.data\.\*\.campaigns\.\*\.id | numeric | 
action\_result\.data\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.circles\.\*\.id | string | 
action\_result\.data\.\*\.circles\.\*\.name | string | 
action\_result\.data\.\*\.circles\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.comment\.body | string | 
action\_result\.data\.\*\.comment\.created\_ts | string | 
action\_result\.data\.\*\.comment\.id | numeric | 
action\_result\.data\.\*\.comment\.modified\_ts | string | 
action\_result\.data\.\*\.comment\.resource\_uri | string | 
action\_result\.data\.\*\.comment\.title | string | 
action\_result\.data\.\*\.comment\.tlp | string | 
action\_result\.data\.\*\.comment\.user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.comment\.user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.comment\.user\.email | string |  `email` 
action\_result\.data\.\*\.comment\.user\.id | string | 
action\_result\.data\.\*\.comment\.user\.is\_active | boolean | 
action\_result\.data\.\*\.comment\.user\.is\_readonly | boolean | 
action\_result\.data\.\*\.comment\.user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.comment\.user\.name | string | 
action\_result\.data\.\*\.comment\.user\.nickname | string | 
action\_result\.data\.\*\.comment\.user\.organization\.id | string | 
action\_result\.data\.\*\.comment\.user\.organization\.name | string | 
action\_result\.data\.\*\.comment\.user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.comment\.user\.resource\_uri | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.cvss2\_score | string | 
action\_result\.data\.\*\.cvss3\_score | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.embedded\_content\_type | string | 
action\_result\.data\.\*\.embedded\_content\_url | string | 
action\_result\.data\.\*\.external\_references\.\*\.filename | string | 
action\_result\.data\.\*\.external\_references\.\*\.id | numeric | 
action\_result\.data\.\*\.external\_references\.\*\.r\_type | string | 
action\_result\.data\.\*\.external\_references\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.external\_references\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.external\_references\.\*\.s3\_url | string |  `url` 
action\_result\.data\.\*\.external\_references\.\*\.title | string | 
action\_result\.data\.\*\.external\_references\.\*\.url | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.incidents\.\*\.id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.asn | string | 
action\_result\.data\.\*\.intelligence\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.confidence | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.country | string | 
action\_result\.data\.\*\.intelligence\.\*\.created\_by | string | 
action\_result\.data\.\*\.intelligence\.\*\.created\_ts | string | 
action\_result\.data\.\*\.intelligence\.\*\.description | string | 
action\_result\.data\.\*\.intelligence\.\*\.expiration\_ts | string | 
action\_result\.data\.\*\.intelligence\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.import\_session\_id | string | 
action\_result\.data\.\*\.intelligence\.\*\.import\_source | string | 
action\_result\.data\.\*\.intelligence\.\*\.ip | string | 
action\_result\.data\.\*\.intelligence\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.itype | string | 
action\_result\.data\.\*\.intelligence\.\*\.latitude | string | 
action\_result\.data\.\*\.intelligence\.\*\.longitude | string | 
action\_result\.data\.\*\.intelligence\.\*\.meta\.detail2 | string | 
action\_result\.data\.\*\.intelligence\.\*\.meta\.severity | string | 
action\_result\.data\.\*\.intelligence\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.intelligence\.\*\.org | string | 
action\_result\.data\.\*\.intelligence\.\*\.owner\_organization\_id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.rdns | string | 
action\_result\.data\.\*\.intelligence\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.intelligence\.\*\.retina\_confidence | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.source | string | 
action\_result\.data\.\*\.intelligence\.\*\.source\_created | string | 
action\_result\.data\.\*\.intelligence\.\*\.source\_modified | string | 
action\_result\.data\.\*\.intelligence\.\*\.source\_reported\_confidence | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.status | string | 
action\_result\.data\.\*\.intelligence\.\*\.subtype | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.org\_id | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.tlp | string | 
action\_result\.data\.\*\.intelligence\.\*\.threat\_type | string | 
action\_result\.data\.\*\.intelligence\.\*\.threatscore | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.tlp | string | 
action\_result\.data\.\*\.intelligence\.\*\.trusted\_circle\_ids | string | 
action\_result\.data\.\*\.intelligence\.\*\.type | string | 
action\_result\.data\.\*\.intelligence\.\*\.update\_id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.uuid | string | 
action\_result\.data\.\*\.intelligence\.\*\.value | string | 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.is\_system | boolean | 
action\_result\.data\.\*\.logo\_s3\_url | string | 
action\_result\.data\.\*\.mitre\_cve\_url | string |  `url` 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.organization\.id | string | 
action\_result\.data\.\*\.organization\.name | string | 
action\_result\.data\.\*\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.organization\_id | numeric | 
action\_result\.data\.\*\.owner\_user\.email | string |  `email` 
action\_result\.data\.\*\.owner\_user\.id | string | 
action\_result\.data\.\*\.owner\_user\.name | string | 
action\_result\.data\.\*\.owner\_user\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_user\_id | numeric | 
action\_result\.data\.\*\.parent | string | 
action\_result\.data\.\*\.publication\_status | string | 
action\_result\.data\.\*\.published\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.signatures\.\*\.id | numeric | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.starred\_by\_me | boolean | 
action\_result\.data\.\*\.starred\_total\_count | numeric | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.ttps\.\*\.id | numeric | 
action\_result\.data\.\*\.update\_id | numeric | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.votes\.me | string | 
action\_result\.data\.\*\.votes\.total | numeric | 
action\_result\.data\.\*\.vulnerability\.\*\.id | numeric | 
action\_result\.data\.\*\.watched\_by\_me | boolean | 
action\_result\.data\.\*\.watched\_total\_count | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create actor'
Create an actor in ThreatStream

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | Name to give an actor | string | 
**fields** |  optional  | JSON formatted string of fields to include with an actor | string | 
**local\_intelligence** |  optional  | Comma\-separated list of local intelligence IDs to associate with an actor \- Note that this appends | string |  `threatstream intelligence id` 
**cloud\_intelligence** |  optional  | Comma\-separated list of remote intelligence IDs to associate with an actor \- Note that this appends | string |  `threatstream intelligence id` 
**comment** |  optional  | Comment to give an actor \(JSON format containing body, title, etc\.\) | string | 
**attachment** |  optional  | Vault id of an attachment to add on the actor | string |  `vault id`  `sha1` 
**is\_public** |  optional  | Classification designation | boolean | 
**create\_on\_cloud** |  optional  | Create on remote \(cloud\)? \(applicable only for hybrid on\-prem instances\) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.attachment | string |  `vault id`  `sha1` 
action\_result\.parameter\.cloud\_intelligence | string |  `threatstream intelligence id` 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.create\_on\_cloud | boolean | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.is\_public | boolean | 
action\_result\.parameter\.local\_intelligence | string |  `threatstream intelligence id` 
action\_result\.parameter\.name | string | 
action\_result\.data\.\*\.aliases\.\*\.id | numeric | 
action\_result\.data\.\*\.aliases\.\*\.name | string | 
action\_result\.data\.\*\.aliases\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.attachment | string | 
action\_result\.data\.\*\.attachments\.filename | string | 
action\_result\.data\.\*\.attachments\.id | numeric | 
action\_result\.data\.\*\.attachments\.r\_type | string | 
action\_result\.data\.\*\.attachments\.remote\_api | boolean | 
action\_result\.data\.\*\.attachments\.resource\_uri | string | 
action\_result\.data\.\*\.attachments\.s3\_url | string | 
action\_result\.data\.\*\.attachments\.title | string | 
action\_result\.data\.\*\.attachments\.url | string | 
action\_result\.data\.\*\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.body\_content\_type | string | 
action\_result\.data\.\*\.campaigns\.\*\.id | numeric |  `threatstream campaign id` 
action\_result\.data\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.circles\.\*\.id | string | 
action\_result\.data\.\*\.circles\.\*\.name | string | 
action\_result\.data\.\*\.circles\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.comment\.\!\@\#$%^ | string | 
action\_result\.data\.\*\.comment\.body | string | 
action\_result\.data\.\*\.comment\.created\_ts | string | 
action\_result\.data\.\*\.comment\.id | numeric | 
action\_result\.data\.\*\.comment\.invalid | string | 
action\_result\.data\.\*\.comment\.modified\_ts | string | 
action\_result\.data\.\*\.comment\.remote\_api | boolean | 
action\_result\.data\.\*\.comment\.resource\_uri | string | 
action\_result\.data\.\*\.comment\.title | string | 
action\_result\.data\.\*\.comment\.tlp | string | 
action\_result\.data\.\*\.comment\.user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.comment\.user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.comment\.user\.email | string |  `email` 
action\_result\.data\.\*\.comment\.user\.id | string | 
action\_result\.data\.\*\.comment\.user\.is\_active | boolean | 
action\_result\.data\.\*\.comment\.user\.is\_readonly | boolean | 
action\_result\.data\.\*\.comment\.user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.comment\.user\.name | string | 
action\_result\.data\.\*\.comment\.user\.nickname | string | 
action\_result\.data\.\*\.comment\.user\.organization\.id | string | 
action\_result\.data\.\*\.comment\.user\.organization\.name | string | 
action\_result\.data\.\*\.comment\.user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.comment\.user\.resource\_uri | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.embedded\_content\_type | string | 
action\_result\.data\.\*\.embedded\_content\_url | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.goals | string | 
action\_result\.data\.\*\.id | numeric |  `threatstream actor id` 
action\_result\.data\.\*\.incidents\.\*\.id | numeric |  `threatstream incident id` 
action\_result\.data\.\*\.intelligence\.\*\.id | numeric |  `threatstream intelligence id` 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.is\_team | boolean | 
action\_result\.data\.\*\.logo\_s3\_url | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.organization\.id | string | 
action\_result\.data\.\*\.organization\.name | string | 
action\_result\.data\.\*\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.organization\_id | numeric | 
action\_result\.data\.\*\.owner\_user\.email | string |  `email` 
action\_result\.data\.\*\.owner\_user\.id | string | 
action\_result\.data\.\*\.owner\_user\.name | string | 
action\_result\.data\.\*\.owner\_user\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_user\_id | numeric | 
action\_result\.data\.\*\.parent | string | 
action\_result\.data\.\*\.personal\_motivations | string | 
action\_result\.data\.\*\.primary\_motivation | string | 
action\_result\.data\.\*\.publication\_status | string | 
action\_result\.data\.\*\.published\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_level | string | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.roles | string | 
action\_result\.data\.\*\.secondary\_motivations | string | 
action\_result\.data\.\*\.signatures\.\*\.id | numeric |  `threatstream signature id` 
action\_result\.data\.\*\.soph\_desc | string | 
action\_result\.data\.\*\.soph\_type | string | 
action\_result\.data\.\*\.soph\_type | string | 
action\_result\.data\.\*\.soph\_type\.display\_name | string | 
action\_result\.data\.\*\.soph\_type\.id | numeric | 
action\_result\.data\.\*\.soph\_type\.resource\_uri | string | 
action\_result\.data\.\*\.soph\_type\.value | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.starred\_by\_me | boolean | 
action\_result\.data\.\*\.starred\_total\_count | numeric | 
action\_result\.data\.\*\.start\_date | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.id | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.name | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.tags\_v2\.\*\.tlp | string | 
action\_result\.data\.\*\.threat\_actor\_types | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.ttps\.\*\.id | numeric |  `threatstream ttp id` 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.victims\.\*\.id | numeric | 
action\_result\.data\.\*\.victims\.\*\.name | string | 
action\_result\.data\.\*\.victims\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.victims\.\*\.value | numeric | 
action\_result\.data\.\*\.votes\.me | string | 
action\_result\.data\.\*\.votes\.total | numeric | 
action\_result\.data\.\*\.vulnerability\.\*\.id | numeric |  `threatstream vulnerability id` 
action\_result\.data\.\*\.watched\_by\_me | boolean | 
action\_result\.data\.\*\.watched\_total\_count | numeric | 
action\_result\.summary\.created\_on\_cloud | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update actor'
Update an actor in ThreatStream

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | ID of an actor | string |  `threatstream actor id` 
**fields** |  optional  | JSON formatted string of fields to include with an actor | string | 
**local\_intelligence** |  optional  | Comma\-separated list of local intelligence IDs to associate with an actor \- Note that this appends | string |  `threatstream intelligence id` 
**cloud\_intelligence** |  optional  | Comma\-separated list of remote intelligence IDs to associate with an actor \- Note that this appends | string |  `threatstream intelligence id` 
**comment** |  optional  | Comment to give an actor \(JSON format containing body, title, etc\.\) | string | 
**attachment** |  optional  | Vault id of an attachment to add on the actor | string |  `vault id`  `sha1` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.attachment | string |  `vault id`  `sha1` 
action\_result\.parameter\.cloud\_intelligence | string |  `threatstream intelligence id` 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.id | string |  `threatstream actor id` 
action\_result\.parameter\.local\_intelligence | string |  `threatstream intelligence id` 
action\_result\.data\.\*\.aliases\.\*\.id | numeric | 
action\_result\.data\.\*\.aliases\.\*\.name | string | 
action\_result\.data\.\*\.aliases\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.assignee\_user | string | 
action\_result\.data\.\*\.attachment | string | 
action\_result\.data\.\*\.attachments\.filename | string | 
action\_result\.data\.\*\.attachments\.id | numeric | 
action\_result\.data\.\*\.attachments\.r\_type | string | 
action\_result\.data\.\*\.attachments\.remote\_api | boolean | 
action\_result\.data\.\*\.attachments\.resource\_uri | string | 
action\_result\.data\.\*\.attachments\.s3\_url | string | 
action\_result\.data\.\*\.attachments\.title | string | 
action\_result\.data\.\*\.attachments\.url | string | 
action\_result\.data\.\*\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.body\_content\_type | string | 
action\_result\.data\.\*\.campaigns\.\*\.id | numeric |  `threatstream campaign id` 
action\_result\.data\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.circles\.\*\.id | string | 
action\_result\.data\.\*\.circles\.\*\.name | string | 
action\_result\.data\.\*\.circles\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.comment\.body | string | 
action\_result\.data\.\*\.comment\.created\_ts | string | 
action\_result\.data\.\*\.comment\.id | numeric | 
action\_result\.data\.\*\.comment\.modified\_ts | string | 
action\_result\.data\.\*\.comment\.resource\_uri | string | 
action\_result\.data\.\*\.comment\.title | string | 
action\_result\.data\.\*\.comment\.tlp | string | 
action\_result\.data\.\*\.comment\.user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.comment\.user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.comment\.user\.email | string |  `email` 
action\_result\.data\.\*\.comment\.user\.id | string | 
action\_result\.data\.\*\.comment\.user\.is\_active | boolean | 
action\_result\.data\.\*\.comment\.user\.is\_readonly | boolean | 
action\_result\.data\.\*\.comment\.user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.comment\.user\.name | string | 
action\_result\.data\.\*\.comment\.user\.nickname | string | 
action\_result\.data\.\*\.comment\.user\.organization\.id | string | 
action\_result\.data\.\*\.comment\.user\.organization\.name | string | 
action\_result\.data\.\*\.comment\.user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.comment\.user\.resource\_uri | string | 
action\_result\.data\.\*\.comments\.\!\@\#$%^&\* | string | 
action\_result\.data\.\*\.comments\.body | string | 
action\_result\.data\.\*\.comments\.created\_ts | string | 
action\_result\.data\.\*\.comments\.id | numeric | 
action\_result\.data\.\*\.comments\.incorrect value | string | 
action\_result\.data\.\*\.comments\.modified\_ts | string | 
action\_result\.data\.\*\.comments\.remote\_api | boolean | 
action\_result\.data\.\*\.comments\.resource\_uri | string | 
action\_result\.data\.\*\.comments\.title | string | 
action\_result\.data\.\*\.comments\.tlp | string | 
action\_result\.data\.\*\.comments\.user\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.comments\.user\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.comments\.user\.email | string | 
action\_result\.data\.\*\.comments\.user\.id | string | 
action\_result\.data\.\*\.comments\.user\.is\_active | boolean | 
action\_result\.data\.\*\.comments\.user\.is\_readonly | boolean | 
action\_result\.data\.\*\.comments\.user\.must\_change\_password | boolean | 
action\_result\.data\.\*\.comments\.user\.name | string | 
action\_result\.data\.\*\.comments\.user\.nickname | string | 
action\_result\.data\.\*\.comments\.user\.organization\.id | string | 
action\_result\.data\.\*\.comments\.user\.organization\.name | string | 
action\_result\.data\.\*\.comments\.user\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.comments\.user\.resource\_uri | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.embedded\_content\_type | string | 
action\_result\.data\.\*\.embedded\_content\_url | string | 
action\_result\.data\.\*\.external\_references\.\*\.filename | string | 
action\_result\.data\.\*\.external\_references\.\*\.id | numeric | 
action\_result\.data\.\*\.external\_references\.\*\.r\_type | string | 
action\_result\.data\.\*\.external\_references\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.external\_references\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.external\_references\.\*\.s3\_url | string |  `url` 
action\_result\.data\.\*\.external\_references\.\*\.title | string | 
action\_result\.data\.\*\.external\_references\.\*\.url | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.goals | string | 
action\_result\.data\.\*\.id | numeric |  `threatstream actor id` 
action\_result\.data\.\*\.incidents\.\*\.id | numeric |  `threatstream incident id` 
action\_result\.data\.\*\.intelligence\.\*\.asn | string | 
action\_result\.data\.\*\.intelligence\.\*\.can\_add\_public\_tags | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.confidence | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.country | string | 
action\_result\.data\.\*\.intelligence\.\*\.created\_by | string | 
action\_result\.data\.\*\.intelligence\.\*\.created\_ts | string | 
action\_result\.data\.\*\.intelligence\.\*\.description | string | 
action\_result\.data\.\*\.intelligence\.\*\.expiration\_ts | string | 
action\_result\.data\.\*\.intelligence\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.import\_session\_id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.import\_source | string | 
action\_result\.data\.\*\.intelligence\.\*\.ip | string | 
action\_result\.data\.\*\.intelligence\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.is\_editable | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.itype | string | 
action\_result\.data\.\*\.intelligence\.\*\.latitude | string | 
action\_result\.data\.\*\.intelligence\.\*\.longitude | string | 
action\_result\.data\.\*\.intelligence\.\*\.meta\.detail2 | string | 
action\_result\.data\.\*\.intelligence\.\*\.meta\.severity | string | 
action\_result\.data\.\*\.intelligence\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.intelligence\.\*\.org | string | 
action\_result\.data\.\*\.intelligence\.\*\.owner\_organization\_id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.rdns | string | 
action\_result\.data\.\*\.intelligence\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.intelligence\.\*\.retina\_confidence | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.source | string | 
action\_result\.data\.\*\.intelligence\.\*\.source\_created | string | 
action\_result\.data\.\*\.intelligence\.\*\.source\_modified | string | 
action\_result\.data\.\*\.intelligence\.\*\.source\_reported\_confidence | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.status | string | 
action\_result\.data\.\*\.intelligence\.\*\.subtype | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.category | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.org\_id | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.source\_user | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.source\_user\_id | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.tagger | string | 
action\_result\.data\.\*\.intelligence\.\*\.tags\.\*\.tlp | string | 
action\_result\.data\.\*\.intelligence\.\*\.threat\_type | string | 
action\_result\.data\.\*\.intelligence\.\*\.threatscore | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.tlp | string | 
action\_result\.data\.\*\.intelligence\.\*\.trusted\_circle\_ids | string | 
action\_result\.data\.\*\.intelligence\.\*\.type | string | 
action\_result\.data\.\*\.intelligence\.\*\.update\_id | numeric | 
action\_result\.data\.\*\.intelligence\.\*\.uuid | string | 
action\_result\.data\.\*\.intelligence\.\*\.value | string | 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_cloneable | string | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.is\_team | boolean | 
action\_result\.data\.\*\.logo\_s3\_url | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.organization\.id | string | 
action\_result\.data\.\*\.organization\.name | string | 
action\_result\.data\.\*\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.organization\_id | numeric | 
action\_result\.data\.\*\.owner\_user\.email | string |  `email` 
action\_result\.data\.\*\.owner\_user\.id | string | 
action\_result\.data\.\*\.owner\_user\.name | string | 
action\_result\.data\.\*\.owner\_user\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_user\_id | numeric | 
action\_result\.data\.\*\.parent | string | 
action\_result\.data\.\*\.personal\_motivations | string | 
action\_result\.data\.\*\.primary\_motivation | string | 
action\_result\.data\.\*\.publication\_status | string | 
action\_result\.data\.\*\.published\_ts | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_level | string | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.roles | string | 
action\_result\.data\.\*\.secondary\_motivations | string | 
action\_result\.data\.\*\.signatures\.\*\.id | numeric |  `threatstream signature id` 
action\_result\.data\.\*\.soph\_desc | string | 
action\_result\.data\.\*\.soph\_type | string | 
action\_result\.data\.\*\.soph\_type | string | 
action\_result\.data\.\*\.soph\_type\.display\_name | string | 
action\_result\.data\.\*\.soph\_type\.id | numeric | 
action\_result\.data\.\*\.soph\_type\.resource\_uri | string | 
action\_result\.data\.\*\.soph\_type\.value | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.starred\_by\_me | boolean | 
action\_result\.data\.\*\.starred\_total\_count | numeric | 
action\_result\.data\.\*\.start\_date | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.id | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.name | string | 
action\_result\.data\.\*\.tags\_v2\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.tags\_v2\.\*\.tlp | string | 
action\_result\.data\.\*\.threat\_actor\_types | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.ttps\.\*\.id | numeric |  `threatstream ttp id` 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.victims\.\*\.id | numeric | 
action\_result\.data\.\*\.victims\.\*\.name | string | 
action\_result\.data\.\*\.victims\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.victims\.\*\.value | numeric | 
action\_result\.data\.\*\.votes\.me | string | 
action\_result\.data\.\*\.votes\.total | numeric | 
action\_result\.data\.\*\.vulnerability\.\*\.id | numeric |  `threatstream vulnerability id` 
action\_result\.data\.\*\.watched\_by\_me | boolean | 
action\_result\.data\.\*\.watched\_total\_count | numeric | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete threat bulletin'
Delete threat bulletin in ThreatStream by ID

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**threat\_bulletin\_id** |  required  | ID of the threat bulletin to delete | string |  `threatstream threatbulletin id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.threat\_bulletin\_id | string |  `threatstream threatbulletin id` 
action\_result\.data\.\* | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete vulnerability'
Delete vulnerability in ThreatStream by ID

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vulnerability\_id** |  required  | ID of the vulnerability to delete | string |  `threatstream vulnerability id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.vulnerability\_id | string |  `threatstream vulnerability id` 
action\_result\.data\.\* | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete actor'
Delete actor in ThreatStream by ID number

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**actor\_id** |  required  | ID number of actor to delete | string |  `threatstream actor id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.actor\_id | string |  `threatstream actor id` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update observable'
Update an observable in ThreatStream

Type: **generic**  
Read only: **False**

If any of the indicator\_type, confidence, tlp, severity, status, or expiration\_date parameter is added and is also mentioned in the fields parameter, the value given in the individual parameters is considered\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | ID of the observable | string |  `threatstream intelligence id` 
**indicator\_type** |  optional  | Indicator type to give the observable | string | 
**confidence** |  optional  | Confidence to give the observable | numeric | 
**tlp** |  optional  | Tlp to give the observable | string | 
**severity** |  optional  | Severity to give the observable | string | 
**status** |  optional  | Status to give the observable \(For example, active, inactive, falsepos\) | string | 
**expiration\_date** |  optional  | Expiration timestamp to give the observable \(in UTC format\) | string | 
**fields** |  optional  | JSON formatted string of fields to include with the observable | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.confidence | numeric | 
action\_result\.parameter\.expiration\_date | string | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.id | string |  `threatstream intelligence id` 
action\_result\.parameter\.indicator\_type | string | 
action\_result\.parameter\.severity | string | 
action\_result\.parameter\.status | string | 
action\_result\.parameter\.tlp | string | 
action\_result\.data\.\*\.asn | string | 
action\_result\.data\.\*\.confidence | numeric | 
action\_result\.data\.\*\.country | string | 
action\_result\.data\.\*\.created\_by | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.expiration\_ts | string | 
action\_result\.data\.\*\.feed\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `threatstream intelligence id` 
action\_result\.data\.\*\.import\_session\_id | string | 
action\_result\.data\.\*\.import\_source | string | 
action\_result\.data\.\*\.ip | string | 
action\_result\.data\.\*\.is\_anonymous | boolean | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.itype | string | 
action\_result\.data\.\*\.latitude | string | 
action\_result\.data\.\*\.longitude | string | 
action\_result\.data\.\*\.meta\.detail2 | string | 
action\_result\.data\.\*\.meta\.next | string | 
action\_result\.data\.\*\.meta\.previous | string | 
action\_result\.data\.\*\.meta\.severity | string | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.org | string | 
action\_result\.data\.\*\.owner\_organization\_id | numeric | 
action\_result\.data\.\*\.rdns | string | 
action\_result\.data\.\*\.remote\_api | boolean | 
action\_result\.data\.\*\.resource\_uri | string | 
action\_result\.data\.\*\.retina\_confidence | numeric | 
action\_result\.data\.\*\.source | string | 
action\_result\.data\.\*\.source\_created | string | 
action\_result\.data\.\*\.source\_modified | string | 
action\_result\.data\.\*\.source\_reported\_confidence | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.subtype | string | 
action\_result\.data\.\*\.tags\.\*\.id | string | 
action\_result\.data\.\*\.tags\.\*\.name | string | 
action\_result\.data\.\*\.tags\.\*\.org\_id | numeric | 
action\_result\.data\.\*\.tags\.\*\.remote\_api | numeric | 
action\_result\.data\.\*\.tags\.\*\.source\_user | string | 
action\_result\.data\.\*\.tags\.\*\.source\_user\_id | string | 
action\_result\.data\.\*\.tags\.\*\.tlp | string | 
action\_result\.data\.\*\.threat\_type | string | 
action\_result\.data\.\*\.threatscore | numeric | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.update\_id | numeric | 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.value | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create investigation'
Create an investigation in ThreatStream

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | Name to give the investigation | string | 
**priority** |  required  | Priority assigned to the investigation | string | 
**fields** |  optional  | JSON formatted string of fields to include with the investigation | string | 
**create\_on\_cloud** |  optional  | Create on remote \(cloud\)? \(applicable only for hybrid on\-prem instances\) | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.create\_on\_cloud | boolean | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.priority | string | 
action\_result\.data\.\*\.assignee | string | 
action\_result\.data\.\*\.attachments | string | 
action\_result\.data\.\*\.candidate\_session | string | 
action\_result\.data\.\*\.circles | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.elements | numeric | 
action\_result\.data\.\*\.graph\_content | string | 
action\_result\.data\.\*\.id | numeric |  `threatstream investigation id` 
action\_result\.data\.\*\.import\_sessions | string | 
action\_result\.data\.\*\.investigation\_attachments | string | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.owner\_org\.id | string | 
action\_result\.data\.\*\.owner\_org\.name | string | 
action\_result\.data\.\*\.owner\_org\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_org\_id | string |  `id` 
action\_result\.data\.\*\.priority | string | 
action\_result\.data\.\*\.reporter\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.reporter\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.reporter\.email | string |  `email` 
action\_result\.data\.\*\.reporter\.id | string |  `id` 
action\_result\.data\.\*\.reporter\.is\_active | boolean | 
action\_result\.data\.\*\.reporter\.is\_readonly | boolean | 
action\_result\.data\.\*\.reporter\.must\_change\_password | boolean | 
action\_result\.data\.\*\.reporter\.name | string | 
action\_result\.data\.\*\.reporter\.nickname | string | 
action\_result\.data\.\*\.reporter\.organization\.id | string |  `id` 
action\_result\.data\.\*\.reporter\.organization\.name | string | 
action\_result\.data\.\*\.reporter\.organization\.resource\_uri | string |  `url` 
action\_result\.data\.\*\.reporter\.resource\_uri | string |  `url` 
action\_result\.data\.\*\.reporter\_id | numeric |  `id` 
action\_result\.data\.\*\.resource\_uri | string |  `url` 
action\_result\.data\.\*\.source\_type | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tips | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.workgroups | string | 
action\_result\.data\.tasks | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list investigations'
List investigations present in ThreatStream

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**limit** |  optional  | Total number of investigations to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.assignee | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.elements | numeric | 
action\_result\.data\.\*\.id | numeric |  `investigation id` 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.owner\_org\.id | string |  `id` 
action\_result\.data\.\*\.owner\_org\.name | string | 
action\_result\.data\.\*\.owner\_org\.resource\_uri | string | 
action\_result\.data\.\*\.owner\_org\_id | string | 
action\_result\.data\.\*\.priority | string | 
action\_result\.data\.\*\.reporter\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.reporter\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.reporter\.email | string |  `email` 
action\_result\.data\.\*\.reporter\.id | string |  `id` 
action\_result\.data\.\*\.reporter\.is\_active | boolean | 
action\_result\.data\.\*\.reporter\.is\_readonly | boolean | 
action\_result\.data\.\*\.reporter\.must\_change\_password | boolean | 
action\_result\.data\.\*\.reporter\.name | string | 
action\_result\.data\.\*\.reporter\.nickname | string | 
action\_result\.data\.\*\.reporter\.organization\.id | string |  `id` 
action\_result\.data\.\*\.reporter\.organization\.name | string | 
action\_result\.data\.\*\.reporter\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.reporter\.resource\_uri | string |  `url` 
action\_result\.data\.\*\.reporter\_id | numeric |  `id` 
action\_result\.data\.\*\.resource\_uri | string |  `url` 
action\_result\.data\.\*\.source\_type | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.workgroups | string | 
action\_result\.summary\.investigations\_returned | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get investigation'
Retrieve investigation present in Threatstream by ID

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**investigation\_id** |  required  | ID of the investigation to retrieve | numeric |  `threatstream investigation id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.investigation\_id | numeric |  `threatstream investigation id` 
action\_result\.data\.\*\.assignee | string | 
action\_result\.data\.\*\.attachments | string | 
action\_result\.data\.\*\.candidate\_session | string | 
action\_result\.data\.\*\.circles | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.elements | numeric | 
action\_result\.data\.\*\.graph\_content | string | 
action\_result\.data\.\*\.id | numeric |  `id` 
action\_result\.data\.\*\.import\_sessions | string | 
action\_result\.data\.\*\.investigation\_attachments | string | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.owner\_org\.id | string |  `id` 
action\_result\.data\.\*\.owner\_org\.name | string | 
action\_result\.data\.\*\.owner\_org\.resource\_uri | string |  `url` 
action\_result\.data\.\*\.owner\_org\_id | string |  `id` 
action\_result\.data\.\*\.priority | string | 
action\_result\.data\.\*\.reporter\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.reporter\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.reporter\.email | string |  `email` 
action\_result\.data\.\*\.reporter\.id | string |  `id` 
action\_result\.data\.\*\.reporter\.is\_active | boolean | 
action\_result\.data\.\*\.reporter\.is\_readonly | boolean | 
action\_result\.data\.\*\.reporter\.must\_change\_password | boolean | 
action\_result\.data\.\*\.reporter\.name | string | 
action\_result\.data\.\*\.reporter\.nickname | string | 
action\_result\.data\.\*\.reporter\.organization\.id | string |  `id` 
action\_result\.data\.\*\.reporter\.organization\.name | string | 
action\_result\.data\.\*\.reporter\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.reporter\.resource\_uri | string | 
action\_result\.data\.\*\.reporter\_id | numeric |  `id` 
action\_result\.data\.\*\.resource\_uri | string |  `url` 
action\_result\.data\.\*\.source\_type | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tips | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.workgroups | string | 
action\_result\.data\.tasks | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update investigation'
Update an investigation in ThreatStream

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**investigation\_id** |  required  | ID of the investigation to update | numeric |  `threatstream investigation id` 
**fields** |  required  | JSON formatted string of fields to include with the investigation | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.fields | string | 
action\_result\.parameter\.investigation\_id | numeric |  `threatstream investigation id` 
action\_result\.data\.\*\.assignee | string | 
action\_result\.data\.\*\.attachments | string | 
action\_result\.data\.\*\.candidate\_session | string | 
action\_result\.data\.\*\.circles | string | 
action\_result\.data\.\*\.created\_ts | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.elements | numeric | 
action\_result\.data\.\*\.graph\_content | string | 
action\_result\.data\.\*\.id | numeric |  `id` 
action\_result\.data\.\*\.import\_sessions | string | 
action\_result\.data\.\*\.investigation\_attachments | string | 
action\_result\.data\.\*\.is\_public | boolean | 
action\_result\.data\.\*\.modified\_ts | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.owner\_org\.id | string |  `id` 
action\_result\.data\.\*\.owner\_org\.name | string | 
action\_result\.data\.\*\.owner\_org\.resource\_uri | string |  `url` 
action\_result\.data\.\*\.owner\_org\_id | string |  `id` 
action\_result\.data\.\*\.priority | string | 
action\_result\.data\.\*\.reporter\.avatar\_s3\_url | string | 
action\_result\.data\.\*\.reporter\.can\_share\_intelligence | boolean | 
action\_result\.data\.\*\.reporter\.email | string |  `email` 
action\_result\.data\.\*\.reporter\.id | string |  `id` 
action\_result\.data\.\*\.reporter\.is\_active | boolean | 
action\_result\.data\.\*\.reporter\.is\_readonly | boolean | 
action\_result\.data\.\*\.reporter\.must\_change\_password | boolean | 
action\_result\.data\.\*\.reporter\.name | string | 
action\_result\.data\.\*\.reporter\.nickname | string | 
action\_result\.data\.\*\.reporter\.organization\.id | string |  `id` 
action\_result\.data\.\*\.reporter\.organization\.name | string | 
action\_result\.data\.\*\.reporter\.organization\.resource\_uri | string | 
action\_result\.data\.\*\.reporter\.resource\_uri | string |  `url` 
action\_result\.data\.\*\.reporter\_id | numeric |  `id` 
action\_result\.data\.\*\.resource\_uri | string |  `url` 
action\_result\.data\.\*\.source\_type | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.tips | string | 
action\_result\.data\.\*\.tlp | string | 
action\_result\.data\.\*\.workgroups | string | 
action\_result\.data\.tasks | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete investigation'
Delete investigation in ThreatStream by ID number

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**investigation\_id** |  required  | ID number of investigation to delete | numeric |  `threatstream investigation id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.investigation\_id | numeric |  `threatstream investigation id` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 