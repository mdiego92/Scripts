#!/usr/bin/env python3

import json
import requests
import urllib3
import argparse
from datetime import datetime
from base64 import b64encode

# Configuration
DEFAULT_PROTOCOL = 'https'
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = '55000'
DEFAULT_USER = 'wazuh-wui'
DEFAULT_PASSWORD = 'wazuh-wui'
DEFAULT_ELASTICSEARCH_HOST = 'localhost'
DEFAULT_ELASTICSEARCH_PORT = '9200'
DEFAULT_ELASTICSEARCH_INDEX = 'wazuh-alerts-4.x'

# Counter for fired times
FIRED_TIMES = 1

# Disable insecure HTTPS warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Functions
def get_response(url, headers, verify=False):
    """Get API result"""
    request_result = requests.get(url, headers=headers, verify=verify)

    if request_result.status_code == 200:
        return json.loads(request_result.content.decode())
    else:
        raise Exception(f"Error obtaining response: {request_result.json()}")

def log(message, is_verbose=False):
    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    full_message = f"[{timestamp}] {message}"
    if is_verbose:
        print(full_message)
    return full_message

def log_event(event):
    """Log events to a file"""
    with open('events.log', 'a') as event_file:
        event_file.write(json.dumps(event, indent=2) + '\n')

def process_agent(agent_id, base_url, headers, elasticsearch_host, elasticsearch_port, elasticsearch_index, elasticsearch_user, elasticsearch_password, is_verbose):
    global FIRED_TIMES  # Use the global variable
    
    firstquery = f'/agents?agents_list={agent_id}'
    secondquery = f'/sca/{agent_id}'
    thirdquery_template = '/sca/{agent_id}/checks/{policy_id}'

    log(f"Processing agent: {agent_id}", is_verbose)

    first_response = get_response(base_url + firstquery, headers)
    wazuh_agent_name = first_response['data']['affected_items'][0]['name']
    wazuh_agent_ip = first_response['data']['affected_items'][0]['ip']
    wazuh_manager_name = first_response['data']['affected_items'][0]['manager']

    second_response = get_response(base_url + secondquery, headers)
    policy_id = second_response['data']['affected_items'][0]['policy_id']
    sca_policy = second_response['data']['affected_items'][0]['name']

    thirdquery = thirdquery_template.format(agent_id=agent_id, policy_id=policy_id)
    third_response = get_response(base_url + thirdquery, headers)

    events_list = []
    
    # Initialize compliance lists with default values
    nist_800_53_list = ["CM.1"]
    pci_dss_list = ["2.2"]
    tsc_list = ["CC7.1", "CC7.2"]

    for item in third_response['data']['affected_items']:
        sca_result = item.get('result', '')
        rule_id = "19009"
        rule_level = 3

        if sca_result == 'passed':
            rule_id = "19008"
        elif sca_result == 'failed':
            rule_id = "19007"
            rule_level = 7

        remediation = item.get('remediation', '')
        file = item.get('file', '')
        description = item.get('description', '')
        sca_id = str(item.get('id', 0))
        title = item.get('title', '')
        rationale = item.get('rationale', '')

        compliance_data = item.get('compliance', [])
        formatted_compliance = {}

        for comp_item in compliance_data:
            key = comp_item.get('key', '')
            value = comp_item.get('value', '')
            if key:
                formatted_compliance[key] = value

        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        rule_description = f"{sca_policy}: {title}"

        pci_dss_values = formatted_compliance.get('pci_dss', '').split(',')
        pci_dss_list = sorted(list(set([value.strip() for value in pci_dss_values if value.strip()])) + ["2.2"])

        hipaa_list = sorted(list(set([value.strip() for value in formatted_compliance.get('hipaa', '').split(',')])))

        tsc_values = formatted_compliance.get('tsc', '').split(',')
        tsc_list = sorted(list(set([value.strip() for value in tsc_values if value.strip()])) + ["CC7.1", "CC7.2", "CC6.1"])

        cis_csc_list = sorted(list(set([value.strip() for value in formatted_compliance.get('cis_csc', '').split(',')])))

        gdpr_IV_list = sorted(list(set([value.strip() for value in formatted_compliance.get('gdpr_IV', '').split(',')])))

        cis_list = sorted(list(set([value.strip() for value in formatted_compliance.get('cis', '').split(',')])))

        nist_800_53_values = formatted_compliance.get('nist_800_53', '').split(',')
        nist_800_53_list = sorted(list(set([value.strip() for value in nist_800_53_values if value.strip()])) + ["CM.1"])

        gpg_13_list = sorted(list(set([value.strip() for value in formatted_compliance.get('gpg_13', '').split(',')])))

        data_rule_firedtimes = FIRED_TIMES
        FIRED_TIMES += 1

        payload = {
            "input": {
                "type": "log"
            },
            "agent": {
                "ip": wazuh_agent_ip,
                "name": wazuh_agent_name,
                "id": agent_id
            },
            "manager": {
                "name": wazuh_manager_name
            },
            "data": {
                "sca": {
                    "scan_id": "0",
                    "check": {
                        "result": sca_result,
                        "remediation": remediation,
                        "file": [file],
                        "compliance": formatted_compliance,
                        "description": description,
                        "id": sca_id,
                        "title": title,
                        "rationale": rationale
                    },
                    "type": "check",
                    "policy": sca_policy
                }
            },
            "rule": {
                "mail": False,
                "level": rule_level,
                "pci_dss": pci_dss_list,
                "tsc": tsc_list,
                "cis_csc": cis_csc_list,
                "hipaa": hipaa_list,
                "gdpr_IV": gdpr_IV_list,
                "description": rule_description,
                "groups": [
                    "sca"
                ],
                "id": rule_id,
                "cis": cis_list,
                "nist_800_53": nist_800_53_list,
                "gdpr": ["IV_35.7.d"],
                "gpg_13": gpg_13_list,
                "firedtimes": data_rule_firedtimes
            },
            "location": "sca",
            "decoder": {
                "name": "sca"
            },
            "id": "0",
            "timestamp": timestamp
        }

        log_event(payload)

        post_headers = {
            "Content-Type": "application/json",
            "Authorization": headers['Authorization']
        }

        post_url = f"https://{elasticsearch_host}:{elasticsearch_port}/{elasticsearch_index}-{datetime.utcnow().strftime('%Y.%m.%d')}/_doc/"

        response = requests.post(
            post_url,
            headers=post_headers,
            json=payload,
            verify=False,
            auth=(elasticsearch_user, elasticsearch_password)
        )

        if response.status_code != 201:
            try:
                log(f"Error posting document: {response.json()}", is_verbose)
            except json.decoder.JSONDecodeError:
                log(f"Error posting document: {response.text}", is_verbose)

    log(f"Processing completed for agent: {agent_id}", is_verbose)

def main():
    parser = argparse.ArgumentParser(description='Wazuh API Query Script')
    parser.add_argument('-a', '--agent', type=str, help='Agent ID')
    parser.add_argument('-all', action='store_true', help='Process all agents')
    parser.add_argument('-wh', '--wazuh-host', type=str, default=DEFAULT_HOST, help='Wazuh host')
    parser.add_argument('-wp', '--wazuh-port', type=str, default=DEFAULT_PORT, help='Wazuh port')
    parser.add_argument('-wu', '--wazuh-user', type=str, default=DEFAULT_USER, help='Wazuh user')
    parser.add_argument('-wpass', '--wazuh-password', type=str, default=DEFAULT_PASSWORD, help='Wazuh password')
    parser.add_argument('-eh', '--elasticsearch-host', type=str, default=DEFAULT_ELASTICSEARCH_HOST, help='Elasticsearch host')
    parser.add_argument('-ep', '--elasticsearch-port', type=str, default=DEFAULT_ELASTICSEARCH_PORT, help='Elasticsearch port')
    parser.add_argument('-eu', '--elasticsearch-user', type=str, default=DEFAULT_USER, help='Elasticsearch user')
    parser.add_argument('-epass', '--elasticsearch-password', type=str, default=DEFAULT_PASSWORD, help='Elasticsearch password')
    parser.add_argument('-i', '--elasticsearch-index', type=str, default=DEFAULT_ELASTICSEARCH_INDEX, help='Elasticsearch index')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    wazuh_host = args.wazuh_host
    wazuh_port = args.wazuh_port
    wazuh_user = args.wazuh_user
    wazuh_password = args.wazuh_password
    elasticsearch_host = args.elasticsearch_host
    elasticsearch_port = args.elasticsearch_port
    elasticsearch_index = args.elasticsearch_index
    elasticsearch_user = args.elasticsearch_user
    elasticsearch_password = args.elasticsearch_password
    is_verbose = args.verbose

    if args.all:
        fourthquery = '/agents'
        base_url = f"{DEFAULT_PROTOCOL}://{wazuh_host}:{wazuh_port}"
        login_url = f"{base_url}/security/user/authenticate"
        basic_auth = f"{wazuh_user}:{wazuh_password}".encode()
        headers = {'Authorization': f'Basic {b64encode(basic_auth).decode()}'}
        headers['Authorization'] = f'Bearer {get_response(login_url, headers)["data"]["token"]}'

        agents_response = get_response(base_url + fourthquery, headers)
        agent_ids = [item['id'] for item in agents_response['data']['affected_items']]
        
        for agent_id in agent_ids:
            process_agent(agent_id, base_url, headers, elasticsearch_host, elasticsearch_port, elasticsearch_index, elasticsearch_user, elasticsearch_password, is_verbose)
    elif args.agent:
        agent_id = args.agent
        base_url = f"{DEFAULT_PROTOCOL}://{wazuh_host}:{wazuh_port}"
        login_url = f"{base_url}/security/user/authenticate"
        basic_auth = f"{wazuh_user}:{wazuh_password}".encode()
        headers = {'Authorization': f'Basic {b64encode(basic_auth).decode()}'}
        headers['Authorization'] = f'Bearer {get_response(login_url, headers)["data"]["token"]}'
        
        process_agent(agent_id, base_url, headers, elasticsearch_host, elasticsearch_port, elasticsearch_index, elasticsearch_user, elasticsearch_password, is_verbose)

if __name__ == '__main__':
    main()
