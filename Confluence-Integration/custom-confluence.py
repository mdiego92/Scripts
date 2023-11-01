#!/usr/bin/env python

import sys
import json
import requests
from requests.auth import HTTPBasicAuth

# Read configuration parameters
alert_file = open(sys.argv[1])
user = sys.argv[2].split(':')[0]
api_key = sys.argv[2].split(':')[1]
hook_url = sys.argv[3]

# Read the alert JSON data
alert_json = json.loads(alert_file.read())
alert_file.close()

# Extract alert information
alert_level = alert_json['rule']['level']
rule_id = alert_json['rule']['id']
description = alert_json['rule']['description']
agent_id = alert_json['agent']['id']
agent_name = alert_json['agent']['name']
path = alert_json['location']
timestamp = alert_json['timestamp'][:16]

# Set the Confluence space and page title
confluence_space = 'KB'
page_title = f'{timestamp} - Rule ID {rule_id} - {description}'

# Create or update Confluence page
confluence_url = f"{hook_url}/rest/api/content"
headers = {'content-type': 'application/json'}

# Initialize variables for update_response and create_response with None
update_response = None
create_response = None

# Check if the page already exists
page_exists = False
page_id = None
search_params = {
    "cql": f"title=\"{page_title}\" and space=\"{confluence_space}\""
}

search_response = requests.get(f"{confluence_url}/search", params=search_params, auth=(user, api_key))
search_json = search_response.json()
if 'results' in search_json:
    for result in search_json['results']:
        if result['title'] == page_title:
            page_exists = True
            page_id = result['id']
            break

# Define the page content
page_content = f'- State: {description}\n- Rule ID: {rule_id}\n- Alert level: {alert_level}\n- Agent: {agent_id} {agent_name}\n\nFull Log:\n{alert_json["full_log"]}'

if page_exists:
    # Attempt to retrieve the existing Confluence page's version
    try:
        version_number = result['version']['number']
    except KeyError:
        version_number = 1

    # Update the existing Confluence page
    update_data = {
        "version": {
            "number": version_number + 1
        },
        "title": page_title,
        "type": "page",
        "body": {
            "storage": {
                "value": page_content,
                "representation": "storage"
            }
        }
    }
    update_response = requests.put(f"{confluence_url}/{page_id}", data=json.dumps(update_data), headers=headers, auth=(user, api_key))
else:
    # Create a new Confluence page
    create_data = {
        "type": "page",
        "title": page_title,
        "space": {
            "key": confluence_space
        },
        "body": {
            "storage": {
                "value": page_content,
                "representation": "storage"
            }
        }
    }
    create_response = requests.post(confluence_url, data=json.dumps(create_data), headers=headers, auth=(user, api_key))

if create_response and create_response.status_code == 200:
    print("Confluence page created successfully.")
elif update_response and update_response.status_code == 200:
    print("Confluence page updated successfully.")
else:
    print("Error creating/updating Confluence page.")
    if create_response:
        print(create_response.text)
    elif update_response:
        print(update_response.text)

sys.exit(0)
