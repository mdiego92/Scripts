#!/var/ossec/framework/python/bin/python3
import requests
import urllib3
import sys
import json
import logging
import os
import argparse
from socket import socket, AF_UNIX, SOCK_DGRAM

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define the socket address
socketAddr = '/var/ossec/queue/sockets/queue'

# Send message to socket
def send_event(msg):
    logging.debug('Sending {} to {} socket.'.format(msg, socketAddr))
    string = '1:group-sca:{}'.format(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()

# Configuring a logger for the script.
def set_logger(name, logfile=None):
    hostname = os.uname()[1]
    format = '%(asctime)s {0} {1}: [%(levelname)s] %(message)s'.format(hostname, name)
    logging.basicConfig(level=logging.INFO, format=format, datefmt="%Y-%m-%d %H:%M:%S", filename=logfile)
    if logfile:
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        formatter = logging.Formatter(format, datefmt="%Y-%m-%d %H:%M:%S")
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

# Function to get the Wazuh API Token
def get_token(user, passw):
    logging.info("Obtaining the Wazuh API token")
    hook_url = "https://" + manager_ip + ":55000/security/user/authenticate?raw=true"
    try:
        response = requests.get(hook_url, auth=(user, passw), verify=False)
        return response.text
    except Exception as e:
        logging.error("Error getting the token. Details: " + str(e))
        sys.exit(1)

# Function to get the agent name by ID
def get_agent_name_by_id(token, agent_id):
    logging.info("Getting agent name for agent ID: " + agent_id)
    hook_url = "https://" + manager_ip + ":55000/agents?agents_list=" + agent_id
    try:
        response = requests.get(hook_url, headers={'Authorization': 'Bearer ' + token}, verify=False)
        agent_info = json.loads(response.text)
        return agent_info["data"]["affected_items"][0]["name"] if agent_info else "Unknown"
    except Exception as e:
        logging.error("Error getting agent name for agent ID {}. Details: {}".format(agent_id, str(e)))
        sys.exit(1)

# Function to get the SCA results for a specific agent and policy
def get_sca_by_agent(token, agent_id):
    logging.info("Getting the SCA results of policy " + policy_id + " for agent ID " + agent_id)
    hook_url = "https://" + manager_ip + ":55000/sca/" + agent_id + "/checks/" + policy_id
    try:
        response = requests.get(hook_url, headers={'Authorization': 'Bearer ' + token}, verify=False)
        sca_results = json.loads(response.text)
        return sca_results
    except Exception as e:
        logging.error("Error getting the SCA results for agent ID {}. Details: {}".format(agent_id, str(e)))
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="sca-alerts.py", description='Get SCA information from agents and inject it in Wazuh as an alert.')
    parser.add_argument('--agent_id', nargs='+', help='Agent ID to query', required=True)
    parser.add_argument('--policy_id', help='Policy ID to query', default="cis_centos7_linux")
    parser.add_argument('--manager_ip', help='Wazuh manager IP', default="127.0.0.1")
    parser.add_argument('--env_username', help='Wazuh username', default="wazuh-wui")
    parser.add_argument('--env_password', help='Wazuh password', default="wazuh-wui")
    args = parser.parse_args()

    agent_ids = args.agent_id
    policy_id = args.policy_id
    manager_ip = args.manager_ip
    env_username = args.env_username
    env_password = args.env_password

    set_logger("sca-alerts")
    api_token = get_token(env_username, env_password)

    # Main Program
    logging.info("Working with the Inventory information")
    for agent_id in agent_ids:
        agent_name = get_agent_name_by_id(api_token, agent_id)
        sca_results = get_sca_by_agent(api_token, agent_id)
        for itm in sca_results["data"]["affected_items"]:
            tmp = {
                "scan-type": "custom-sca"
            }
            tmp["agent"] = {
                "id": agent_id,
                "name": agent_name,
            }
            tmp["sca"] = {
                "result": itm["result"],
                "description": itm.get("description", "Unknown description"),
                "id": itm["id"],
                "title": itm.get("title", "Unknown title"),
                "rationale": itm.get("rationale", "Unknown rationale")
            }
            if "remediation" in itm:
                tmp["sca"]["remediation"] = itm["remediation"]
            json_msg = json.dumps(tmp, default=str)
            send_event(json_msg)

    logging.info("Finished getting the sca information for the agents")
