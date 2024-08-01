## Environment

- Elasticsearch 7.x
- Wazuh Indexer
- ODFE 1.x

## Summary

This script allows you to get the information from the Security Configuration Assessment through the Wazuh API, format the output and send it to the current index of Wazuh Indexer or Elasticsearch. 

```
  -a AGENT, --agent AGENT
                        Agent ID
  -all                  Process all agents
  -wh WAZUH_HOST, --wazuh-host WAZUH_HOST
                        Wazuh host
  -wp WAZUH_PORT, --wazuh-port WAZUH_PORT
                        Wazuh port
  -wu WAZUH_USER, --wazuh-user WAZUH_USER
                        Wazuh user
  -wpass WAZUH_PASSWORD, --wazuh-password WAZUH_PASSWORD
                        Wazuh password
  -eh ELASTICSEARCH_HOST, --elasticsearch-host ELASTICSEARCH_HOST
                        Elasticsearch host
  -ep ELASTICSEARCH_PORT, --elasticsearch-port ELASTICSEARCH_PORT
                        Elasticsearch port
  -eu ELASTICSEARCH_USER, --elasticsearch-user ELASTICSEARCH_USER
                        Elasticsearch user
  -epass ELASTICSEARCH_PASSWORD, --elasticsearch-password ELASTICSEARCH_PASSWORD
                        Elasticsearch password
  -i ELASTICSEARCH_INDEX, --elasticsearch-index ELASTICSEARCH_INDEX
                        Elasticsearch index
  -v, --verbose         Enable verbose output
```


## Execute the script.

```
python3 sca.py -a 001 -wh localhost -wp 55000 -wu wazuh-wui -wpass wazuh-wui -eh localhost -ep 9200 -eu wazuh -epass wazuh -i wazuh-alerts-4.x -v
```
