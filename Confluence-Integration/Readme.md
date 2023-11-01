## Environment

- Wazuh Manager 4.5.0
- Elasticsearch 7.x
- Wazuh Indexer
- ODFE 1.x

## Summary

This script allows you to post events from Wazuh to your Confluence page. 

## Execute the script.

Example of a configuration for the ossec.conf file:

```
     <integration>
        <name>custom-confluence</name>
        <hook_url>https://url.atlassian.net/wiki</hook_url>
        <level>3</level>
        <group>yum</group>
        <api_key>user_mail:key</api_key>
        <alert_format>json</alert_format>
     </integration>
```
