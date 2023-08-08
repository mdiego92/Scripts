## Environment

- Elasticsearch 7.x
- Wazuh Indexer
- ODFE 1.x

## Summary

These are the steps to change one or multiple field types depending on your needs. In this use case, we needed the data.vulnerability.cvss.cvss2.base_score and data.vulnerability.cvss.cvss3.base_score to be any number type field instead of keyword to use them in visualizations with different functions.
> Reminder: please bear in mind that modifying the field type can cause different kinds of issues, so please have a backup or snapshot before manipulating indices and perform the required tests in a Stage, UAT, or local environment.

## Procedure

- Modify the wazuh-template.json file:


```
…
              "cvss": {
                "properties": {
                  "cvss2": {
                    "properties": {
                      "base_score": {
                        "type": "long"
                      },
…

…
                  "cvss3": {
                    "properties": {
                      "base_score": {
                        "type": "long"
                      },
…
```


- Apply the changes and restart filebeat:


```
filebeat setup --index-management
systemctl restart filebeat or /etc/init.d/filebeat restart
```


## Execute the script.

- Once all the indices are modified, refresh the modified index (wazuh-alerts-* in this example) from Stack Management > Index patterns > wazuh-alerts* by clicking the refresh button at the top right corner:
