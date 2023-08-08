#!/bin/bash

# Prompt parameters
read -p "Enter username for ElasticSearch / Wazuh Indexer: " user
read -p "Enter password for ElasticSearch / Wazuh Indexer: " pass
read -p "Enter Elasticsearch IP address / DNS (e.g., https://this_paramter_only:9200): " server
read -p "Enter index/indices name (e.g., wazuh-alerts-4.x-2023.06.30 or wazuh-alerts-4.x-2023.06. for an entire month): " filter

indices=$(curl -s -k -u "$user:$pass" "https://$server:9200/_cat/indices?h=index&s=index" | grep "$filter")

if [[ -z "$indices" ]]; then
echo "No indices matching the filter were found. Exiting..."
exit 1
fi

for index in $indices; do
reindex_response=$(curl -s -k -XPOST -u "$user:$pass" "https://$server:9200/_reindex?wait_for_completion=false" -H 'Content-Type: application/json' -d '{
"source": {
"index": "'$index'"
},
"dest": {
"index": "tempindex"
}
}' | jq -r '.task')

echo "Copying $index to tempindex..."

# Execute GET _tasks/$reindex_response
task_response=$(curl -s -k -u "$user:$pass" "https://$server:9200/_tasks/$reindex_response")

start_time=$(date +%s)

while :; do
# Extract completion and timed_out status from task_response
completed=$(echo "$task_response" | jq -r '.completed')
timed_out=$(echo "$task_response" | jq -r '.response.timed_out')

# Check if reindexing is completed and not timed out
if [[ "$completed" == "true" && "$timed_out" == "false" ]]; then
echo "Reindexing completed for $index to tempindex."
delete_response=$(curl -s -k -XDELETE -u "$user:$pass" "https://$server:9200/$index" -H 'Content-Type: application/json' | jq -r '.acknowledged')
echo "Deleted $index."
break
fi

# Check if the script has exceeded the maximum timeout of 30 minutes
current_time=$(date +%s)
time_elapsed=$((current_time - start_time))
if [[ "$time_elapsed" -gt 1800 ]]; then
echo "Timeout exceeded. Reindexing took more than 30 minutes. Exiting..."
exit 1
fi

# Wait before checking again
sleep 3

# Fetch the updated task response
task_response=$(curl -s -k -u "$user:$pass" "https://$server:9200/_tasks/$reindex_response")
done

reindex_response=$(curl -s -k -XPOST -u "$user:$pass" "https://$server:9200/_reindex?wait_for_completion=false" -H 'Content-Type: application/json' -d '{
"source": {
"index": "tempindex"
},
"dest": {
"index": "'$index'"
}
}' | jq -r '.task')

echo "Copying tempindex to $index..."

# Execute GET _tasks/$reindex_response
task_response=$(curl -s -k -u "$user:$pass" "https://$server:9200/_tasks/$reindex_response")

start_time=$(date +%s)

while :; do
# Extract completion and timed_out status from task_response
completed=$(echo "$task_response" | jq -r '.completed')
timed_out=$(echo "$task_response" | jq -r '.response.timed_out')

# Check if reindexing is completed and not timed out
if [[ "$completed" == "true" && "$timed_out" == "false" ]]; then
echo "Reindexing completed from tempindex to $index."
delete_response=$(curl -s -k -XDELETE -u "$user:$pass" "https://$server:9200/tempindex" -H 'Content-Type: application/json' | jq -r '.acknowledged')
echo "Deleted tempindex."
break
fi

# Check if the script has exceeded the maximum timeout of 30 minutes
current_time=$(date +%s)
time_elapsed=$((current_time - start_time))
if [[ "$time_elapsed" -gt 1800 ]]; then
echo "Timeout exceeded. Reindexing took more than 30 minutes. Exiting..."
exit 1
fi

# Wait before checking again
sleep 3

# Fetch the updated task response
task_response=$(curl -s -k -u "$user:$pass" "https://$server:9200/_tasks/$reindex_response")
done
done
