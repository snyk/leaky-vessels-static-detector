#!/bin/bash

#  © 2024 Snyk Limited
#  
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#      https://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

env_vars=("TARGET_ORG" "PAGERDUTY_KEY")
for var in "${env_vars[@]}"; do
    if [ -z "${!var+x}" ]; then
        echo "$var is not defined"
        exit 1
    fi
done

GH_DATA=gh_data
SCAN_REPORT_TSV=${GH_DATA}/${TARGET_ORG}_scan_report.tsv

# Parsing through tsv file to get error codes that are 1 and anything > 3.
cat ${SCAN_REPORT_TSV} | awk -F'\t' '$2 == 1 || $2 > 3' > ${GH_DATA}/issues.tsv

# Read issues from issues.tsv into a variable.
# issues=$(cat ${GH_DATA}/issues.tsv)

# Send a PagerDuty alert.
curl --request 'POST' \
--url 'https://events.pagerduty.com/v2/enqueue' \
--header 'Content-Type: application/json' \
--data '{
  "payload": {
        "summary": "Snyk leaky vessels scan failed. Please check the pod logs.",
        "severity": "error",
        "source": "Snyk"
  },
  "routing_key": "'${PAGERDUTY_KEY}'",
  "event_action": "trigger"
}'


