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

set -eo pipefail

echo " "
echo "Collecting GitHub Information..."

env_vars=("TARGET_ORG" "GH_TOKEN" "DH_USERNAME" "DH_PASSWORD_OR_PAT")
for var in "${env_vars[@]}"; do
    if [ -z "${!var+x}" ]; then
        echo "$var is not defined"
        exit 1
    fi
done

GH_TARGETS="${TARGET_ORG}/*"

GH_DATA=gh_data
# rm -rf ${GH_DATA}
mkdir -p ${GH_DATA}

npx ./gh_enumerator --output=${GH_DATA} -T $GH_TOKEN -R "${GH_TARGETS}" -R '!snyk/devex-research' --source="**/*Dockerfile*" --octoherd-cache
