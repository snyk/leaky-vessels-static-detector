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

env_vars=("TARGET_ORG" "GH_TOKEN" "DH_USERNAME" "DH_PASSWORD_OR_PAT")
for var in "${env_vars[@]}"; do
    if [ -z "${!var+x}" ]; then
        echo "$var is not defined"
        exit 1
    fi
done

GH_DATA=gh_data
DOCKERFILES=`cat ${GH_DATA}/${TARGET_ORG}/list.csv`
SCAN_LOG=${GH_DATA}/${TARGET_ORG}_scan.log
SCAN_REPORT_TSV=${GH_DATA}/${TARGET_ORG}_scan_report.tsv

rm -f ${SCAN_LOG}

result=0

echo -e "Dockerfile\tResult\tMessage" | tee ${SCAN_REPORT_TSV}
for dockerfile in ${DOCKERFILES}; do
    echo Scanning ${dockerfile} ... #>> ${SCAN_LOG}
    ./static-detector dockerfile -f ${dockerfile} --dockerhub  --disable=1,3 #>> ${SCAN_LOG} 2>&1
    res=$?
    if [ $res -eq 0 ]; then
        echo -e "${dockerfile}\t0\tno issues" | tee -a ${SCAN_REPORT_TSV}
    elif [ $res -eq 1 ]; then
        echo -e "${dockerfile}\t1\tissues found" | tee -a ${SCAN_REPORT_TSV}
    elif [ $res -eq 2 ]; then
        echo -e "${dockerfile}\t2\terror parsing dockerfile" | tee -a ${SCAN_REPORT_TSV}
    elif [ $res -eq 3 ]; then
        echo -e "${dockerfile}\t3\tno issues in dockerfile but could not verify base image" | tee -a ${SCAN_REPORT_TSV}
    else
        echo -e "${dockerfile}\t${res}\tunknown exit code" | tee -a ${SCAN_REPORT_TSV}
    fi
done

exit ${result}
