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

FROM golang:1.21 as builder

COPY . /app
WORKDIR /app
RUN go build 

FROM node:18

ARG USERNAME=scanner
ARG USER_UID=1001
ARG USER_GID=$USER_UID
ARG USER_HOME=/srv/app

USER root

RUN addgroup \
        --gid "${USER_GID}" \
        --quiet \
        "${USERNAME}" && \
    adduser \
        --disabled-password \
        --disabled-login \
        --gecos '' \
        --home ${USER_HOME} \
        --uid "${USER_UID}" \
        --gid "${USER_GID}" \
        --quiet \
        "${USERNAME}"

WORKDIR /srv/app
COPY --chown=scanner:scanner ./gh_crawler/src /srv/app
COPY --from=builder /app/static-detector /srv/app

WORKDIR /srv/app/gh_enumerator
RUN npm i

WORKDIR /srv/app
USER scanner

ENTRYPOINT ["/srv/app/static_scan.sh"]
