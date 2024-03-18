## GitHub Crawler and Scanner

### Prerequisites

1. Define environment variables:
   - `TARGET_ORG`: the name of the GitHUb organisation to crawl, example `snyk`
   - `GH_TOKEN`: a GitHub token with read permissions on all the repositories
   - `DH_USERNAME`: (Optional) Docker hub username to access base image history from Dockerhub
   - `DH_PASSWORD_OR_PAT`: (Optional) Docker hub passwor to access base image history from Dockerhub
   - `GOOGLE_SERVICE_ACCOUNT_JSON`: (Optional) Google Cloud SA key for accessing the container registry

### Running from Code

1. Build the `static-detector` and copy it in the `src` folder
1. Run `./static_scan.sh` in the context of the `crawler` folder
1. Alternatively, run the 2 components independently:
   1. `./collect_dockerfiles.sh`
   1. `./scan_dockerfiles.sh`

### Running as a container

1. Build the container image:
   `docker build . -f gh_crawler/docker/Dockerfile -t static-scanner:latest`
1. Run the container image:
   `docker run -e TARGET_ORG -e GH_TOKEN -e DH_USERNAME -e DH_PASSWORD_OR_PAT -e GOOGLE_SERVICE_ACCOUNT_JSON static-scanner:latest`

#### CircleCI Example

The attached `circleci.yaml` shows how to use the static detector to crawl & scan all Dockerfiles in a given org.
