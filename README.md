# Leaky Vessels Static Detector

![snyk-oss-category](https://github.com/snyk-labs/oss-images/blob/main/oss-community.jpg)

A static analysis based exploit detector for runc and Docker vulnerabilities.

## Overview

### runc process.cwd & Leaked fds Container Breakout [CVE-2024-21626]

CVE-2024-21626 is a vulnerability in the `runc` container runtime allowing an attacker to break out of the container isolation and achieve full root RCE via a crafted image that exploits an issue within the `WORKDIR` instruction's handling. Since there's a "race" condition between the time some file descriptors to the host are opened and closed, an attacker can create a Dockerfile with the following instruction `WORKDIR /proc/self/fd/[ID]` (with ID being a system dependent file descriptor) that will point to the underlying host machine's file system. This can be exploited when running:

1. `docker build` - In 2 cases:
   - When the Dockerfile being built contains the exploit triggerting instruction.
   - When the Dockerfile being built refers to a base image via the `FROM` instruction that contains an `ONBUILD` command triggering the exploit e.e. `ONBUILD WORKDIR /proc/self/fd/[ID]`. The `ONBUILD` instruction injects the command not in the image that contains it but in the image that uses it as a base image. This means that if a base image is compromised or intentionally nefarious i.e. hosted on Dockerhub or other public container registries, exploitation if possible even if nothing changes in the image that the `docker build` command actually builds.
2. `docker run`

Thus, this vulnerability can put both build systems and production environments at risk.

### Buildkit Mount Cache Race: Build-time Race Condition Container Breakout [CVE-2024-23651]

CVE-2024-23651 is a vulnerability in Docker where a `RUN` command is using the `--mount=type=cache` flag. There's a time-of-check/time-of-use (TOCTOU) vulnerability between the check that a `source` dir exists on the Docker daemon's host and the actual call to the `mount` syscall. An attacker is able to craft a Dockerfile that would plant a symlink in between these two calls to induce an arbitrary bind mount that results in full root RCE on the host.
This vulnerability only affects the `docker build` command.

### Buildkit GRPC SecurityMode Privilege Check [CVE-2024-23653]

CVE-2024-23653 is a vulnerability in Docker that occurs when using a custom Buildkit LLB generator is used with the `# syntax` directive. The generator can use the Client.NewContainer and Container.Start GRPC calls to execute a new container during build. The StartRequest.SecurityMode argument is not appropriately checked against the privilege expectations of the docker daemon or docker build call, which allows the GRPC caller to create a privileged container during build. This new privileged container can then be escaped to gain full root RCE on the build host.
This vulnerability only affects the `docker build` command.

### Buildkit Build-time Container Teardown Arbitrary Delete [CVE-2024-23652]

CVE-2024-23652 is an arbitrary deletion vulnerability in Docker. When `RUN --mount` is used in a Dockerfile, if the target of the mount does not exist it will be created for that environment. When the execution completes this created directory will be cleaned up. If the executing command changes the path used for the mount to a symbolic link, the cleanup procedure will traverse this symbolic link and potentially clean up arbitrary directories in the host root filesystem.
This vulnerability only affects the `docker build` command.

For a dynamic eBPF based detection approach, please see [this](https://github.com/snyk/leaky-vessels-runtime-detector).

## Features

The detector uses Buildkit's Dockerfile [parser](https://pkg.go.dev/github.com/moby/buildkit/frontend/dockerfile/parser) Go package to generate the AST (Abstract Syntax Tree) of a Dockerfile, traverses it and detects potential exploits using Regex matching on the instruction's arguments and flags. It can run the detection mechanism on an image history obtained from the local Docker daemon/Dockerhub as well. The image history is the output the user sees when running `docker image history [IMAGE_NAME]`, e.g:

```
IMAGE          CREATED       CREATED BY                                      SIZE      COMMENT
5381a1ec32f5   4 days ago    CMD ["/bin/sh" "-c" "/exploit"]                 0B        buildkit.dockerfile.v0
<missing>      4 days ago    RUN /bin/sh -c /exploit # buildkit              0B        buildkit.dockerfile.v0
<missing>      4 days ago    COPY <<EOT /exploit # buildkit                  110B      buildkit.dockerfile.v0
<missing>      2 weeks ago   WORKDIR /proc/self/fd/7                         0B        buildkit.dockerfile.v0
<missing>      5 weeks ago   /bin/sh -c #(nop)  CMD ["/bin/sh"]              0B
<missing>      5 weeks ago   /bin/sh -c #(nop) ADD file:1f4eb46669b5b6275…   7.38MB
```

The image history is not a 1-to-1 representation of a Dockerfile so it doesn't contain all the instructions the latter would, but it has info on both `WORKDIR` and `ONBUILD` instructions deeming it useful for our purpose. We supplement this data by also using the inspection metadata received from `docker image inspect [IMAGE_NAME]`.

The detector receives a Dockerfile path as an input and can analyze it for the aforementioned vulnerabilities exploit attempts. It can also extract the base image or multiple ones (if a multi-staged Dockerfile is used), try to determine it's source and run the analysis. Currently we only support images from GCR, Dockerhub and the local Docker daemon.

Here's a high-level breakdown of supported features:

- Regex based detection rule matching.
- Dockerfile detection - scan a Dockerfile and flag instructions potentially indicating an exploit attempt.
  - Automated base image analysis - for images from:
    1.  Local Docker daemon.
    2.  Dockerhub.
    3.  GCR - Google Container Registry.
- Image detection - runs rules directly on images hosted in one of the following sources: local daemon, Dockerhub and GCR.
  - For the local daemon and Dockerhub - analyzes the image layer history and inspection metadata.
  - For GCR - the image layer metadata doesn't contain instructions. As a workaround - pulls the image locally and runs the daemon analysis on it.

### Strengths and Limitations

Compared with the dynamic eBPF-based detector mentioned, the static detector has the following pros and cons:

1. Doesn't require continuous running in the environment.
2. Has a solid false-negative (miss) rate - if a Dockerfile is scanned and is clean, there's a good chance that running it is safe. This cannot be guaranteed 100%.

On the other hand:

1. Less accurate - has higher false-positive rates. If a Dockerfile is matched, it's still potentially vulnerable and needs further verification.
2. Does not cover everything that is built/executed - we tried to improve this by looking at the base image layer history but it's not perfect.

## Usage

### Build

Simply run:

```
go build
```

### Run

To run the main file:

```
go run main.go [COMMAND] [ARGS]
```

To run the compiled binary:

```
./static-detector [COMMAND] [ARGS]
```

### Commands and Args

- Common args -

  `--env [ENV_FILE_PATH]` - path to .env file used to store.
  `--disable [RULES_LIST]` - comma separated list of rule ids to turn off.
  `--debug` - toggle debug logs.

- Commands -

1. `dockerfile` - run Dockerfile analysis.

   - `-f [DOCKERFILE_PATH]` - path to Dockerfile.
   - `--base` - enable base image analysis.

2. `image` - run image analysis.
   - `--name [IMAGE_NAME]` - image name.

### Credentials

Provide Dockerhub credentials either via `DH_USERNAME` / `DH_PASSWORD_OR_PAT` env vars or `.env` file. `DH_PASSWORD_OR_PAT` accepts both a password or a personal access token (PAT).

Provide GCR credentials via `GOOGLE_SERVICE_ACCOUNT_JSON` env var or `.env` file. It should contain the JSON key of your service account obtained from running:

```
gcloud iam service-accounts keys create [FILENAME] --iam-account=[SERVICE_ACCOUNT_NAME]@[PROJECT_ID].iam.gserviceaccount.com
```

### Return values

- `0` - Successful, now rules were matched.
- `1` - Successful, found matches.
- `2` - Failed, an unknown error occurred.
- `3` - Failed at base image analysis.

Results are printed to the console as a `json` list.

### Running in CI/CD

For an example of how this tool can be leveraged to scan all Dockerfiles in your Github org, please see our attached [Github Crawler](./gh_crawler).

### A Note on Noise

The rules to detect the `--mount` related CVEs - CVE-2024-23651 and CVE-2024-23652, can be extremely noisy. When one of these rules matches, it essentially means that you're just using `RUN --mount=type=cache` or `RUN --mount` in general rather than an actual exploit attempt taking place resulting in a false-positive. The reason is that due to the complexity of the exploit, statically detecting these rules is not feasible. In case of high false-positive rates, we offer the `--disable` arg to turn these off or try out our [dynamic detector](https://github.com/snyk/leaky-vessels-runtime-detector) for more accurate results.

# Issues

For an updated list of bugs and issues see the project issues.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Leaky Vessels Static Detector is under the Apache 2.0 License. See [LICENSE](LICENSE) for more information.


