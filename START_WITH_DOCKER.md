# Check SSL Library Compatibility with Docker Buildx

## Check the Library Locally

Verify the library architecture using the `file` command:

```bash
file Ecliptix.Security.Certificate.Pinning/NativeLibraries/linux/libcertificate.pinning.server.so
```

**Expected output:**

```
ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, 
BuildID[sha1]=13bac9d61f6c274bb0856fb4ab3a2dce06ada1de, not stripped
```

> **Warning:** If the architecture differs (e.g., ARM), building for `amd64` may result in errors: `exec format error` or `wrong ELF class`.


## Create a Docker Buildx Builder

### Create a new builder

```bash
docker buildx create --name multiarch --use
```

Or with explicit driver specification:

```bash
docker buildx create --use --driver docker-container
```

### Verify the active builder

```bash
docker buildx ls
```

**Expected output:**

```
NAME/NODE       DRIVER/ENDPOINT             STATUS   PLATFORMS
multiarch *     docker-container            running  linux/amd64, linux/arm64, linux/arm/v7
```

## Build Docker Image for Target Platform

### Basic build

```bash
docker buildx build \
  --platform=linux/amd64 \
  --build-arg DOTNET_CLI_NUM_THREADS=4 \
  -t ecliptix-membership:lts \
  -f Ecliptix.Core/Dockerfile .
```

### Build with local registry loading

To load the image into local `docker images`, add the `--load` flag:

```bash
docker buildx build \
  --platform=linux/amd64 \
  -t ecliptix-membership:lts \
  --load \
  -f Ecliptix.Core/Dockerfile .
```