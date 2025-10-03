# Dockerfile
FROM rockylinux:9
USER root

RUN dnf -y update && \
    dnf -y update && \
    dnf install -y gcc epel-release && \
    dnf install -y cjson-devel unzip && \
    dnf clean all

# Set version and download URL
ENV C2PA_VERSION=0.66.0
ENV C2PA_URL=https://github.com/contentauth/c2pa-rs/releases/download/c2pa-v${C2PA_VERSION}/c2pa-v${C2PA_VERSION}-x86_64-unknown-linux-gnu.zip

# Create a directory for the library
WORKDIR /opt

# Download and unpack the release
RUN curl -L $C2PA_URL -o c2pa.zip && \
    unzip c2pa.zip -d c2pa && \
    rm c2pa.zip

# Add headers and libs to standard locations
ENV C_INCLUDE_PATH=/opt/c2pa/include
ENV LIBRARY_PATH=/opt/c2pa/lib
ENV LD_LIBRARY_PATH=/opt/c2pa/lib

# Default workdir for your C project
WORKDIR /workspace

# Copy the test file into the container
COPY test-c2pa-ffi.c /workspace/test-c2pa-ffi.c

# Compile the test program
RUN gcc /workspace/test-c2pa-ffi.c -I/opt/c2pa/include -L/opt/c2pa/lib -lc2pa_c -lcjson -lpthread -ldl -lm -o /workspace/test-c2pa-ffi

CMD ["/workspace/test-c2pa-ffi"]