# test-c2pa-ffi

A minimal test setup for the C2PA C API (https://github.com/contentauth/c2pa-rs/blob/main/c2pa_c_ffi/src/c_api.rs), demonstrating image signing using memory streams.

## Overview
This project provides a simple example of how to use the C2PA C API to sign images using memory streams. It is designed to run in a containerized environment and is meant to serve as a (hopefully) helpful example of how to integrate C2PA into plain C projects.

## File Structure
- `test-c2pa-ffi.c`: Main test source code
- `Dockerfile`: Container build instructions for dependencies and test execution
- `resources/`: Example input files (images, manifests, certs, keys)

## Prerequisites
- Docker (for building and running)

## Building and Running
1. Build the Docker image:
   ```sh
   docker build -t test-c2pa-ffi .
   ```
2. Run the container, the signed image will get copied out to `resources/`:
   ```sh
   docker run -v "$PWD/resources":/workspace/tmp test-c2pa-ffi
   ```

## Usage Notes
- Output and error messages are printed to stdout for debugging.
- To test with other images, change the hardcoded filepaths in test-c2pa-ffi.c and rebuild. TODO: pass file paths as args.