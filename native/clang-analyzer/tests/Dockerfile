FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake ninja-build g++ llvm-18-dev libclang-18-dev libclang-cpp18-dev clang-18 python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
