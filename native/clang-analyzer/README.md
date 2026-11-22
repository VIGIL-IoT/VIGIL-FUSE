# FUSE Clang semantic producer

This C++17 LibTooling executable emits AST observations, never security verdicts.
Python validates and selects evidence. C fixtures are analysis targets, never executed.
See [the contract and limitations](../../docs/cpp-semantic-analysis.md).

Detect prerequisites with `clang --version`, `clang++ --version`, `cmake --version`
and `llvm-config --cmakedir`. A compiler binary alone is insufficient: LLVM and
Clang development libraries, including `ClangConfig.cmake`, must be installed.
FUSE does not install these automatically.

With compatible development packages already installed:

```sh
cmake -S native/clang-analyzer -B native/clang-analyzer/build -DCMAKE_BUILD_TYPE=Release
cmake --build native/clang-analyzer/build --parallel 2
ctest --test-dir native/clang-analyzer/build --output-on-failure
native/clang-analyzer/build/fuse-clang-analyzer --version
```

Set `LLVM_DIR` and `Clang_DIR` when CMake cannot locate the matching package configs.
The executable is dynamically linked; retain the matching runtime libraries.
The supplied development Dockerfile uses Ubuntu 24.04 and LLVM 18 packages.
It is a test environment, not a production worker. Package versions follow the
Ubuntu repository; record the actual tested version rather than assuming a patch version.

Approved isolated build example (PowerShell, from repository root):

```powershell
docker build -t fuse-clang-build:llvm18 -f native/clang-analyzer/tests/Dockerfile native/clang-analyzer/tests
New-Item -ItemType Directory -Force native/clang-analyzer/build
docker run --rm --network none --memory 3g --cpus 2 --mount "type=bind,source=$($PWD.Path),target=/src,readonly" --mount "type=bind,source=$($PWD.Path)/native/clang-analyzer/build,target=/build" fuse-clang-build:llvm18 sh -ec 'cmake -S /src/native/clang-analyzer -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR=/usr/lib/llvm-18/lib/cmake/llvm -DClang_DIR=/usr/lib/llvm-18/lib/cmake/clang; cmake --build /build --parallel 1; ctest --test-dir /build --output-on-failure'
```

CTest runs version probing and real Python-adapter/C/C++ integration tests when
Python is available. Windows Python can run adapter tests without LLVM installed.
The Docker executable is Linux-only; it does not make Windows doctor report available.
