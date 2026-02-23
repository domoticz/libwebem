# Contributing to libwebem

Thank you for your interest in contributing to libwebem!

## Getting Started

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run the build and verify it compiles cleanly
5. Submit a pull request

## Building

### Linux/macOS (CMake)

```bash
mkdir build && cd build
cmake .. -DWEBEM_ENABLE_SSL=ON
make -j$(nproc)
```

### Windows (Visual Studio)

Open `webem.vcxproj` in Visual Studio and build the Release|Win32 configuration.

## Code Style

- C++17 standard
- Use tabs for indentation
- Run `clang-format` with the provided `.clang-format` before submitting
- Keep lines under 160 characters

## Pull Request Guidelines

- Keep PRs focused on a single change
- Include a clear description of what the PR does and why
- Ensure the library compiles without warnings on both GCC/Clang and MSVC
- Do not introduce dependencies on application-specific code; libwebem must remain a standalone library

## Reporting Issues

- Use GitHub Issues to report bugs or request features
- Include build environment details (OS, compiler, Boost version)
- For bugs, include steps to reproduce

## License

By contributing, you agree that your contributions will be licensed under the BSD 3-Clause License.
