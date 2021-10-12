Contributing {#contrib}
===

You can contribute to `libzpc` by submitting issues (feature requests, bug reports) or pull requests (code contributions) to the GitHub repository.


Bug reports
---

When filing a bug report, please include all relevant information.

In all cases include the `libzpc` version, operating system and kernel version used.

Additionally, if it is a build error, include the toolchain version used. If it is a runtime error, include the crypto adapter config and processor model used.

Ideally, detailed steps on how to reproduce the issue would be included.


Code contributions
---

All code contributions are reviewed by the `libzpc` maintainers who reverve the right to accept or reject a pull request.

Please state clearly if your pull request changes the `libzpc` API or ABI, and if so, whether the changes are backward compatible.

If your pull request resolves an issue, please put a `"Fixes #<issue number>"` line in the commit message. Ideally, the pull request would add a corresponding regression test.

If your pull request adds a new feature, please add a corresponding unit test.

The code base is formatted using the `indent` tool with the options specified in the enclosed `.indent.pro` file. All code contributions must not violate this coding style. When formatting `libzpc` code, you can use `indent` with the prescribed options by copying the file to your home directory or by setting the `INDENT_PROFILE` environment variable's value to name the file.
