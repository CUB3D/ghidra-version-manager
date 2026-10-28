# GVM
Ghidra Version Manager is a utility to manage and update your Ghidra versions and extensions

Supports Linux, macOS and Windows

## Installing
### Stable Version
```shell
cargo install ghidra-version-manager
```
### Latest Version
```shell
cargo install --git https://github.com/CUB3D/ghidra-version-manager
```

This will download and extract the selected version. On Linux it will create a `.desktop` entry as well.
On macOS it will create a launcher app in `/Applications` for spotlight integration.

# Usage
In places where a version is specified you can also use "default" for your selected default version or "latest" for the latest release

## Install a new version
```shell
gvm install Ghidra_11.4_build
```

## Run it
```shell
# Run the default one
gvm run
# Or specify
gvm run Ghidra_11.2_build
```

## Update it
```shell
gvm update
```

## Change your default version
```shell
gvm default set Ghidra_11.2_build
gvm default show
```

## Install a third-party Processor
```shell
gvm extensions install PDK
```

## List known extensions
```shell
gvm extensions list
```

## Uninstall a version
```shell
gvm uninstall Ghidra_11.4_build
```

## List Ghidra versions
```shell
gvm list
```

## LLM policy
Please ensure all contributions to this project are conducted with respect to our [LLM policy](https://nlnetlabs.nl/llm-policy/).
Also note that we consider the inclusion of an extension in the library shipped with this tool as an endorsement of quality. In order to ensure this, we expect the presence of human judgement in their development. i.e. we will not accept plugins that are significantly or exclusively produced by an LLM.

# License
GPL3
