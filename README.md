# GVM
Ghidra Version Manager is a utility to manage and update your Ghidra versions and extensions

## Installing
```shell
cargo install --git https://github.com/CUB3D/ghidra-version-manager
```
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

# License
GPL3