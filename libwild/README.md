# libwild

This crate allows the wild linker to be used as a library. The API is currently fairly narrow and is
basically the same as the command-line interface. The reason for this is that when a linker is
embedded in something like a compiler, you often need to be able to pass arbitrary linker arguments
to the linker. For this to be possible, the command-line parsing itself needs to be exposed as part
of the API.

Alternative APIs may be added in future based on actual use-cases. Until such use-cases arise
though, it's hard to determine what those APIs should look like.

For more details about the wild linker, see the [wild
repository](https://github.com/davidlattimore/wild).
