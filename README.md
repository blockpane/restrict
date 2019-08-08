# restrict

Command line utiity that facilitates changing UID/GID, applies a seccomp policy, and can strip the environment before running a command. Useful for things like preventing nodejs from launching commands (just remove clone) or allowing a daemon to accept incoming, but not make outgoing connections. See seccomp.yml for an example policy.

TODO: add the ability to drop or restrict specific Linux capabilities.

Basically, this is just a modified version of the example from: https://github.com/elastic/go-seccomp-bpf
