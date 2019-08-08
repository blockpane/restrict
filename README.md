# restrict

Command line utiity that facilitates changing UID/GID, applies a seccomp policy, and can strip the environment before running a command. Useful for things like preventing nodejs from launching commands (just remove clone) or allowing a daemon to accept incoming, but not make outgoing connections. See seccomp.yml for an example policy.

TODO: add the ability to drop or restrict specific Linux capabilities.

Basically, this is just a modified version of the example from: https://github.com/elastic/go-seccomp-bpf

## Using:

```
# restrict -h
Usage of restrict:
  -env
    	process inherits environment variables (default true)
  -gid int
    	run process as this gid
  -no-new-privs
    	set no new privs bit (default true)
  -policy string
    	seccomp policy file, if not present will use a basic policy preventing changing UID
  -uid int
    	run process as this uid
```

For example: `/bin/restrict -env=false -uid=65534 -gid=65534 -policy=./seccomp.yml /bin/dash`

## Download

Compiled version is available here: https://frameloss.org/restrict.tgz

`SHA256(restrict)= aeccfb852a413291c8b31033b76d99cf45e03591a9917bc93e3665556628159a`