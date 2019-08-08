// Copyright [2019] [Todd Garrison]
//
// Based upon work by Elasticsearch B.V. See NOTICE.txt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"github.com/elastic/go-seccomp-bpf"
	"github.com/elastic/go-ucfg/yaml"
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

var (
	policyFile string
	noNewPrivs bool
	passEnv    bool
	uid        int
	gid        int
)

func main() {
	myUid := unix.Getuid()
	myGid := unix.Getgid()
	flag.StringVar(&policyFile, "policy", "", "seccomp policy file, if not present will use a basic policy preventing changing UID")
	flag.BoolVar(&noNewPrivs, "no-new-privs", true, "set no new privs bit")
	flag.BoolVar(&passEnv, "env", true, "process inherits environment variables")
	flag.IntVar(&uid, "uid", myUid, "run process as this uid")
	flag.IntVar(&gid, "gid", myGid, "run process as this gid")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "You must specify a command and args to execute.\n")
		os.Exit(1)
	}

	// Load seccomp policy from file.
	policy, err := parseSeccompPolicy()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error loading policy: %v\n", err)
		os.Exit(1)
	}

	// Create a filter based on config.
	filter := seccomp.Filter{
		NoNewPrivs: noNewPrivs,
		Flag:       seccomp.FilterFlagTSync,
		Policy:     *policy,
	}

	// Set rgid/egid
	if myGid != gid {
		if e := unix.Setgroups(nil); e != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error clearing groups: %v\n", err)
		}
		if e := unix.Setregid(gid, gid); e != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error setting gid: %v\n", err)
			//os.Exit(1)
		}
	}
	//// Set ruid/euid
	if myUid != uid {
		if e := unix.Setreuid(uid, uid); e != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error setting uid: %v\n", err)
			os.Exit(1)
		}
	}

	// Load the BPF filter using the seccomp system call.
	if err = seccomp.LoadFilter(filter); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error loading filter: %v\n", err)
		os.Exit(1)
	}


	eEnv := make([]string,0)
	if passEnv {
		eEnv = os.Environ()
	}

	execErr := syscall.Exec(args[0], args, eEnv)
	if execErr != nil {
		panic(execErr)
	}

}

func parseSeccompPolicy() (*seccomp.Policy, error) {
	if policyFile == "" {
		return &seccomp.Policy{
			DefaultAction: seccomp.ActionAllow,
			Syscalls: []seccomp.SyscallGroup{
				{
					Action: seccomp.ActionErrno,
					Names:  []string{
						"capset",
						"ptrace",
						"seccomp",
						"setgid",
						"setgroups",
						"setuid",
					},
				},
			},
		}, nil
	}
	conf, err := yaml.NewConfigWithFile(policyFile)
	if err != nil {
		return nil, err
	}

	type Config struct {
		Seccomp seccomp.Policy
	}

	var config Config
	if err = conf.Unpack(&config); err != nil {
		return nil, err
	}

	return &config.Seccomp, nil
}
