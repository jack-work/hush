package agent

import (
	"os"
	"strconv"
	"strings"
)

// soAcceptcon is the flag the kernel reports in /proc/net/unix for a
// socket that has been listen(2)ed on.
const soAcceptcon = 0x10000

// socketIsListening reports whether some process is currently listening
// on the AF_UNIX path — without connecting to it, which matters: a
// connect to a socket-activated path *starts the service*, so probing by
// dialing would make `hush down` spawn the agent it just stopped.
//
// /proc/net/unix is the only way to ask that question passively. Line
// shape (kernel net/unix/af_unix.c):
//
//	Num RefCount Protocol Flags Type St Inode Path
//	0000: 00000002 00000000 00010000 0001 01 12345 /run/user/1000/hush/agent.sock
//
// A false answer is the safe one everywhere it is used: it means "treat
// the node as stale", which is the behavior hush had before activation.
func socketIsListening(path string) bool {
	data, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		if fields[7] != path {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 64)
		if err != nil {
			continue
		}
		if flags&soAcceptcon != 0 {
			return true
		}
	}
	return false
}
