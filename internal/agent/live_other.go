//go:build !linux

package agent

// socketIsListening cannot be answered passively off Linux (there is no
// /proc/net/unix), and socket activation is a systemd notion anyway. It
// reports false, which restores hush's pre-activation behavior: a socket
// node with no agent behind the lock is treated as stale litter.
func socketIsListening(path string) bool { return false }
