package agent

import "net"

// inheritedListener has no meaning on Windows: there is no sd_listen_fds
// protocol, and the Windows service manager hands nothing to a service.
// The agent always binds its own socket there.
func inheritedListener() (net.Listener, error) { return nil, nil }
