//go:build !linux

package workload

import (
	"fmt"
	"net"
)

func PeerAttestor(net.Conn) (Peer, error) {
	return Peer{}, fmt.Errorf("%w: peer attestation needs Linux", ErrUnattested)
}
