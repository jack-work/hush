//go:build !linux && !windows

package daemon

import "errors"

func moveIntoScope(placement, int) error { return errors.ErrUnsupported }
