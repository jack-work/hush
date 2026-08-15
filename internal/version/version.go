// Package version holds the build version, injected at link time.
package version

// Version is set via -ldflags:
//
//	go install -ldflags "-X github.com/jack-work/hush/version.Version=v0.4.0" ./...
//
// Falls back to "dev" for local builds without ldflags.
var Version = "dev"
