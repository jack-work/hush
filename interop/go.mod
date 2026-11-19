module github.com/jack-work/hush/interop

go 1.25.5

replace github.com/jack-work/hush => ../

require (
	github.com/jack-work/hush v0.0.0-00010101000000-000000000000
	github.com/spiffe/go-spiffe/v2 v2.9.0
)

require (
	github.com/go-jose/go-jose/v4 v4.1.5 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)
