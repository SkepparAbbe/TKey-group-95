module tkeycthKod

go 1.22.2

replace github.com/tillitis/tkeyclient => ./lib/tkeyclient

replace github.com/tillitis/tkey-verification => ./lib/tkey-verification

replace github.com/tillitis/tkeysign.git => ./lib/tkeysign

require (
	github.com/tillitis/tkeyclient v1.1.0
	github.com/tillitis/tkeysign v1.0.1
)

require (
	github.com/ccoveille/go-safecast v1.1.0 // indirect
	github.com/creack/goselect v0.1.2 // indirect
	go.bug.st/serial v1.6.2 // indirect
	golang.org/x/crypto v0.28.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
)
