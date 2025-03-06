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
	github.com/gdamore/encoding v1.0.0 // indirect
	github.com/gdamore/tcell/v2 v2.7.1 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	golang.org/x/term v0.25.0 // indirect
	golang.org/x/text v0.19.0 // indirect
)

require (
	github.com/ccoveille/go-safecast v1.1.0 // indirect
	github.com/creack/goselect v0.1.2 // indirect
	github.com/rivo/tview v0.0.0-20241227133733-17b7edb88c57
	go.bug.st/serial v1.6.2 // indirect
	golang.org/x/crypto v0.28.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
)
