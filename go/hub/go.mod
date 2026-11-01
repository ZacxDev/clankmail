module github.com/ZacxDev/clankmail/go/hub

go 1.22

require (
	github.com/ZacxDev/clankmail v0.0.0-20261101080649-c65f52f77152
	modernc.org/sqlite v1.36.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/exp v0.0.0-20230315142452-642cacee5cc0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	modernc.org/libc v1.61.13 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.8.2 // indirect
)

// In this repo the hub builds against the root module in the same checkout.
// An outside module never sees this replace: it resolves the require above,
// a real pseudo-version of clankmail main. Bump that require when the hub
// starts using root-module API newer than it.
replace github.com/ZacxDev/clankmail => ../..
