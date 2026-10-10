module github.com/CMABERY/4GARTHA/ci/anchor-go

go 1.25.0

require (
	golang.org/x/mod v0.35.0
	sigsum.org/sigsum-go v0.14.1
)

require github.com/pborman/getopt/v2 v2.1.0 // indirect

tool sigsum.org/sigsum-go/cmd/sigsum-verify
