//go:build unix

package main

import (
	"syscall"
	"testing"
)

// §4.1: the broker runs with RLIMIT_CORE=0, soft and hard.
func TestDisableCoreDumps(t *testing.T) {
	if err := disableCoreDumps(); err != nil {
		t.Fatal(err)
	}
	var l syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &l); err != nil {
		t.Fatal(err)
	}
	if l.Cur != 0 || l.Max != 0 {
		t.Fatalf("RLIMIT_CORE = %+v", l)
	}
}

// Under the systemd unit the limit is already zero and setrlimit is filtered out; a second
// call must succeed without it (PR Reviewer Guide on #9).
func TestDisableCoreDumpsAcceptsAZeroLimit(t *testing.T) {
	if err := disableCoreDumps(); err != nil {
		t.Fatal(err)
	}
	setrlimit = func() error { t.Fatal("setrlimit called with the limit already zero"); return nil }
	defer func() { setrlimit = realSetrlimit }()
	if err := disableCoreDumps(); err != nil {
		t.Fatal(err)
	}
}
