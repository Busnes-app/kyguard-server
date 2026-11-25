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
