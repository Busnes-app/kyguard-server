//go:build unix

package main

import "syscall"

func realSetrlimit() error {
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
}

var setrlimit = realSetrlimit

// disableCoreDumps ensures RLIMIT_CORE is 0, soft and hard. Under the systemd unit
// (LimitCORE=0) it already is, and the unit's syscall filter refuses setrlimit, so it is
// called only when needed.
func disableCoreDumps() error {
	var l syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &l); err == nil && l.Cur == 0 && l.Max == 0 {
		return nil
	}
	return setrlimit()
}
