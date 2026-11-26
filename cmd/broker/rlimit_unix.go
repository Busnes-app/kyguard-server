//go:build unix

package main

import "syscall"

// disableCoreDumps sets RLIMIT_CORE to 0, soft and hard (§4.1). On Linux Go issues
// prlimit64, which the unit's filter allows (@default); `~@resources` denies only the
// setrlimit syscall. TestDisableCoreDumpsUnderTheUnit runs this under the real filter.
func disableCoreDumps() error {
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
}
