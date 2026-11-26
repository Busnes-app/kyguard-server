//go:build !unix

package main

import "errors"

func disableCoreDumps() error { return errors.New("kyguard-broker runs on Linux only") }
