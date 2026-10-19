//go:build !windows

package secretstore

import (
	log "github.com/sirupsen/logrus"
)

// platformProtector falls back to the plain medium where no operating-system
// protection is available.
//
// The fallback is reported rather than hidden: the seal file records the medium,
// and the management status shows it, so an operator is never told a store is
// protected when it is not.
func platformProtector() (keyProtector, error) {
	log.Warn("secret store: no OS key protection is available on this platform; " +
		"the seal file holds the storage key unencrypted and its file permissions are the only protection")
	return plainProtector{}, nil
}
