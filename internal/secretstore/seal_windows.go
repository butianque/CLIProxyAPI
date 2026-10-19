//go:build windows

package secretstore

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dpapiEntropy is mixed into every seal. It is not a secret — it only binds the
// blob to this application, so another program on the same machine cannot
// unprotect it by accident.
var dpapiEntropy = []byte("cpa-secretstore-seal-v1")

// platformProtector returns DPAPI on Windows.
//
// Machine scope is deliberate: the store is opened by a service, and a key sealed
// to one user account would break the moment the service account changes. The
// file's ACL, not the DPAPI scope, is what keeps other users out.
func platformProtector() (keyProtector, error) {
	return dpapiProtector{}, nil
}

type dpapiProtector struct{}

func (dpapiProtector) medium() string { return SealMediumDPAPI }

func (dpapiProtector) protect(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, errors.New("cannot seal an empty key")
	}
	in := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	entropy := windows.DataBlob{Size: uint32(len(dpapiEntropy)), Data: &dpapiEntropy[0]}
	var out windows.DataBlob
	if errCall := windows.CryptProtectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE, &out); errCall != nil {
		return nil, fmt.Errorf("dpapi protect: %w", errCall)
	}
	return takeBlob(&out)
}

func (dpapiProtector) unprotect(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, errors.New("sealed key is empty")
	}
	in := windows.DataBlob{Size: uint32(len(blob)), Data: &blob[0]}
	entropy := windows.DataBlob{Size: uint32(len(dpapiEntropy)), Data: &dpapiEntropy[0]}
	var out windows.DataBlob
	if errCall := windows.CryptUnprotectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE, &out); errCall != nil {
		return nil, fmt.Errorf("dpapi unprotect: %w", errCall)
	}
	return takeBlob(&out)
}

// takeBlob copies a DPAPI-allocated buffer out and frees it.
func takeBlob(blob *windows.DataBlob) ([]byte, error) {
	if blob.Data == nil || blob.Size == 0 {
		return nil, errors.New("dpapi returned no data")
	}
	result := make([]byte, blob.Size)
	copy(result, unsafe.Slice(blob.Data, blob.Size))
	if _, errFree := windows.LocalFree(windows.Handle(unsafe.Pointer(blob.Data))); errFree != nil {
		return nil, fmt.Errorf("dpapi free: %w", errFree)
	}
	blob.Data = nil
	blob.Size = 0
	return result, nil
}
