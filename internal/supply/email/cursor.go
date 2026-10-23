package email

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// The two shapes a read position can take. They are not the two natures a
// mailbox can have: an OAuth2 mailbox is still read over IMAP, so it counts UIDs
// like a password mailbox does. Only Graph, which has no UID, needs its own.
const (
	cursorNatureIMAP  = "imap"
	cursorNatureGraph = "graph"
)

// cursorPrefix marks an encoded cursor, so a value this build did not write is
// refused instead of being read as a position that never existed.
const cursorPrefix = "v1."

// ErrCursor reports a cursor this build cannot read. A caller that gets it
// should start over rather than poll with a position nothing can honour.
var ErrCursor = errors.New("email: the read position is not readable")

// FolderPosition is how far one folder has been read.
//
// It is per folder because a UID only means something inside the folder that
// issued it: the same number names a different message in INBOX and in Junk, so
// one position cannot describe both.
type FolderPosition struct {
	// Folder is the folder the position belongs to.
	Folder string `json:"b"`
	// UIDValidity is that folder's generation. A different value means every
	// stored UID now names a different message, so the position is dropped and
	// the window is read again rather than silently skipping mail.
	UIDValidity uint32 `json:"v,omitempty"`
	// UID is the last message read in the folder.
	UID uint32 `json:"u,omitempty"`
	// Received is the last arrival read in the folder, for Graph.
	Received string `json:"t,omitempty"`
}

// Cursor is where one address's mail has been read up to.
//
// It is opaque to the caller on purpose: the interface must not make a script
// branch on how a mailbox is read. The provider encodes it, the caller hands it
// back, and only this package knows that an IMAP mailbox counts UIDs while a
// Graph mailbox counts arrival times.
//
// The position is held by the caller rather than stored by the service, so two
// consumers reading the same mailbox cannot take mail away from each other and a
// restart loses nothing.
type Cursor struct {
	// Nature is which of the two shapes these positions take.
	Nature string `json:"n,omitempty"`
	// Folders is one position per folder that has been read.
	Folders []FolderPosition `json:"f,omitempty"`
}

// IsZero reports whether the cursor names no position, which is the state of a
// first read.
func (c Cursor) IsZero() bool { return c.Nature == "" }

// For returns the position this cursor holds for one folder, or the zero value
// when it holds none — which is what makes a folder read from the window the
// first time it is seen.
func (c Cursor) For(folder string) FolderPosition {
	wanted := strings.TrimSpace(folder)
	for _, position := range c.Folders {
		if strings.EqualFold(strings.TrimSpace(position.Folder), wanted) {
			return position
		}
	}
	return FolderPosition{}
}

// With returns the cursor updated with one folder's new position. A folder that
// is already carried is replaced, so a position never accumulates duplicates.
func (c Cursor) With(position FolderPosition) Cursor {
	next := Cursor{Nature: c.Nature, Folders: make([]FolderPosition, 0, len(c.Folders)+1)}
	for _, existing := range c.Folders {
		if strings.EqualFold(strings.TrimSpace(existing.Folder), strings.TrimSpace(position.Folder)) {
			continue
		}
		next.Folders = append(next.Folders, existing)
	}
	next.Folders = append(next.Folders, position)
	return next
}

// EncodeCursor renders a cursor for the wire. A zero cursor encodes to the empty
// string, so "start from the beginning" and "no position yet" are one value and
// a caller never has to invent one.
func EncodeCursor(c Cursor) string {
	if c.IsZero() {
		return ""
	}
	payload, errMarshal := json.Marshal(c)
	if errMarshal != nil {
		// A Cursor is a string and a list of scalars; encoding it cannot fail.
		// Reporting the zero value is still the safe answer: the caller reads
		// from the beginning instead of from a position that was never written.
		return ""
	}
	return cursorPrefix + base64.RawURLEncoding.EncodeToString(payload)
}

// DecodeCursor reads a cursor produced by EncodeCursor. An empty value is the
// zero cursor and not an error, because that is what a first read sends.
func DecodeCursor(raw string) (Cursor, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Cursor{}, nil
	}
	encoded, ok := strings.CutPrefix(trimmed, cursorPrefix)
	if !ok {
		return Cursor{}, fmt.Errorf("%w: %q does not start with %q", ErrCursor, trimmed, cursorPrefix)
	}
	payload, errDecode := base64.RawURLEncoding.DecodeString(encoded)
	if errDecode != nil {
		return Cursor{}, fmt.Errorf("%w: %v", ErrCursor, errDecode)
	}
	var cursor Cursor
	if errUnmarshal := json.Unmarshal(payload, &cursor); errUnmarshal != nil {
		return Cursor{}, fmt.Errorf("%w: %v", ErrCursor, errUnmarshal)
	}
	if cursor.Nature != cursorNatureIMAP && cursor.Nature != cursorNatureGraph {
		return Cursor{}, fmt.Errorf("%w: unknown position kind %q", ErrCursor, cursor.Nature)
	}
	return cursor, nil
}

// cursorNature names the position shape an auth mode implies.
func cursorNature(auth AuthMode) string {
	if auth == AuthGraph {
		return cursorNatureGraph
	}
	return cursorNatureIMAP
}
