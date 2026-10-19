package supply

// This file moves mailbox identities out of the channel table and into the pool.
//
// A channel used to be able to declare oauth2 or graph, one mailbox per channel.
// That put a single personal mailbox in the same table as a service that mints
// addresses for a whole domain — the table grew one row per bought mailbox, and
// the question "which connection can I use" got mixed up with "which address do
// I have".
//
// The natures are refused on write now (see ChannelNatures). An existing document
// still declares them, so it is moved here rather than rejected at load time: the
// mailbox keeps working, it just lives where it belongs.

// MigrateChannelsToPool moves every mailbox a channel can no longer own into the
// pool, and reports how many identities it moved.
//
// A connection is moved when its nature is oauth2 or graph — transports whose
// credential belongs to the mailbox rather than to a source of many addresses —
// or when the channel's category is the retired self-owned one.
//
// The rest of the channel is preserved: an IMAP connection stays a channel, a
// phone block stays a channel, and a channel left with no kind at all is removed
// because it would only be an empty row. Nothing is written when nothing moved,
// so a start-up on an already-migrated directory does not rewrite the file.
func MigrateChannelsToPool(store *ChannelStore, pool *Pool, now int64) (int, error) {
	if store == nil || pool == nil {
		return 0, nil
	}
	moved := 0
	for _, channel := range store.All() {
		next := channel
		changed := false
		if channel.Email != nil {
			emailBlock, count := detachMailboxIdentities(channel, pool, now)
			moved += count
			if count > 0 {
				changed = true
				next.Email = emailBlock
			}
		}
		if next.Category == "self-owned" {
			// The category no longer exists. A channel that kept it would be
			// refused by the next write, so it is lowered to the default rather
			// than left in a state the operator cannot save.
			next.Category = "third-party"
			changed = true
		}
		if !changed {
			continue
		}
		// A channel left with no kind at all is only an empty row: every mailbox
		// it had is a pool identity now, so there is nothing left to connect to.
		if next.Email == nil && next.Phone == nil {
			if errDelete := store.Delete(next.ID); errDelete != nil {
				return moved, errDelete
			}
			continue
		}
		if _, errSave := store.Upsert(next, now); errSave != nil {
			return moved, errSave
		}
	}
	return moved, nil
}

// detachMailboxIdentities copies every connection that belongs to a pool identity
// into the pool and returns the email block a channel may keep, or nil when
// nothing is left for it to do.
//
// The kept block is rebuilt rather than edited in place: the store hands out
// copies, but the connection map inside is shared with the caller's copy, and
// deleting from it would mutate the channel the caller is iterating.
func detachMailboxIdentities(channel Channel, pool *Pool, now int64) (*KindConfig, int) {
	source := channel.Email
	kept := make([]Nature, 0, len(source.Natures))
	connections := make(map[Nature]Connection, len(source.Connections))
	moved := 0
	for _, nature := range source.Natures {
		connection := source.Connections[nature]
		if nature == NatureIMAP && channel.Category != "self-owned" {
			kept = append(kept, nature)
			connections[nature] = connection
			continue
		}
		if !nature.IsMailbox() {
			// A nature this block never spoke; dropping it is what the write path
			// would do anyway.
			continue
		}
		account := connection.Account
		if account == "" {
			continue
		}
		box := Mailbox{
			Nature:   nature,
			Endpoint: connection.Endpoint,
			ClientID: connection.ClientID,
			Secret:   connection.Secret,
		}
		if box.Secret == "" {
			box.Secret = EmailOAuth2CredentialName(account)
			if nature == NatureIMAP {
				box.Secret = EmailCredentialName(account)
			}
		}
		pool.AttachMailbox(KindEmail, account, box, now)
		moved++
	}
	if len(kept) == 0 {
		return nil, moved
	}
	return &KindConfig{
		Enabled:     source.Enabled,
		Natures:     kept,
		Connections: connections,
	}, moved
}
