// Copyright 2026 The Kaia Authors
// This file is part of the Kaia library.
//
// The Kaia library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Kaia library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Kaia library. If not, see <http://www.gnu.org/licenses/>.

package pathstate

import (
	"sync"

	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/log"
	"github.com/kaiachain/kaia/storage/database"
	"github.com/kaiachain/kaia/storage/pathstate/pathdb"
	"github.com/kaiachain/kaia/storage/pathstate/trie"
	"github.com/kaiachain/kaia/storage/pathstate/trienode"
	"github.com/kaiachain/kaia/storage/pathstate/triestate"
)

var logger = log.NewModuleLogger(log.StorageStateDB)

// Database ties the ported path-based trie database (pathdb) to Kaia. It
// satisfies the path trie package's backing-database interface and mediates
// per-block state updates into the layered path database. In archive mode it
// additionally records a per-block value history (see history.go).
type Database struct {
	pdb     *pathdb.Database
	kv      database.Database
	archive bool
}

var (
	registryMu sync.Mutex
	registry   = make(map[database.Database]*Database)
)

// ForKV returns the singleton path-state database backed by the given
// key-value store, creating it (and loading its journal) on first use. Only
// one writable pathdb instance may exist per store, hence the registry.
func ForKV(kv database.Database) *Database {
	registryMu.Lock()
	defer registryMu.Unlock()
	if db, ok := registry[kv]; ok {
		return db
	}
	archive := false
	if has, err := kv.Has(ArchiveMarkerKey); err == nil && has {
		archive = true
		logger.Info("Path trie store is archive-enabled; recording value history")
	}
	db := &Database{pdb: pathdb.New(kv, nil), kv: kv, archive: archive}
	registry[kv] = db
	return db
}

// Reader retrieves the layer belonging to the given state root.
func (db *Database) Reader(root common.Hash) (trie.Reader, error) {
	return db.pdb.Reader(trie.TrieRootHash(root))
}

// Update applies the merged dirty node set of one block on top of its parent
// state, and indexes the new root's block number. Kaia is instant-final, so
// no reorg rollback history is retained by the layer tree itself.
func (db *Database) Update(root, parentRoot common.Hash, block uint64, nodes *trienode.MergedNodeSet) error {
	if err := db.pdb.Update(trie.TrieRootHash(root), trie.TrieRootHash(parentRoot), block, nodes, emptyStates()); err != nil {
		return err
	}
	db.writeRootIndex(trie.TrieRootHash(root), block)
	return nil
}

// Commit flattens all in-memory layers down to the persistent disk layer.
func (db *Database) Commit(root common.Hash) error {
	return db.pdb.Commit(trie.TrieRootHash(root), false)
}

// Journal persists the in-memory layers across a restart. The path database
// rejects further mutations afterwards, so this must only run at shutdown.
func (db *Database) Journal(root common.Hash) error {
	return db.pdb.Journal(trie.TrieRootHash(root))
}

// Initialized reports whether the path database already holds a state.
func (db *Database) Initialized() bool {
	return db.pdb.Initialized(common.Hash{})
}

// emptyStates returns an empty state change set. State histories are disabled
// in this port, but the journal encoder expects non-nil maps.
func emptyStates() *triestate.Set {
	return triestate.New(
		make(map[common.Address][]byte),
		make(map[common.Address]map[common.Hash][]byte),
		make(map[common.Address]struct{}),
	)
}
