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
	"encoding/binary"
	"fmt"

	"github.com/kaiachain/kaia/common"
)

// Archive mode records a versioned value history alongside the path database:
// for every block, the post-values of all changed accounts and storage slots.
// Because Kaia is BFT instant-final, history is strictly append-forward and
// never truncated, which reduces geth's freezer/history-index machinery to a
// plain versioned key-value layout:
//
//	'a' + addrHash(32) + invBlock(8)               -> account RLP ("" = absent)
//	's' + addrHash(32) + slotHash(32) + invBlock(8) -> slot RLP  ("" = absent)
//	'w' + addrHash(32) + invBlock(8)               -> ""  (storage wipe barrier)
//	'r' + stateRoot(32)                            -> block(8)   (root index)
//
// Block numbers are stored bitwise-inverted so that entries sort newest-first
// and "value as of block N" is a single forward iterator seek.
var (
	// ArchiveMarkerKey marks the store as archive-enabled. It is written by
	// the database manager when the archive flag is set (duplicated there
	// because storage/database cannot import this package).
	ArchiveMarkerKey = []byte("PathTrieArchiveEnabled")

	accountHistoryPrefix = []byte("a")
	storageHistoryPrefix = []byte("s")
	wipeBarrierPrefix    = []byte("w")
	rootIndexPrefix      = []byte("r")
)

// invBlock encodes a block number so that higher blocks sort first.
func invBlock(n uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], ^n)
	return b[:]
}

func accountHistoryKey(addrHash common.Hash, block uint64) []byte {
	return append(append(append([]byte{}, accountHistoryPrefix...), addrHash.Bytes()...), invBlock(block)...)
}

func storageHistoryKey(addrHash, slotHash common.Hash, block uint64) []byte {
	k := append(append([]byte{}, storageHistoryPrefix...), addrHash.Bytes()...)
	k = append(k, slotHash.Bytes()...)
	return append(k, invBlock(block)...)
}

func wipeBarrierKey(addrHash common.Hash, block uint64) []byte {
	return append(append(append([]byte{}, wipeBarrierPrefix...), addrHash.Bytes()...), invBlock(block)...)
}

func rootIndexKey(root common.Hash) []byte {
	return append(append([]byte{}, rootIndexPrefix...), root.Bytes()...)
}

// BlockHistory aggregates one block's state changes for the history store.
// All keys are secure (keccak256) hashes; values are the exact bytes written
// into the tries (nil means deleted/absent).
type BlockHistory struct {
	Accounts map[common.Hash][]byte                 // addrHash -> account RLP
	Storages map[common.Hash]map[common.Hash][]byte // addrHash -> slotHash -> slot RLP
	Wipes    map[common.Hash]struct{}               // addrHashes whose storage was wiped (account deleted)
}

func NewBlockHistory() *BlockHistory {
	return &BlockHistory{
		Accounts: make(map[common.Hash][]byte),
		Storages: make(map[common.Hash]map[common.Hash][]byte),
		Wipes:    make(map[common.Hash]struct{}),
	}
}

func (h *BlockHistory) AddAccount(addrHash common.Hash, value []byte) {
	h.Accounts[addrHash] = value
}

func (h *BlockHistory) AddStorage(addrHash, slotHash common.Hash, value []byte) {
	slots, ok := h.Storages[addrHash]
	if !ok {
		slots = make(map[common.Hash][]byte)
		h.Storages[addrHash] = slots
	}
	slots[slotHash] = value
}

func (h *BlockHistory) AddWipe(addrHash common.Hash) {
	h.Wipes[addrHash] = struct{}{}
}

func (h *BlockHistory) Empty() bool {
	return len(h.Accounts) == 0 && len(h.Storages) == 0 && len(h.Wipes) == 0
}

// ArchiveEnabled reports whether this store records and serves value history.
func (db *Database) ArchiveEnabled() bool {
	return db.archive
}

// writeRootIndex maps a state root to its block number. Written on every
// Update (in both modes) so historic tries can resolve roots to blocks.
func (db *Database) writeRootIndex(root common.Hash, block uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], block)
	if err := db.kv.Put(rootIndexKey(root), b[:]); err != nil {
		logger.Crit("Failed to write path trie root index", "root", root, "err", err)
	}
}

// BlockOfRoot resolves a state root to its block number via the root index.
func (db *Database) BlockOfRoot(root common.Hash) (uint64, bool) {
	val, err := db.kv.Get(rootIndexKey(root))
	if err != nil || len(val) != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(val), true
}

// WriteBlockHistory persists one block's value history. It must be called at
// most once per (block, root) with the complete change set of that block.
func (db *Database) WriteBlockHistory(block uint64, h *BlockHistory) error {
	if !db.archive {
		return nil
	}
	batch := db.kv.NewBatch()
	defer batch.Release()
	for addrHash, value := range h.Accounts {
		if err := batch.Put(accountHistoryKey(addrHash, block), value); err != nil {
			return err
		}
	}
	for addrHash, slots := range h.Storages {
		for slotHash, value := range slots {
			if err := batch.Put(storageHistoryKey(addrHash, slotHash, block), value); err != nil {
				return err
			}
		}
	}
	for addrHash := range h.Wipes {
		if err := batch.Put(wipeBarrierKey(addrHash, block), []byte{}); err != nil {
			return err
		}
	}
	return batch.Write()
}

// seekLatest returns the newest entry at or before the given block for the
// given key prefix, exploiting the inverted block encoding.
func (db *Database) seekLatest(prefix []byte, block uint64) (foundBlock uint64, value []byte, ok bool) {
	it := db.kv.NewIterator(prefix, invBlock(block))
	defer it.Release()
	if !it.Next() {
		return 0, nil, false
	}
	key := it.Key()
	if len(key) != len(prefix)+8 {
		return 0, nil, false
	}
	b := ^binary.BigEndian.Uint64(key[len(prefix):])
	val := common.CopyBytes(it.Value())
	return b, val, true
}

// HistoricAccount returns the account RLP as of the given block, or nil if the
// account did not exist. The second return distinguishes "known absent" from
// store errors (there are none in this layout, so error is always nil today).
func (db *Database) HistoricAccount(addrHash common.Hash, block uint64) ([]byte, error) {
	prefix := append(append([]byte{}, accountHistoryPrefix...), addrHash.Bytes()...)
	_, value, ok := db.seekLatest(prefix, block)
	if !ok || len(value) == 0 {
		return nil, nil
	}
	return value, nil
}

// HistoricStorage returns a storage slot's RLP value as of the given block,
// honoring storage wipe barriers written when the owning account was deleted:
// a slot value survives only if it was written at or after the latest wipe.
func (db *Database) HistoricStorage(addrHash, slotHash common.Hash, block uint64) ([]byte, error) {
	valuePrefix := append(append([]byte{}, storageHistoryPrefix...), addrHash.Bytes()...)
	valuePrefix = append(valuePrefix, slotHash.Bytes()...)
	valueBlock, value, ok := db.seekLatest(valuePrefix, block)
	if !ok || len(value) == 0 {
		return nil, nil
	}
	barrierPrefix := append(append([]byte{}, wipeBarrierPrefix...), addrHash.Bytes()...)
	if wipeBlock, _, wiped := db.seekLatest(barrierPrefix, block); wiped && wipeBlock > valueBlock {
		return nil, nil
	}
	return value, nil
}

// CheckArchiveConsistency validates that history can be recorded for a block
// whose parent is the given root. A missing root index on a non-genesis parent
// means the store was not archive from genesis, which would corrupt history.
func (db *Database) CheckArchiveConsistency(parentRoot common.Hash, parentKnown bool) error {
	if !db.archive || parentKnown {
		return nil
	}
	return fmt.Errorf("path trie archive requires history from genesis, but parent root %x has no block index (datadir was not synced with archive enabled)", parentRoot)
}
