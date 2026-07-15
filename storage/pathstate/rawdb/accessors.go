// Modifications Copyright 2026 The Kaia Authors
// Copyright 2022 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.
//
// This file is derived from core/rawdb/accessors_trie.go and
// core/rawdb/accessors_state.go (go-ethereum v1.13.15), keeping only the
// path-based state scheme accessors.

package rawdb

import (
	"encoding/binary"
	"hash"
	"sync"

	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/crypto/sha3"
	"github.com/kaiachain/kaia/log"
	"github.com/kaiachain/kaia/storage/database"
)

var logger = log.NewModuleLogger(log.StorageStateDB)

// KeyValueReader wraps the Get and Has methods of the backing store. Kaia's
// database.Database and database.Batch both satisfy the writer half; readers are
// provided by database.Database. Reads return a non-nil error on a missing key,
// which the accessors below treat as "not found" to mirror geth semantics.
type KeyValueReader interface {
	Get(key []byte) ([]byte, error)
	Has(key []byte) (bool, error)
}

// keccakState wraps sha3.state. In addition to the usual hash methods, it also
// supports Read to get a variable amount of data from the hash state.
type keccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

// hasher is used to compute the keccak256 hash of the provided data.
type hasher struct{ sha keccakState }

var hasherPool = sync.Pool{
	New: func() interface{} { return &hasher{sha: sha3.NewKeccak256().(keccakState)} },
}

func newHasher() *hasher {
	return hasherPool.Get().(*hasher)
}

func (h *hasher) hash(data []byte) common.Hash {
	var out common.Hash
	h.sha.Reset()
	h.sha.Write(data)
	h.sha.Read(out[:])
	return out
}

func (h *hasher) release() {
	hasherPool.Put(h)
}

// ReadAccountTrieNode retrieves the account trie node and the associated node
// hash with the specified node path.
func ReadAccountTrieNode(db KeyValueReader, path []byte) ([]byte, common.Hash) {
	data, err := db.Get(accountTrieNodeKey(path))
	if err != nil {
		return nil, common.Hash{}
	}
	h := newHasher()
	defer h.release()
	return data, h.hash(data)
}

// HasAccountTrieNode checks the account trie node presence with the specified
// node path and the associated node hash.
func HasAccountTrieNode(db KeyValueReader, path []byte, hash common.Hash) bool {
	data, err := db.Get(accountTrieNodeKey(path))
	if err != nil {
		return false
	}
	h := newHasher()
	defer h.release()
	return h.hash(data) == hash
}

// WriteAccountTrieNode writes the provided account trie node into database.
func WriteAccountTrieNode(db database.KeyValueWriter, path []byte, node []byte) {
	if err := db.Put(accountTrieNodeKey(path), node); err != nil {
		logger.Crit("Failed to store account trie node", "err", err)
	}
}

// DeleteAccountTrieNode deletes the specified account trie node from the database.
func DeleteAccountTrieNode(db database.KeyValueWriter, path []byte) {
	if err := db.Delete(accountTrieNodeKey(path)); err != nil {
		logger.Crit("Failed to delete account trie node", "err", err)
	}
}

// ReadStorageTrieNode retrieves the storage trie node and the associated node
// hash with the specified node path.
func ReadStorageTrieNode(db KeyValueReader, accountHash common.Hash, path []byte) ([]byte, common.Hash) {
	data, err := db.Get(storageTrieNodeKey(accountHash, path))
	if err != nil {
		return nil, common.Hash{}
	}
	h := newHasher()
	defer h.release()
	return data, h.hash(data)
}

// HasStorageTrieNode checks the storage trie node presence with the provided
// node path and the associated node hash.
func HasStorageTrieNode(db KeyValueReader, accountHash common.Hash, path []byte, hash common.Hash) bool {
	data, err := db.Get(storageTrieNodeKey(accountHash, path))
	if err != nil {
		return false
	}
	h := newHasher()
	defer h.release()
	return h.hash(data) == hash
}

// WriteStorageTrieNode writes the provided storage trie node into database.
func WriteStorageTrieNode(db database.KeyValueWriter, accountHash common.Hash, path []byte, node []byte) {
	if err := db.Put(storageTrieNodeKey(accountHash, path), node); err != nil {
		logger.Crit("Failed to store storage trie node", "err", err)
	}
}

// DeleteStorageTrieNode deletes the specified storage trie node from the database.
func DeleteStorageTrieNode(db database.KeyValueWriter, accountHash common.Hash, path []byte) {
	if err := db.Delete(storageTrieNodeKey(accountHash, path)); err != nil {
		logger.Crit("Failed to delete storage trie node", "err", err)
	}
}

// ReadStateID retrieves the state id with the provided state root.
func ReadStateID(db KeyValueReader, root common.Hash) *uint64 {
	data, err := db.Get(stateIDKey(root))
	if err != nil || len(data) == 0 {
		return nil
	}
	number := binary.BigEndian.Uint64(data)
	return &number
}

// WriteStateID writes the provided state lookup to database.
func WriteStateID(db database.KeyValueWriter, root common.Hash, id uint64) {
	var buff [8]byte
	binary.BigEndian.PutUint64(buff[:], id)
	if err := db.Put(stateIDKey(root), buff[:]); err != nil {
		logger.Crit("Failed to store state ID", "err", err)
	}
}

// DeleteStateID deletes the specified state lookup from the database.
func DeleteStateID(db database.KeyValueWriter, root common.Hash) {
	if err := db.Delete(stateIDKey(root)); err != nil {
		logger.Crit("Failed to delete state ID", "err", err)
	}
}

// ReadPersistentStateID retrieves the id of the persistent state from the database.
func ReadPersistentStateID(db KeyValueReader) uint64 {
	data, _ := db.Get(persistentStateIDKey)
	if len(data) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(data)
}

// WritePersistentStateID stores the id of the persistent state into database.
func WritePersistentStateID(db database.KeyValueWriter, number uint64) {
	var buff [8]byte
	binary.BigEndian.PutUint64(buff[:], number)
	if err := db.Put(persistentStateIDKey, buff[:]); err != nil {
		logger.Crit("Failed to store the persistent state ID", "err", err)
	}
}

// ReadTrieJournal retrieves the serialized in-memory trie nodes of layers saved at
// the last shutdown.
func ReadTrieJournal(db KeyValueReader) []byte {
	data, _ := db.Get(trieJournalKey)
	return data
}

// WriteTrieJournal stores the serialized in-memory trie nodes of layers to save at
// shutdown.
func WriteTrieJournal(db database.KeyValueWriter, journal []byte) {
	if err := db.Put(trieJournalKey, journal); err != nil {
		logger.Crit("Failed to store tries journal", "err", err)
	}
}

// DeleteTrieJournal deletes the serialized in-memory trie nodes of layers saved at
// the last shutdown.
func DeleteTrieJournal(db database.KeyValueWriter) {
	if err := db.Delete(trieJournalKey); err != nil {
		logger.Crit("Failed to remove tries journal", "err", err)
	}
}
