// Modifications Copyright 2026 The Kaia Authors
// Copyright 2018 The go-ethereum Authors
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
// This file is derived from core/rawdb/schema.go (go-ethereum v1.13.15),
// keeping only the path-based state scheme key layout.

package rawdb

import (
	"github.com/kaiachain/kaia/common"
)

// PathScheme is the new path-based state scheme with which trie nodes are stored
// in the disk with node path as the database key. This scheme will only store one
// version of state data in the disk, which means that the state pruning operation
// is native. At the same time, this scheme will put adjacent trie nodes in the same
// area of the disk with good data locality property. But this scheme needs to rely
// on extra state diffs to survive deep reorg.
const PathScheme = "path"

var (
	// persistentStateIDKey tracks the id of latest stored state(for path-based only).
	persistentStateIDKey = []byte("LastStateID")

	// trieJournalKey tracks the in-memory trie node layers across restarts.
	trieJournalKey = []byte("TrieJournal")

	trieNodeAccountPrefix = []byte("A") // trieNodeAccountPrefix + hexPath -> trie node
	trieNodeStoragePrefix = []byte("O") // trieNodeStoragePrefix + accountHash + hexPath -> trie node
	stateIDPrefix         = []byte("L") // stateIDPrefix + state root -> state id
)

// stateIDKey = stateIDPrefix + root (32 bytes)
func stateIDKey(root common.Hash) []byte {
	return append(stateIDPrefix, root.Bytes()...)
}

// accountTrieNodeKey = trieNodeAccountPrefix + nodePath.
func accountTrieNodeKey(path []byte) []byte {
	return append(trieNodeAccountPrefix, path...)
}

// storageTrieNodeKey = trieNodeStoragePrefix + accountHash + nodePath.
func storageTrieNodeKey(accountHash common.Hash, path []byte) []byte {
	buf := make([]byte, len(trieNodeStoragePrefix)+common.HashLength+len(path))
	n := copy(buf, trieNodeStoragePrefix)
	n += copy(buf[n:], accountHash.Bytes())
	copy(buf[n:], path)
	return buf
}
