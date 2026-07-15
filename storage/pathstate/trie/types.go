// Modifications Copyright 2026 The Kaia Authors
// Copyright 2023 The go-ethereum Authors
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
// This file collects the local type definitions that in go-ethereum live in
// triedb/database (the database/Reader interfaces) and core/types
// (EmptyRootHash, TrieRootHash). They are defined here so the ported trie
// package is self-contained.

package trie

import (
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/log"
)

var logger = log.NewModuleLogger(log.StorageStateDB)

// EmptyRootHash is the known root hash of an empty merkle trie.
var EmptyRootHash = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

// TrieRootHash returns the canonical root hash for a trie, converting the zero
// hash into the empty-trie root hash.
func TrieRootHash(root common.Hash) common.Hash {
	if root == (common.Hash{}) {
		return EmptyRootHash
	}
	return root
}

// database is the read-only node source a trie sits on top of. In go-ethereum
// this is triedb/database.Database; here it is a local single-method interface
// over the exported Reader type, so an external frontend (e.g. a pathdb
// wrapper) can satisfy it structurally without importing this package's
// internals.
type database interface {
	// Reader returns a node reader associated with the specific state.
	Reader(root common.Hash) (Reader, error)
}

// Reader wraps the Node method of a backing trie store.
type Reader interface {
	// Node retrieves the trie node blob with the provided trie identifier,
	// node path and the corresponding node hash. No error will be returned
	// if the node is not found.
	Node(owner common.Hash, path []byte, hash common.Hash) ([]byte, error)
}
