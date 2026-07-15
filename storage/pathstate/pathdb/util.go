// Modifications Copyright 2026 The Kaia Authors
//
// This file provides pathdb-local helpers that in go-ethereum are supplied by
// core/types (EmptyRootHash / TrieRootHash) and the module logger. They are
// defined here so the pathdb package stays self-contained.

package pathdb

import (
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/log"
)

var logger = log.NewModuleLogger(log.StorageStateDB)

// emptyRootHash is the known root hash of an empty merkle trie.
var emptyRootHash = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

// trieRootHash returns the canonical root hash for a trie, converting the zero
// hash into the empty-trie root hash.
func trieRootHash(root common.Hash) common.Hash {
	if root == (common.Hash{}) {
		return emptyRootHash
	}
	return root
}
