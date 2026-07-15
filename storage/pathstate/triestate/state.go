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
// This file is derived from trie/triestate/state.go (go-ethereum v1.13.15),
// trimmed to only the types required by pathdb (state-history rollback support
// has been removed).

package triestate

import (
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/storage/pathstate/trienode"
)

// Trie is an Ethereum state trie, can be implemented by Ethereum Merkle Patricia
// tree or Verkle tree.
type Trie interface {
	// Get returns the value for key stored in the trie.
	Get(key []byte) ([]byte, error)

	// Update associates key with value in the trie.
	Update(key, value []byte) error

	// Delete removes any existing value for key from the trie.
	Delete(key []byte) error

	// Commit the trie and returns a set of dirty nodes generated along with
	// the new root hash.
	Commit(collectLeaf bool) (common.Hash, *trienode.NodeSet, error)
}

// TrieLoader wraps functions to load tries.
type TrieLoader interface {
	// OpenTrie opens the main account trie.
	OpenTrie(root common.Hash) (Trie, error)

	// OpenStorageTrie opens the storage trie of an account.
	OpenStorageTrie(stateRoot common.Hash, addrHash, root common.Hash) (Trie, error)
}

// Set represents a collection of mutated states during a state transition.
// The value refers to the original content of state before the transition
// is made. Nil means that the state was not present previously.
type Set struct {
	Accounts   map[common.Address][]byte                 // Mutated account set, nil means the account was not present
	Storages   map[common.Address]map[common.Hash][]byte // Mutated storage set, nil means the slot was not present
	Incomplete map[common.Address]struct{}               // Indicator whether the storage is incomplete due to large deletion
	size       common.StorageSize                        // Approximate size of set
}

// New constructs the state set with provided data.
func New(accounts map[common.Address][]byte, storages map[common.Address]map[common.Hash][]byte, incomplete map[common.Address]struct{}) *Set {
	return &Set{
		Accounts:   accounts,
		Storages:   storages,
		Incomplete: incomplete,
	}
}

// Size returns the approximate memory size occupied by the set.
func (s *Set) Size() common.StorageSize {
	if s.size != 0 {
		return s.size
	}
	for _, account := range s.Accounts {
		s.size += common.StorageSize(common.AddressLength + len(account))
	}
	for _, slots := range s.Storages {
		for _, val := range slots {
			s.size += common.StorageSize(common.HashLength + len(val))
		}
		s.size += common.StorageSize(common.AddressLength)
	}
	s.size += common.StorageSize(common.AddressLength * len(s.Incomplete))
	return s.size
}
