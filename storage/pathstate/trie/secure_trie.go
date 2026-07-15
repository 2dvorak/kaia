// Modifications Copyright 2026 The Kaia Authors
// Copyright 2015 The go-ethereum Authors
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
// This file is derived from trie/secure_trie.go (go-ethereum v1.13.15). The
// go-ethereum typed account/storage methods (which assume core/types account
// serialization and RLP re-encoding of values) are intentionally NOT ported;
// Kaia's account serialization differs. Instead StateTrie exposes a generic
// secure-key byte API: keys are hashed with keccak256, values are stored and
// returned verbatim, and no key preimages are recorded.

package trie

import (
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/storage/pathstate/trienode"
)

// SecureTrie is the old name of StateTrie.
// Deprecated: use StateTrie.
type SecureTrie = StateTrie

// NewSecure creates a new StateTrie.
// Deprecated: use NewStateTrie.
func NewSecure(stateRoot common.Hash, owner common.Hash, root common.Hash, db database) (*SecureTrie, error) {
	id := &ID{
		StateRoot: stateRoot,
		Owner:     owner,
		Root:      root,
	}
	return NewStateTrie(id, db)
}

// StateTrie wraps a trie with key hashing. All access operations hash the key
// using keccak256 before touching the underlying trie. This prevents calling
// code from creating long chains of nodes that increase the access time.
//
// Unlike go-ethereum's StateTrie, this port stores and returns values verbatim
// (no RLP re-encoding) and records no key preimages.
//
// StateTrie is not safe for concurrent use.
type StateTrie struct {
	trie       Trie
	hashKeyBuf [common.HashLength]byte
}

// NewStateTrie creates a trie with an existing root node from a backing database.
//
// If root is the zero hash or the sha3 hash of an empty string, the trie is
// initially empty. Otherwise, NewStateTrie returns a MissingNodeError if the
// root node cannot be found. It panics if db is nil.
func NewStateTrie(id *ID, db database) (*StateTrie, error) {
	if db == nil {
		panic("trie.NewStateTrie called without a database")
	}
	trie, err := New(id, db)
	if err != nil {
		return nil, err
	}
	return &StateTrie{trie: *trie}, nil
}

// Get returns the value stored under key. The key is hashed with keccak256 and
// the stored value is returned verbatim. The value bytes must not be modified
// by the caller. If the key is absent, nil is returned. If a trie node is not
// found in the database, a MissingNodeError is returned.
func (t *StateTrie) Get(key []byte) ([]byte, error) {
	return t.trie.Get(t.hashKey(key))
}

// Update stores value under key. The key is hashed with keccak256 and the value
// is stored verbatim (no RLP re-encoding). If value has length zero, any
// existing value is deleted and subsequent calls to Get will return nil. The
// value bytes must not be modified by the caller while they are stored in the
// trie. If a node is not found in the database, a MissingNodeError is returned.
func (t *StateTrie) Update(key, value []byte) error {
	return t.trie.Update(t.hashKey(key), value)
}

// Delete removes any existing value for key from the trie.
// If a node is not found in the database, a MissingNodeError is returned.
func (t *StateTrie) Delete(key []byte) error {
	return t.trie.Delete(t.hashKey(key))
}

// GetKey returns the keccak256 preimage of a hashed key. Preimage recording has
// been removed from this port, so this always returns nil.
func (t *StateTrie) GetKey(shaKey []byte) []byte {
	return nil
}

// Hash returns the root hash of StateTrie. It does not write to the
// database and can be used even if the trie doesn't have one.
func (t *StateTrie) Hash() common.Hash {
	return t.trie.Hash()
}

// Commit collects all dirty nodes in the trie and replaces them with the
// corresponding node hash. All collected nodes (including dirty leaves if
// collectLeaf is true) will be encapsulated into a nodeset for return.
// The returned nodeset can be nil if the trie is clean (nothing to commit).
// Once the trie is committed, it's not usable anymore. A new trie must
// be created with new root and updated trie database for following usage.
func (t *StateTrie) Commit(collectLeaf bool) (common.Hash, *trienode.NodeSet, error) {
	return t.trie.Commit(collectLeaf)
}

// Copy returns a copy of StateTrie.
func (t *StateTrie) Copy() *StateTrie {
	return &StateTrie{trie: *t.trie.Copy()}
}

// NodeIterator returns an iterator that returns nodes of the underlying trie.
// Iteration starts at the key after the given start key.
func (t *StateTrie) NodeIterator(start []byte) (NodeIterator, error) {
	return t.trie.NodeIterator(start)
}

// hashKey returns the hash of key as an ephemeral buffer.
// The caller must not hold onto the return value because it will become
// invalid on the next call to hashKey.
func (t *StateTrie) hashKey(key []byte) []byte {
	h := newHasher(false)
	h.sha.Reset()
	h.sha.Write(key)
	h.sha.Read(t.hashKeyBuf[:])
	returnHasherToPool(h)
	return t.hashKeyBuf[:]
}
