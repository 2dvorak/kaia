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

package statedb

import (
	"errors"

	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/crypto"
	"github.com/kaiachain/kaia/storage/database"
	"github.com/kaiachain/kaia/storage/pathstate"
	pathtrie "github.com/kaiachain/kaia/storage/pathstate/trie"
	"github.com/kaiachain/kaia/storage/pathstate/trienode"
)

// PathAccountTrie is the account trie backed by the path-based state scheme
// (PBSS). It keeps genuine Merkle Patricia trie semantics, so the computed
// roots match the canonical hash-based state roots; only the node persistence
// differs (path-keyed, layered).
type PathAccountTrie struct {
	db   *pathstate.Database
	trie *pathtrie.StateTrie

	// parentRoot is the state root this trie was opened at; it addresses the
	// parent layer when the commit result is pushed into the path database.
	parentRoot common.Hash

	// commitGenesis additionally flattens the committed layer into the
	// persistent disk layer so genesis survives without a journal.
	commitGenesis bool

	// baseNum is the block number of parentRoot (from the root index);
	// parentKnown records whether it could be resolved. The committed block
	// is baseNum+1 (or 0 for genesis).
	baseNum     uint64
	parentKnown bool

	// storageNodes collects the node sets committed by this block's storage
	// tries; they are merged with the account node set on Commit.
	storageNodes []*trienode.NodeSet

	// history collects this block's value changes when archive mode is
	// enabled (nil otherwise); flushed on Commit.
	history *pathstate.BlockHistory
}

func NewPathAccountTrie(db *pathstate.Database, root common.Hash, opts *TrieOpts) (*PathAccountTrie, error) {
	tr, err := pathtrie.NewStateTrie(pathtrie.StateTrieID(pathtrie.TrieRootHash(root)), db)
	if err != nil {
		return nil, err
	}
	parentRoot := pathtrie.TrieRootHash(root)
	baseNum, parentKnown := db.BlockOfRoot(parentRoot)
	if parentRoot == pathtrie.EmptyRootHash {
		parentKnown = true // genesis parent
	}
	t := &PathAccountTrie{
		db:            db,
		trie:          tr,
		parentRoot:    parentRoot,
		commitGenesis: opts != nil && opts.CommitGenesis,
		baseNum:       baseNum,
		parentKnown:   parentKnown,
	}
	if db.ArchiveEnabled() {
		t.history = pathstate.NewBlockHistory()
	}
	return t, nil
}

func (t *PathAccountTrie) GetKey(key []byte) []byte {
	// Preimages are not recorded for the path trie.
	return nil
}

func (t *PathAccountTrie) TryGet(key []byte) ([]byte, error) {
	return t.trie.Get(key)
}

func (t *PathAccountTrie) TryUpdate(key, value []byte) error {
	if t.history != nil {
		t.history.AddAccount(crypto.Keccak256Hash(key), value)
	}
	return t.trie.Update(key, value)
}

func (t *PathAccountTrie) TryUpdateWithKeys(key, hashKey, hexKey, value []byte) error {
	return t.TryUpdate(key, value)
}

func (t *PathAccountTrie) TryDelete(key []byte) error {
	if t.history != nil {
		addrHash := crypto.Keccak256Hash(key)
		t.history.AddAccount(addrHash, nil)
		// Account deletion wipes its storage; record a barrier so historic
		// reads of a later re-created account do not resurrect old slots.
		t.history.AddWipe(addrHash)
	}
	return t.trie.Delete(key)
}

func (t *PathAccountTrie) Hash() common.Hash {
	return t.trie.Hash()
}

func (t *PathAccountTrie) HashExt() common.ExtHash {
	return t.Hash().ExtendZero()
}

// Commit hashes the trie, merges the dirty nodes of the account trie and all
// storage tries committed for this block, and pushes them into the path
// database as one new layer on top of the parent state.
func (t *PathAccountTrie) Commit(onleaf LeafCallback) (common.Hash, error) {
	root, nodes, err := t.trie.Commit(false)
	if err != nil {
		return common.Hash{}, err
	}
	merged := trienode.NewMergedNodeSet()
	if nodes != nil {
		if err := merged.Merge(nodes); err != nil {
			return common.Hash{}, err
		}
	}
	for _, ns := range t.storageNodes {
		if ns == nil {
			continue
		}
		if err := merged.Merge(ns); err != nil {
			return common.Hash{}, err
		}
	}
	t.storageNodes = nil

	if t.commitGenesis && t.db.Initialized() {
		// The genesis state is already present (the init path can re-commit
		// genesis); the layer tree cannot take a second genesis layer.
		return root, nil
	}
	if root == t.parentRoot {
		// No state transition; there is no layer to add.
		return root, nil
	}
	block := t.baseNum + 1
	if t.commitGenesis {
		block = 0
	} else if err := t.db.CheckArchiveConsistency(t.parentRoot, t.parentKnown); err != nil {
		return common.Hash{}, err
	}
	if err := t.db.Update(root, t.parentRoot, block, merged); err != nil {
		return common.Hash{}, err
	}
	if t.history != nil {
		if err := t.db.WriteBlockHistory(block, t.history); err != nil {
			return common.Hash{}, err
		}
		t.history = pathstate.NewBlockHistory()
	}
	if t.commitGenesis {
		if err := t.db.Commit(root); err != nil {
			return common.Hash{}, err
		}
	}
	return root, nil
}

func (t *PathAccountTrie) CommitExt(onleaf LeafCallback) (common.ExtHash, error) {
	root, err := t.Commit(onleaf)
	if err != nil {
		return common.ExtHash{}, err
	}
	return root.ExtendZero(), nil
}

func (t *PathAccountTrie) NodeIterator(start []byte) NodeIterator {
	it, err := t.trie.NodeIterator(start)
	if err != nil {
		logger.Error("Failed to create PathAccountTrie.NodeIterator", "err", err)
		return &EmptyNodeIterator{}
	}
	return &pathNodeIterator{it: it}
}

func (t *PathAccountTrie) Prove(key []byte, fromLevel uint, proofDb database.DBManager) error {
	logger.Error("PathAccountTrie.Prove is not implemented")
	return errors.New("not implemented")
}

// Copy returns a copy sharing the path database handle and the pending
// storage node sets registry; the trie itself is independently copied.
// The copy does NOT record archive history: copies serve tracers and
// read-only forks, and the original trie is the committing instance.
func (t *PathAccountTrie) Copy() *PathAccountTrie {
	return &PathAccountTrie{
		db:            t.db,
		trie:          t.trie.Copy(),
		parentRoot:    t.parentRoot,
		commitGenesis: t.commitGenesis,
		baseNum:       t.baseNum,
		parentKnown:   t.parentKnown,
		storageNodes:  append([]*trienode.NodeSet{}, t.storageNodes...),
	}
}

// PathStorageTrie is a contract storage trie backed by the path-based state
// scheme. Its committed node set is handed to the parent PathAccountTrie,
// which pushes one aggregated layer per block into the path database.
type PathStorageTrie struct {
	trie  *pathtrie.StateTrie
	at    *PathAccountTrie
	addr  common.Address
	owner common.Hash // keccak256(addr), the trie owner and history key
}

func NewPathStorageTrie(db *pathstate.Database, addr common.Address, root common.Hash, opts *TrieOpts) (*PathStorageTrie, error) {
	if opts == nil || opts.PathAccountTrie == nil {
		return nil, errors.New("path account trie is not set")
	}
	at := opts.PathAccountTrie
	owner := crypto.Keccak256Hash(addr.Bytes())
	tr, err := pathtrie.NewStateTrie(pathtrie.StorageTrieID(at.parentRoot, owner, pathtrie.TrieRootHash(root)), db)
	if err != nil {
		return nil, err
	}
	return &PathStorageTrie{trie: tr, at: at, addr: addr, owner: owner}, nil
}

func (t *PathStorageTrie) GetKey(key []byte) []byte {
	return nil
}

func (t *PathStorageTrie) TryGet(key []byte) ([]byte, error) {
	return t.trie.Get(key)
}

func (t *PathStorageTrie) TryUpdate(key, value []byte) error {
	if t.at.history != nil {
		t.at.history.AddStorage(t.owner, crypto.Keccak256Hash(key), value)
	}
	return t.trie.Update(key, value)
}

func (t *PathStorageTrie) TryUpdateWithKeys(key, hashKey, hexKey, value []byte) error {
	return t.TryUpdate(key, value)
}

func (t *PathStorageTrie) TryDelete(key []byte) error {
	if t.at.history != nil {
		t.at.history.AddStorage(t.owner, crypto.Keccak256Hash(key), nil)
	}
	return t.trie.Delete(key)
}

func (t *PathStorageTrie) Hash() common.Hash {
	return t.trie.Hash()
}

func (t *PathStorageTrie) HashExt() common.ExtHash {
	return t.Hash().ExtendZero()
}

// Commit hashes the storage trie and registers its dirty nodes with the parent
// account trie; the actual database update happens in PathAccountTrie.Commit.
func (t *PathStorageTrie) Commit(onleaf LeafCallback) (common.Hash, error) {
	root, nodes, err := t.trie.Commit(false)
	if err != nil {
		return common.Hash{}, err
	}
	if nodes != nil {
		t.at.storageNodes = append(t.at.storageNodes, nodes)
	}
	return root, nil
}

func (t *PathStorageTrie) CommitExt(onleaf LeafCallback) (common.ExtHash, error) {
	root, err := t.Commit(onleaf)
	if err != nil {
		return common.ExtHash{}, err
	}
	return root.ExtendZero(), nil
}

func (t *PathStorageTrie) NodeIterator(start []byte) NodeIterator {
	it, err := t.trie.NodeIterator(start)
	if err != nil {
		logger.Error("Failed to create PathStorageTrie.NodeIterator", "err", err)
		return &EmptyNodeIterator{}
	}
	return &pathNodeIterator{it: it}
}

func (t *PathStorageTrie) Prove(key []byte, fromLevel uint, proofDb database.DBManager) error {
	logger.Error("PathStorageTrie.Prove is not implemented")
	return errors.New("not implemented")
}

// Copy returns a copy sharing the parent account trie reference; committing
// both the original and the copy would register the node set twice, so copies
// are only safe for read access (mirrors the FlatStorageTrie caveat).
func (t *PathStorageTrie) Copy() *PathStorageTrie {
	return &PathStorageTrie{trie: t.trie.Copy(), at: t.at, addr: t.addr, owner: t.owner}
}

// pathNodeIterator adapts the path trie package's node iterator to Kaia's
// statedb.NodeIterator interface.
type pathNodeIterator struct {
	it pathtrie.NodeIterator
}

func (n *pathNodeIterator) Next(descend bool) bool {
	return n.it.Next(descend)
}

func (n *pathNodeIterator) Error() error {
	return n.it.Error()
}

func (n *pathNodeIterator) Hash() common.Hash {
	return n.it.Hash()
}

func (n *pathNodeIterator) Parent() common.Hash {
	return n.it.Parent()
}

func (n *pathNodeIterator) Path() []byte {
	return n.it.Path()
}

func (n *pathNodeIterator) Leaf() bool {
	return n.it.Leaf()
}

func (n *pathNodeIterator) LeafKey() []byte {
	return n.it.LeafKey()
}

func (n *pathNodeIterator) LeafBlob() []byte {
	return n.it.LeafBlob()
}

func (n *pathNodeIterator) LeafProof() [][]byte {
	return n.it.LeafProof()
}

func (n *pathNodeIterator) AddResolver(database.DBManager) {
	// not supported
}
