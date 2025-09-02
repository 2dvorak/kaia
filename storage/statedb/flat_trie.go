// Copyright 2025 The Kaia Authors
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
	"fmt"
	"os"

	"github.com/erigontech/erigon-lib/kaiatrie"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/rlp"
	"github.com/kaiachain/kaia/storage/database"
)

var (
	singletonDM *kaiatrie.DomainsManager
)

func getDm() *kaiatrie.DomainsManager {
	if singletonDM == nil {
		tmpdir, err := os.MkdirTemp(os.TempDir(), "kaiatrie")
		if err != nil {
			logger.Crit("Failed to create temporary directory", "err", err)
		}
		singletonDM, err = kaiatrie.NewTemporaryDomainsManager(tmpdir)
		if err != nil {
			logger.Crit("Failed to create temporary domains manager", "err", err)
		}
		logger.Warn("Created temporary directory for FlatAccountTrie", "dir", tmpdir)
	}
	return singletonDM
}

type FlatAccountTrie struct {
	dt *kaiatrie.DeferredAccountTrie
}

func NewFlatAccountTrie(opts *TrieOpts) (*FlatAccountTrie, error) {
	dt := kaiatrie.NewDeferredAccountTrie(getDm(), opts.BaseBlockNumber, opts.CommitGenesis, kaiatrie.ModeRawBytes)
	return &FlatAccountTrie{dt: dt}, nil
}

func (t *FlatAccountTrie) GetKey(key []byte) []byte {
	logger.Error("FlatAccountTrie.GetKey is not implemented")
	return nil
}

func (t *FlatAccountTrie) TryGet(key []byte) ([]byte, error) {
	return t.dt.Get(key)
}

func (t *FlatAccountTrie) TryUpdate(key, value []byte) error {
	return t.dt.Update(key, value)
}

func (t *FlatAccountTrie) TryUpdateWithKeys(key, hashKey, hexKey, value []byte) error {
	return t.TryUpdate(key, value)
}

func (t *FlatAccountTrie) TryDelete(key []byte) error {
	return t.dt.Delete(key)
}

func (t *FlatAccountTrie) Hash() common.Hash {
	h, err := t.dt.Hash()
	if err != nil {
		logger.Error("Failed to hash account trie", "err", err)
		return common.Hash{}
	}
	return common.BytesToHash(h[:])
}

func (t *FlatAccountTrie) HashExt() common.ExtHash {
	return t.Hash().ExtendZero()
}

func (t *FlatAccountTrie) Commit(onleaf LeafCallback) (common.Hash, error) {
	h, err := t.dt.Commit()
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(h[:]), nil
}

func (t *FlatAccountTrie) CommitExt(onleaf LeafCallback) (common.ExtHash, error) {
	h, err := t.Commit(onleaf)
	if err != nil {
		return common.ExtHash{}, err
	}
	return h.ExtendZero(), nil
}

func (t *FlatAccountTrie) NodeIterator(start []byte) NodeIterator {
	logger.Error("FlatAccountTrie.NodeIterator is not implemented")
	return &FlatNodeIterator{}
}

func (t *FlatAccountTrie) Prove(key []byte, fromLevel uint, proofDb database.DBManager) error {
	logger.Error("FlatAccountTrie.Prove is not implemented")
	return errors.New("not implemented")
}

type FlatStorageTrie struct {
	dt *kaiatrie.DeferredStorageTrie
}

func NewFlatStorageTrie(addr common.Address, opts *TrieOpts) (*FlatStorageTrie, error) {
	dt := kaiatrie.NewDeferredStorageTrie(getDm(), addr.Bytes(), opts.BaseBlockNumber, opts.CommitGenesis, kaiatrie.ModeRawBytes)
	return &FlatStorageTrie{dt: dt}, nil
}

func (t *FlatStorageTrie) GetKey(key []byte) []byte {
	logger.Error("FlatStorageTrie.GetKey is not implemented")
	return nil
}

func (t *FlatStorageTrie) TryGet(key []byte) ([]byte, error) {
	return t.dt.Get(key)
}

func (t *FlatStorageTrie) TryUpdate(key, value []byte) error {
	kind, slot, _, err := rlp.Split(value)
	if err != nil {
		return err
	}
	if kind != rlp.String {
		return fmt.Errorf("expected string, got %d", kind)
	}
	return t.dt.Update(key, slot)
}

func (t *FlatStorageTrie) TryUpdateWithKeys(key, hashKey, hexKey, value []byte) error {
	return t.TryUpdate(key, value)
}

func (t *FlatStorageTrie) TryDelete(key []byte) error {
	return t.dt.Delete(key)
}

func (t *FlatStorageTrie) Hash() common.Hash {
	h, err := t.dt.Hash()
	if err != nil {
		logger.Error("Failed to hash storage trie", "err", err)
		return common.Hash{}
	}
	return common.BytesToHash(h[:])
}

func (t *FlatStorageTrie) HashExt() common.ExtHash {
	return t.Hash().ExtendZero()
}

func (t *FlatStorageTrie) Commit(onleaf LeafCallback) (common.Hash, error) {
	h, err := t.dt.Commit()
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(h[:]), nil
}

func (t *FlatStorageTrie) CommitExt(onleaf LeafCallback) (common.ExtHash, error) {
	h, err := t.Commit(onleaf)
	if err != nil {
		return common.ExtHash{}, err
	}
	return h.ExtendZero(), nil
}

func (t *FlatStorageTrie) NodeIterator(start []byte) NodeIterator {
	logger.Error("FlatStorageTrie.NodeIterator is not implemented")
	return &FlatNodeIterator{}
}

func (t *FlatStorageTrie) Prove(key []byte, fromLevel uint, proofDb database.DBManager) error {
	logger.Error("FlatStorageTrie.Prove is not implemented")
	return errors.New("not implemented")
}

// TODO: Fill this.
type FlatNodeIterator struct {
}

func (t *FlatNodeIterator) Next(bool) bool {
	return false
}

func (t *FlatNodeIterator) Error() error {
	return nil
}

func (t *FlatNodeIterator) Hash() common.Hash {
	return common.Hash{}
}

func (t *FlatNodeIterator) Parent() common.Hash {
	return common.Hash{}
}

func (t *FlatNodeIterator) Path() []byte {
	return nil
}

func (t *FlatNodeIterator) Leaf() bool {
	return false
}

func (t *FlatNodeIterator) LeafKey() []byte {
	return nil
}

func (t *FlatNodeIterator) LeafBlob() []byte {
	return nil
}

func (t *FlatNodeIterator) LeafProof() [][]byte {
	return nil
}

func (t *FlatNodeIterator) AddResolver(database.DBManager) {
}
