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
	"fmt"

	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/crypto"
	"github.com/kaiachain/kaia/storage/database"
	"github.com/kaiachain/kaia/storage/pathstate"
)

// errHistoricReadOnly is returned by any mutating operation on historic tries.
var errHistoricReadOnly = errors.New("historic path trie is read-only")

// HistoricPathTrie serves account reads for a historical state that is no
// longer present in the path database's layer tree, using the archive value
// history instead of trie nodes. It is strictly read-only: Hash returns the
// root it was opened with, and all mutations fail.
type HistoricPathTrie struct {
	db    *pathstate.Database
	root  common.Hash
	block uint64
}

func NewHistoricPathTrie(db *pathstate.Database, root common.Hash, opts *TrieOpts) (*HistoricPathTrie, error) {
	block, ok := db.BlockOfRoot(root)
	if !ok {
		return nil, fmt.Errorf("historic state unavailable: no block index for root %x", root)
	}
	return &HistoricPathTrie{db: db, root: root, block: block}, nil
}

func (t *HistoricPathTrie) Block() uint64 { return t.block }

func (t *HistoricPathTrie) GetKey(key []byte) []byte { return nil }

func (t *HistoricPathTrie) TryGet(key []byte) ([]byte, error) {
	return t.db.HistoricAccount(crypto.Keccak256Hash(key), t.block)
}

func (t *HistoricPathTrie) TryUpdate(key, value []byte) error {
	return errHistoricReadOnly
}

func (t *HistoricPathTrie) TryUpdateWithKeys(key, hashKey, hexKey, value []byte) error {
	return errHistoricReadOnly
}

func (t *HistoricPathTrie) TryDelete(key []byte) error {
	return errHistoricReadOnly
}

func (t *HistoricPathTrie) Hash() common.Hash {
	return t.root
}

func (t *HistoricPathTrie) HashExt() common.ExtHash {
	return t.root.ExtendZero()
}

func (t *HistoricPathTrie) Commit(onleaf LeafCallback) (common.Hash, error) {
	return common.Hash{}, errHistoricReadOnly
}

func (t *HistoricPathTrie) CommitExt(onleaf LeafCallback) (common.ExtHash, error) {
	return common.ExtHash{}, errHistoricReadOnly
}

func (t *HistoricPathTrie) NodeIterator(start []byte) NodeIterator {
	logger.Error("HistoricPathTrie.NodeIterator is not supported")
	return &EmptyNodeIterator{}
}

func (t *HistoricPathTrie) Prove(key []byte, fromLevel uint, proofDb database.DBManager) error {
	return errors.New("not implemented")
}

// HistoricStorageTrie serves storage-slot reads for a historical state from
// the archive value history. Read-only, like HistoricPathTrie.
type HistoricStorageTrie struct {
	db    *pathstate.Database
	owner common.Hash // keccak256(address)
	root  common.Hash // storage root as recorded in the historic account
	block uint64
}

func NewHistoricStorageTrie(db *pathstate.Database, addr common.Address, root common.Hash, opts *TrieOpts) (*HistoricStorageTrie, error) {
	if opts == nil || opts.HistoricAccountTrie == nil {
		return nil, errors.New("historic account trie is not set")
	}
	return &HistoricStorageTrie{
		db:    db,
		owner: crypto.Keccak256Hash(addr.Bytes()),
		root:  root,
		block: opts.HistoricAccountTrie.block,
	}, nil
}

func (t *HistoricStorageTrie) GetKey(key []byte) []byte { return nil }

func (t *HistoricStorageTrie) TryGet(key []byte) ([]byte, error) {
	return t.db.HistoricStorage(t.owner, crypto.Keccak256Hash(key), t.block)
}

func (t *HistoricStorageTrie) TryUpdate(key, value []byte) error {
	return errHistoricReadOnly
}

func (t *HistoricStorageTrie) TryUpdateWithKeys(key, hashKey, hexKey, value []byte) error {
	return errHistoricReadOnly
}

func (t *HistoricStorageTrie) TryDelete(key []byte) error {
	return errHistoricReadOnly
}

func (t *HistoricStorageTrie) Hash() common.Hash {
	return t.root
}

func (t *HistoricStorageTrie) HashExt() common.ExtHash {
	return t.root.ExtendZero()
}

func (t *HistoricStorageTrie) Commit(onleaf LeafCallback) (common.Hash, error) {
	return common.Hash{}, errHistoricReadOnly
}

func (t *HistoricStorageTrie) CommitExt(onleaf LeafCallback) (common.ExtHash, error) {
	return common.ExtHash{}, errHistoricReadOnly
}

func (t *HistoricStorageTrie) NodeIterator(start []byte) NodeIterator {
	logger.Error("HistoricStorageTrie.NodeIterator is not supported")
	return &EmptyNodeIterator{}
}

func (t *HistoricStorageTrie) Prove(key []byte, fromLevel uint, proofDb database.DBManager) error {
	return errors.New("not implemented")
}
