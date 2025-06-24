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
	"bytes"
	"context"
	"encoding/hex"
	"strconv"
	"sync"

	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/storage/database"

	"github.com/erigontech/erigon-lib/commitment"
	erigon_kv "github.com/erigontech/erigon-lib/kv"
	erigon_state "github.com/erigontech/erigon-lib/state"
)

var terminatorHexByte = byte(16) // max nibble value +1. Defines end of nibble line in the trie

var (
	stateRootToBlockNumPrefix = []byte("root")
)

type kaiaPatriciaContext struct {
	sdc             *erigon_state.SharedDomainsCommitmentContext
	pendingAccounts map[string][]byte
	pendingBranches map[string][]byte
}

func (ctx *kaiaPatriciaContext) Branch(prefix []byte) ([]byte, uint64, error) {
	if ctx.pendingBranches != nil {
		if data, ok := ctx.pendingBranches[string(prefix)]; ok {
			return data, 0, nil
		}
	}
	return ctx.sdc.Branch(prefix)
}

func (ctx *kaiaPatriciaContext) PutBranch(prefix []byte, data []byte, prevData []byte, prevStep uint64) error {
	if ctx.pendingBranches != nil {
		ctx.pendingBranches[string(prefix)] = data
	}
	return nil
}

func (ctx *kaiaPatriciaContext) Account(plainKey []byte) (*commitment.Update, error) {
	if ctx.pendingAccounts != nil {
		if data, ok := ctx.pendingAccounts[string(plainKey)]; ok {
			rawBytes := make([]byte, len(data))
			copy(rawBytes, data)
			return &commitment.Update{
				CodeHash: commitment.EmptyCodeHashArray,
				Flags:    commitment.RawBytesUpdate,
				RawBytes: rawBytes,
			}, nil
		}
	}
	return ctx.sdc.Account(plainKey)
}

func (ctx *kaiaPatriciaContext) Storage(plainKey []byte) (*commitment.Update, error) {
	// TODO-Kaia: pendingStorage
	return ctx.sdc.Storage(plainKey)
}

type FlatTrie struct {
	dbm      database.DBManager
	num      uint64
	root     common.Hash
	hphState []byte

	addr      common.Address
	isGenesis bool

	mu              sync.RWMutex
	pendingAccounts map[string][]byte
	pendingBranches map[string][]byte
}

func NewFlatTrieWithDBManager(root common.Hash, db database.DBManager, opts *TrieOpts) (*FlatTrie, error) {
	if root != (common.Hash{}) {
		var blockNum uint64
		db.WithSharedDomains(func(sd *erigon_state.SharedDomains) bool {
			val, _, err := sd.GetLatest(erigon_kv.CommitmentDomain, append(stateRootToBlockNumPrefix, root.Bytes()...))
			if err == nil {
				blockNum, err = strconv.ParseUint(string(val), 10, 64)
				if err != nil {
					panic("Failed to parse block number from stateRootToBlockNumPrefix: " + err.Error())
				}
			}
			return false
		})
		if blockNum != 0 {
			if opts != nil {
				if opts.TrieBlockNumber != 0 && opts.TrieBlockNumber != blockNum {
					panic("Trie block number mismatch: " + strconv.FormatUint(opts.TrieBlockNumber, 10) + " != " + strconv.FormatUint(blockNum, 10))
				}
			}
			return &FlatTrie{
				num:             blockNum,
				dbm:             db,
				root:            root,
				isGenesis:       false,
				pendingAccounts: make(map[string][]byte),
				pendingBranches: make(map[string][]byte),
			}, nil
		}
	}

	if opts != nil {
		return &FlatTrie{
			num:             opts.TrieBlockNumber,
			dbm:             db,
			root:            common.BytesToHash(commitment.EmptyRootHash),
			isGenesis:       opts.IsGenesis,
			pendingAccounts: make(map[string][]byte),
			pendingBranches: make(map[string][]byte),
		}, nil
	}
	return &FlatTrie{
		num:             0,
		dbm:             db,
		root:            common.BytesToHash(commitment.EmptyRootHash),
		pendingAccounts: make(map[string][]byte),
		pendingBranches: make(map[string][]byte),
	}, nil
}

func (trie *FlatTrie) getInjectedTrie(sd *erigon_state.SharedDomains) (*erigon_state.SharedDomainsCommitmentContext, *commitment.HexPatriciaHashed) {
	sdCtx := sd.GetCommitmentContext()
	injectedCtx := &kaiaPatriciaContext{
		sdc:             sdCtx,
		pendingAccounts: trie.pendingAccounts,
		pendingBranches: trie.pendingBranches,
	}

	hph := sdCtx.Trie().(*commitment.HexPatriciaHashed)
	hph.ResetContext(injectedCtx)
	hph.SetState(trie.hphState)
	return sdCtx, hph
}

func (trie *FlatTrie) TryGet(key []byte) ([]byte, error) {
	// If account trie
	if common.EmptyAddress(trie.addr) {
		return trie.getAccount(key)
	}
	panic("FlatTrie for storage not implemented")
}

func (trie *FlatTrie) getAccount(key []byte) ([]byte, error) {
	trie.mu.RLock()
	defer trie.mu.RUnlock()

	if val, ok := trie.pendingAccounts[string(key)]; ok {
		return val, nil
	}

	var result []byte
	trie.dbm.WithSharedDomains(func(sd *erigon_state.SharedDomains) bool {
		//sd.SetTxNum(trie.num)
		//sd.SetBlockNum(trie.num)
		//val, _, err := sd.GetLatest(erigon_kv.AccountsDomain, key)
		aggTx := sd.AggTx().(*erigon_state.AggregatorRoTx)
		val, _, err := aggTx.GetAsOf(sd.Tx(), erigon_kv.AccountsDomain, key, trie.num+1)
		if err == nil {
			result = val
		}
		return false
	})
	return result, nil
}

func (trie *FlatTrie) TryUpdate(key, val []byte) error {
	// If account trie
	if common.EmptyAddress(trie.addr) {
		return trie.updateAccount(key, val)
	}
	panic("FlatTrie for storage not implemented")
}

func (trie *FlatTrie) updateAccount(key, val []byte) error {
	trie.mu.Lock()
	defer trie.mu.Unlock()

	trie.pendingAccounts[string(key)] = val

	var root []byte
	var err error
	// TODO: defer hash calculation to trie.Hash() and trie.Commit().
	trie.dbm.WithSharedDomains(func(sd *erigon_state.SharedDomains) bool {
		//sd.SetTxNum(trie.num)
		//sd.SetBlockNum(trie.num)
		sdCtx, hph := trie.getInjectedTrie(sd)
		sdCtx.TouchKey(erigon_kv.AccountsDomain, string(key), val)

		root, err = sd.ComputeCommitment(context.Background(), false, trie.num, "")

		trie.root = common.BytesToHash(root)
		trie.hphState, err = hph.EncodeCurrentState(nil)
		return false
	})
	return err
}

func (trie *FlatTrie) Hash() common.Hash {
	trie.mu.RLock()
	defer trie.mu.RUnlock()

	return trie.root
}

func (trie *FlatTrie) Commit(cb LeafCallback) (common.Hash, error) { // TODO-Kaia: return hash, err
	trie.mu.Lock()
	defer trie.mu.Unlock()

	trie.dbm.WithSharedDomains(func(sd *erigon_state.SharedDomains) bool {
		// Increment block number before commit, because we're commiting state for next block.
		// For genesis block, we have to commit to block 0.
		if !trie.isGenesis {
			trie.num++
		}
		sd.SetTxNum(trie.num)
		sd.SetBlockNum(trie.num)
		for key, val := range trie.pendingAccounts {
			sd.DomainPut(erigon_kv.AccountsDomain, []byte(key), nil, val, nil, 0)
		}
		trie.pendingAccounts = make(map[string][]byte)
		for key, val := range trie.pendingBranches {
			sd.DomainPut(erigon_kv.CommitmentDomain, []byte(key), nil, val, nil, 0)
		}
		trie.pendingBranches = make(map[string][]byte)
		// Try Commit and store state
		root, err := sd.ComputeCommitment(context.Background(), true, trie.num, "")
		if err != nil {
			panic("ComputeCommitment failed: " + err.Error())
		}
		if !bytes.Equal(root, trie.root.Bytes()) {
			panic("Commit: root mismatch: " + hex.EncodeToString(root) + " != " + hex.EncodeToString(trie.root.Bytes()))
		}
		// Store mapping for stateRoot -> blockNum
		err = sd.DomainPut(erigon_kv.CommitmentDomain, stateRootToBlockNumPrefix, trie.root.Bytes(), []byte(strconv.FormatUint(trie.num, 10)), nil, 0)
		if err != nil {
			panic("Failed to store stateRoot to blockNum mapping for root: " + hex.EncodeToString(trie.root.Bytes()) + ", num: " + strconv.FormatUint(trie.num, 10) + ", err: " + err.Error())
		}
		return true
	})
	return trie.root, nil
}

func (trie *FlatTrie) CommitExt(cb LeafCallback) (common.ExtHash, error) {
	panic("not implemented")
}

func (trie *FlatTrie) NodeIterator(startKey []byte) NodeIterator {
	// Create a new iterator that wraps the HexPatriciaHashed trie
	return newFlatTrieIterator(trie, startKey)
}

// flatTrieIterator implements NodeIterator interface for FlatTrie
type flatTrieIterator struct {
	trie     *FlatTrie
	path     []byte
	hash     common.Hash
	parent   common.Hash
	err      error
	keyBuf   []byte
	valueBuf []byte
}

func newFlatTrieIterator(trie *FlatTrie, start []byte) *flatTrieIterator {
	it := &flatTrieIterator{
		trie: trie,
		path: keybytesToHex(start),
	}
	// Remove terminator byte
	if len(it.path) > 0 {
		it.path = it.path[:len(it.path)-1]
	}
	return it
}

func (it *flatTrieIterator) Hash() common.Hash {
	return it.hash
}

func (it *flatTrieIterator) Parent() common.Hash {
	return it.parent
}

func (it *flatTrieIterator) Path() []byte {
	return it.path
}

func (it *flatTrieIterator) Leaf() bool {
	return hasTerm(it.path)
}

func (it *flatTrieIterator) LeafKey() []byte {
	if !it.Leaf() {
		panic("not at leaf")
	}
	return hexToKeybytes(it.path)
}

func (it *flatTrieIterator) LeafBlob() []byte {
	if !it.Leaf() {
		panic("not at leaf")
	}
	return it.valueBuf
}

func (it *flatTrieIterator) LeafProof() [][]byte {
	if !it.Leaf() {
		panic("not at leaf")
	}
	// TODO: Implement proof generation if needed
	return nil
}

func (it *flatTrieIterator) Error() error {
	if it.err == iteratorEnd {
		return nil
	}
	return it.err
}

func (it *flatTrieIterator) Next(descend bool) bool {
	if it.err != nil {
		return false
	}

	// Get the next key-value pair from the underlying HexPatriciaHashed
	key := it.path
	if len(key) == 0 {
		key = make([]byte, 1)
	}

	val, err := it.trie.TryGet(key)
	if err != nil {
		it.err = err
		return false
	}
	if val == nil {
		it.err = iteratorEnd
		return false
	}

	// Update iterator state
	it.keyBuf = key
	it.valueBuf = val
	it.path = append(it.path, terminatorHexByte) // Mark as leaf node

	return true
}

func (it *flatTrieIterator) AddResolver(resolver database.DBManager) {
	// Not needed for FlatTrie
}

func (trie *FlatTrie) GetKey(key []byte) []byte {
	panic("not implemented")
}

func (trie *FlatTrie) HashExt() common.ExtHash {
	panic("not implemented")
}

func (trie *FlatTrie) TryUpdateWithKeys(key, hashKey, hexKey, value []byte) error {
	return trie.TryUpdate(key, value)
}

func (trie *FlatTrie) TryDelete(key []byte) error {
	if common.EmptyAddress(trie.addr) {
		return trie.deleteAccount(key)
	}
	panic("FlatTrie for storage not implemented")
}

func (trie *FlatTrie) deleteAccount(key []byte) error {
	trie.mu.Lock()
	defer trie.mu.Unlock()

	trie.pendingAccounts[string(key)] = nil

	var root []byte
	var err error
	// TODO: defer hash calculation to trie.Hash() and trie.Commit().
	trie.dbm.WithSharedDomains(func(sd *erigon_state.SharedDomains) bool {
		sdCtx, hph := trie.getInjectedTrie(sd)
		sdCtx.TouchKey(erigon_kv.AccountsDomain, string(key), nil)

		root, err = sd.ComputeCommitment(context.Background(), false, 0, "")

		trie.root = common.BytesToHash(root)
		trie.hphState, err = hph.EncodeCurrentState(nil)
		return false
	})
	return err
}

func (trie *FlatTrie) Copy() *FlatTrie {
	return &FlatTrie{
		dbm:      trie.dbm,
		num:      trie.num,
		addr:     trie.addr,
		hphState: trie.hphState,
		mu:       sync.RWMutex{},
	}
}

func (trie *FlatTrie) Prove(key []byte, fromLevel uint, proofDb database.DBManager) error {
	panic("not implemented")
}
