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
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"

	"github.com/kaiachain/kaia/blockchain/types"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/rlp"
	"github.com/kaiachain/kaia/storage/database"

	"github.com/erigontech/erigon-lib/commitment"
	erigon_kv "github.com/erigontech/erigon-lib/kv"
	erigon_state "github.com/erigontech/erigon-lib/state"
)

var terminatorHexByte = byte(16) // max nibble value +1. Defines end of nibble line in the trie

var (
	accountRootToBlockNumPrefix = []byte("ar")
	storageRootToBlockNumPrefix = []byte("sr")
)

type kaiaPatriciaContext struct {
	sdc             *erigon_state.SharedDomainsCommitmentContext
	pendingAccounts map[string][]byte
	pendingStorage  map[string][]byte
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
	if ctx.pendingStorage != nil {
		if data, ok := ctx.pendingStorage[string(plainKey)]; ok {
			fmt.Printf("pendingStorage: %x, %x\n", plainKey, data)
			u := &commitment.Update{
				StorageLen: len(data),
				Flags:      commitment.DeleteUpdate,
			}
			if len(data) > 0 {
				u.Flags = commitment.StorageUpdate
				copy(u.Storage[:u.StorageLen], data)
			}
			return u, nil
		}
	}
	return ctx.sdc.Storage(plainKey)
}

type FlatTrie struct {
	dbm      database.DBManager
	num      uint64
	root     common.Hash
	hphState []byte

	addr      *common.Address
	isGenesis bool

	mu              sync.RWMutex
	pendingAccounts map[string][]byte
	pendingStorage  map[string][]byte
	pendingBranches map[string][]byte
}

// TODO: opts: FlatTrieCommit, FlatTrieIsGenesis + add comments
// TODO: if root == empty or root == {00..}, that means it's a new trie, we start from empty trie (not block 0)
// so we should not allow any get, before commit.
func NewFlatTrieWithDBManager(root common.Hash, db database.DBManager, addr *common.Address, opts *TrieOpts) (ft *FlatTrie, err error) {
	// TODO: tidy up these if blocks
	if addr != nil {
		var val []byte
		db.WithSharedDomains(func(sd *erigon_state.SharedDomains) bool {
			val, _, err = sd.GetLatest(erigon_kv.AccountsDomain, addr.Bytes())
			if err != nil {
				panic("Failed to get account for address: " + addr.Hex() + ", err: " + err.Error())
			}
			return false
		})
		if err == nil && len(val) == 0 {
			defer func() {
				ft.pendingAccounts[string(addr.Bytes())] = common.Hex2Bytes("00000000")
			}()
		}
	}
	if !common.EmptyHash(root) && (root != types.EmptyRootHash) {
		var blockNum uint64
		var err error
		db.WithSharedDomains(func(sd *erigon_state.SharedDomains) bool {
			var val []byte
			if addr == nil {
				val, _, err = sd.GetLatest(erigon_kv.CommitmentDomain, append(accountRootToBlockNumPrefix, root.Bytes()...))
			} else {
				val, _, err = sd.GetLatest(erigon_kv.CommitmentDomain, append(storageRootToBlockNumPrefix, append(addr.Bytes(), root.Bytes()...)...))
			}
			if err != nil {
				panic("Failed to get corresponding block number for root: " + root.Hex() + ", err: " + err.Error())
			}
			if len(val) == 0 {
				err = fmt.Errorf("no block number found for root: %x", root)
				return false
			}
			blockNum, err = strconv.ParseUint(string(val), 10, 64)
			if err != nil {
				panic("Failed to parse block number from stateRootToBlockNumPrefix: " + err.Error())
			}
			return false
		})
		if err != nil {
			return nil, err
		}
		if opts != nil {
			// For account trie, the state root must match the block number.
			// For storage trie, the state root can be different from the block number,
			// because storage root is not updated for every block.
			if opts.TrieBlockNumber != 0 && opts.TrieBlockNumber != blockNum {
				if addr == nil {
					panic("Trie block number mismatch: " + strconv.FormatUint(opts.TrieBlockNumber, 10) + " != " + strconv.FormatUint(blockNum, 10))
				}
				blockNum = opts.TrieBlockNumber
			}
		}
		return &FlatTrie{
			num:             blockNum,
			dbm:             db,
			root:            root,
			addr:            addr,
			isGenesis:       opts != nil && opts.IsGenesis,
			pendingAccounts: make(map[string][]byte),
			pendingStorage:  make(map[string][]byte),
			pendingBranches: make(map[string][]byte),
		}, nil
	}

	if opts != nil {
		return &FlatTrie{
			num:             opts.TrieBlockNumber,
			dbm:             db,
			root:            common.BytesToHash(commitment.EmptyRootHash),
			addr:            addr,
			isGenesis:       opts.IsGenesis,
			pendingAccounts: make(map[string][]byte),
			pendingStorage:  make(map[string][]byte),
			pendingBranches: make(map[string][]byte),
		}, nil
	}
	return &FlatTrie{
		num:             0,
		dbm:             db,
		root:            common.BytesToHash(commitment.EmptyRootHash),
		addr:            addr,
		pendingAccounts: make(map[string][]byte),
		pendingStorage:  make(map[string][]byte),
		pendingBranches: make(map[string][]byte),
	}, nil
}

func (trie *FlatTrie) getInjectedTrie(sd *erigon_state.SharedDomains) (*erigon_state.SharedDomainsCommitmentContext, *commitment.HexPatriciaHashed) {
	sdCtx := sd.GetCommitmentContext()
	injectedCtx := &kaiaPatriciaContext{
		sdc:             sdCtx,
		pendingAccounts: trie.pendingAccounts,
		pendingStorage:  trie.pendingStorage,
		pendingBranches: trie.pendingBranches,
	}

	hph := sdCtx.Trie().(*commitment.HexPatriciaHashed)
	hph.ResetContext(injectedCtx)
	hph.SetState(trie.hphState)
	return sdCtx, hph
}

func (trie *FlatTrie) TryGet(key []byte) ([]byte, error) {
	// If account trie
	if trie.addr == nil {
		return trie.getAccount(key)
	}
	val, err := trie.getStorage(key)
	if err != nil {
		return nil, err
	}
	return rlp.EncodeToBytes(val)
}

func (trie *FlatTrie) getAccount(key []byte) ([]byte, error) {
	trie.mu.RLock()
	defer trie.mu.RUnlock()

	if val, ok := trie.pendingAccounts[string(key)]; ok {
		return val, nil
	}

	var val []byte
	var err error
	trie.dbm.WithSharedDomains(func(sd *erigon_state.SharedDomains) bool {
		//sd.SetTxNum(trie.num)
		//sd.SetBlockNum(trie.num)
		//val, _, err := sd.GetLatest(erigon_kv.AccountsDomain, key)
		aggTx := sd.AggTx().(*erigon_state.AggregatorRoTx)
		val, _, err = aggTx.GetAsOf(sd.Tx(), erigon_kv.AccountsDomain, key, trie.num+1)
		return false
	})
	return val, err
}

func (trie *FlatTrie) getStorage(key []byte) ([]byte, error) {
	trie.mu.RLock()
	defer trie.mu.RUnlock()

	if val, ok := trie.pendingStorage[string(append(trie.addr.Bytes(), key...))]; ok {
		return val, nil
	}

	var val []byte
	var err error
	trie.dbm.WithSharedDomains(func(sd *erigon_state.SharedDomains) bool {
		aggTx := sd.AggTx().(*erigon_state.AggregatorRoTx)
		val, _, err = aggTx.GetAsOf(sd.Tx(), erigon_kv.StorageDomain, key, trie.num+1)
		return false
	})
	return val, err
}

func (trie *FlatTrie) TryUpdate(key, val []byte) error {
	fmt.Printf("TryUpdate: key: %x, val: %x\n", key, val)
	// If account trie
	if trie.addr == nil {
		return trie.updateAccount(key, val)
	}
	// Since our code RLP encodes the value, try removing the first byte.
	var dec []byte
	err := rlp.DecodeBytes(val, &dec)
	if err != nil {
		return err
	}
	return trie.updateStorage(key, dec)
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

func (trie *FlatTrie) updateStorage(key, val []byte) error {
	trie.mu.Lock()
	defer trie.mu.Unlock()

	trie.pendingStorage[string(append(trie.addr.Bytes(), key...))] = val

	var err error
	// TODO: defer hash calculation to trie.Hash() and trie.Commit().
	trie.dbm.WithSharedDomains(func(sd *erigon_state.SharedDomains) bool {
		sdCtx, hph := trie.getInjectedTrie(sd)
		sdCtx.TouchKey(erigon_kv.StorageDomain, string(append(trie.addr.Bytes(), key...)), val)

		aggTx := sd.AggTx().(*erigon_state.AggregatorRoTx)
		val, _, err := aggTx.GetAsOf(sd.Tx(), erigon_kv.AccountsDomain, trie.addr.Bytes(), trie.num+1)
		if err != nil {
			panic("GetAsOf failed: " + err.Error())
		}
		_ = val
		sdCtx.TouchKey(erigon_kv.AccountsDomain, string(trie.addr.Bytes()), val)

		r, err := sd.ComputeCommitment(context.Background(), false, trie.num, "")
		if err != nil {
			panic("ComputeCommitment failed: " + err.Error())
		}
		fmt.Printf("updateStorage: commitmentroot: %x\n", r)

		root, ok := sd.GetStorageRootHash(trie.addr.Bytes())
		if !ok {
			panic("updateStorage: storage root not found for account " + hex.EncodeToString(trie.addr.Bytes()))
		}

		trie.root = common.BytesToHash(root[:])
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
		//////////////////////
		// TODO-Kaia: We should not increment num here, because we may commit to the same block multiple times.
		//////////////////////
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
		for key, val := range trie.pendingStorage {
			// The key is already prefixed with the address, so we don't need to add it again.
			sd.DomainPut(erigon_kv.StorageDomain, []byte(key), nil, val, nil, 0)
		}
		trie.pendingStorage = make(map[string][]byte)
		for key, val := range trie.pendingBranches {
			sd.DomainPut(erigon_kv.CommitmentDomain, []byte(key), nil, val, nil, 0)
		}
		trie.pendingBranches = make(map[string][]byte)

		var err error
		// Store mapping for stateRoot -> blockNum
		if trie.addr == nil {
			err = sd.DomainPut(erigon_kv.CommitmentDomain, accountRootToBlockNumPrefix, trie.root.Bytes(), []byte(strconv.FormatUint(trie.num, 10)), nil, 0)
		} else {
			err = sd.DomainPut(erigon_kv.CommitmentDomain, storageRootToBlockNumPrefix, append(trie.addr.Bytes(), trie.root.Bytes()...), []byte(strconv.FormatUint(trie.num, 10)), nil, 0)
		}
		if err != nil {
			panic("Failed to store stateRoot to blockNum mapping for root: " + hex.EncodeToString(trie.root.Bytes()) + ", num: " + strconv.FormatUint(trie.num, 10) + ", err: " + err.Error())
		}
		return true
	})
	return trie.root, nil
}

func (trie *FlatTrie) CommitExt(cb LeafCallback) (common.ExtHash, error) {
	root, err := trie.Commit(cb)
	if err != nil {
		return common.ExtHash{}, err
	}
	return root.ExtendZero(), nil
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
	trie.mu.RLock()
	defer trie.mu.RUnlock()

	return trie.root.ExtendZero()
}

func (trie *FlatTrie) TryUpdateWithKeys(key, hashKey, hexKey, value []byte) error {
	return trie.TryUpdate(key, value)
}

func (trie *FlatTrie) TryDelete(key []byte) error {
	if trie.addr == nil {
		return trie.deleteAccount(key)
	}
	return trie.deleteStorage(key)
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

func (trie *FlatTrie) deleteStorage(key []byte) error {
	trie.mu.Lock()
	defer trie.mu.Unlock()

	trie.pendingStorage[string(append(trie.addr.Bytes(), key...))] = nil

	var root []byte
	var err error
	// TODO: defer hash calculation to trie.Hash() and trie.Commit().
	trie.dbm.WithSharedDomains(func(sd *erigon_state.SharedDomains) bool {
		sdCtx, hph := trie.getInjectedTrie(sd)
		sdCtx.TouchKey(erigon_kv.StorageDomain, string(append(trie.addr.Bytes(), key...)), nil)

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
