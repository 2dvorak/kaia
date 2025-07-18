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
	"encoding/binary"
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
	storageBranchesPrefix       = []byte("sb")
	keyCommitmentState          = []byte("state")
)

type branch struct {
	data     []byte
	prevData []byte
	prevStep uint64
}

type kaiaPatriciaContext struct {
	sdc             *erigon_state.SharedDomainsCommitmentContext
	pendingAccounts map[string][]byte
	pendingStorage  map[string][]byte
	pendingBranches map[string]branch
}

func (ctx *kaiaPatriciaContext) Branch(prefix []byte) ([]byte, uint64, error) {
	if ctx.pendingBranches != nil {
		if branch, ok := ctx.pendingBranches[string(prefix)]; ok {
			return branch.data, branch.prevStep, nil
		}
	}
	return ctx.sdc.Branch(prefix)
}

func (ctx *kaiaPatriciaContext) PutBranch(prefix []byte, data []byte, prevData []byte, prevStep uint64) error {
	if ctx.pendingBranches != nil {
		ctx.pendingBranches[string(prefix)] = branch{
			data:     data,
			prevData: prevData,
			prevStep: prevStep,
		}
	}
	return ctx.sdc.PutBranch(prefix, data, prevData, prevStep)
}

func (ctx *kaiaPatriciaContext) Account(plainKey []byte) (*commitment.Update, error) {
	if ctx.pendingAccounts != nil {
		if data, ok := ctx.pendingAccounts[string(plainKey)]; ok {
			rawBytes := make([]byte, len(data))
			copy(rawBytes, data)
			return &commitment.Update{
				//CodeHash: commitment.EmptyCodeHashArray,
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
	pendingBranches map[string]branch
}

// TODO: opts: FlatTrieCommit, FlatTrieIsGenesis + add comments
// TODO: if root == empty or root == {00..}, that means it's a new trie, we start from empty trie (not block 0)
// so we should not allow any get, before commit.
func NewFlatTrieWithDBManager(root common.Hash, db database.DBManager, addr *common.Address, opts *TrieOpts) (ft *FlatTrie, err error) {
	// TODO: tidy up these if blocks
	if addr != nil {
		var val []byte
		var branches []byte
		db.WithSharedDomains(func(sd *erigon_state.SharedDomains) bool {
			val, _, err = sd.GetLatest(erigon_kv.AccountsDomain, addr.Bytes())
			if err != nil {
				panic("Failed to get account for address: " + addr.Hex() + ", err: " + err.Error())
			}
			branches, _, err = sd.GetLatest(erigon_kv.CommitmentDomain, append(storageBranchesPrefix, append(addr.Bytes(), root.Bytes()...)...))
			if err != nil {
				panic("Failed to get branches for address: " + addr.Hex() + ", err: " + err.Error())
			}
			return false
		})
		if err == nil && len(val) == 0 {
			defer func() {
				ft.pendingAccounts[string(addr.Bytes())] = common.Hex2Bytes("00000000")
			}()
		}
		if err == nil && len(branches) != 0 {
			defer func() {
				// deserialize branches
				if ft.pendingBranches, err = deserializeBranch(branches); err != nil {
					panic("Failed to deserialize branches: " + err.Error())
				}
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
			pendingBranches: make(map[string]branch),
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
			pendingBranches: make(map[string]branch),
		}, nil
	}
	return &FlatTrie{
		num:             0,
		dbm:             db,
		root:            common.BytesToHash(commitment.EmptyRootHash),
		addr:            addr,
		pendingAccounts: make(map[string][]byte),
		pendingStorage:  make(map[string][]byte),
		pendingBranches: make(map[string]branch),
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
	// If the value is empty, return nil.
	if len(val) == 0 {
		return nil, nil
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
		val, _, err = aggTx.GetAsOf(sd.Tx(), erigon_kv.StorageDomain, append(trie.addr.Bytes(), key...), trie.num+1)
		return false
	})
	return val, err
}

func (trie *FlatTrie) TryUpdate(key, val []byte) error {
	fmt.Printf("TryUpdate: key: %x, val: %x, addr: %x\n", key, val, trie.addr)
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

		// This means the account is not yet committed, so we need to touch it to trigger storage root calculation.
		if account, ok := trie.pendingAccounts[string(trie.addr.Bytes())]; ok {
			sdCtx.TouchKey(erigon_kv.AccountsDomain, string(trie.addr.Bytes()), account)
		}

		// Call ComputeCommitment to update the storage root.
		_, err = sd.ComputeCommitment(context.Background(), false, trie.num, "")
		if err != nil {
			panic("ComputeCommitment failed: " + err.Error())
		}

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
		// We may have set empty account to calculate storage root for non-existent account, so we should not commit it.
		if trie.addr == nil {
			for key, val := range trie.pendingAccounts {
				if len(val) == 0 {
					if err := sd.DomainDel(erigon_kv.AccountsDomain, []byte(key), nil, nil, 0); err != nil {
						panic("Failed to delete account: " + err.Error())
					}
				} else {
					if err := sd.DomainPut(erigon_kv.AccountsDomain, []byte(key), nil, val, nil, 0); err != nil {
						panic("Failed to put account: " + err.Error())
					}
				}
			}
		}
		trie.pendingAccounts = make(map[string][]byte)
		for key, val := range trie.pendingStorage {
			// The key is already prefixed with the address, so we don't need to add it again.
			if len(val) == 0 {
				if err := sd.DomainDel(erigon_kv.StorageDomain, []byte(key), nil, nil, 0); err != nil {
					panic("Failed to delete storage: " + err.Error())
				}
			} else {
				if err := sd.DomainPut(erigon_kv.StorageDomain, []byte(key), nil, val, nil, 0); err != nil {
					panic("Failed to put storage: " + err.Error())
				}
			}
		}
		trie.pendingStorage = make(map[string][]byte)
		for key, val := range trie.pendingBranches {
			if len(val.data) == 0 {
				if err := sd.DomainDel(erigon_kv.CommitmentDomain, []byte(key), nil, val.prevData, val.prevStep); err != nil {
					panic("Failed to delete branch: " + err.Error())
				}
			} else {
				if err := sd.DomainPut(erigon_kv.CommitmentDomain, []byte(key), nil, val.data, val.prevData, val.prevStep); err != nil {
					panic("Failed to put branch: " + err.Error())
				}
			}
			// Try to put branch here too, so that it would be committed to the db.
			sd.GetCommitmentContext().PutBranch([]byte(key), val.data, val.prevData, val.prevStep)
		}
		// TODO: this bypass should be removed
		// Let's try store/load branches for storage trie..
		/*if trie.addr != nil {
			branches, err := serializeBranch(trie.pendingBranches)
			if err != nil {
				panic("Failed to serialize branches: " + err.Error())
			}
			if err := sd.DomainPut(erigon_kv.CommitmentDomain, append(storageBranchesPrefix, append(trie.addr.Bytes(), trie.root.Bytes()...)...), nil, branches, nil, 0); err != nil {
				panic("Failed to store serialized branches: " + err.Error())
			}
		}*/
		trie.pendingBranches = make(map[string]branch)

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

func serializeBranch(branches map[string]branch) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	// first write the length of the map
	if err := binary.Write(buf, binary.BigEndian, uint32(len(branches))); err != nil {
		return nil, fmt.Errorf("encode storageRootHashes count: %w", err)
	}
	for pref, branch := range branches {
		if trace {
			fmt.Printf("serializeBranch: pref: %x, data: %x\n", pref, branch.data)
		}
		if err := binary.Write(buf, binary.BigEndian, uint16(len(pref))); err != nil {
			return nil, fmt.Errorf("encode account key length: %w", err)
		}
		if n, err := buf.Write([]byte(pref)); err != nil || n != len(pref) {
			return nil, fmt.Errorf("encode account key: %w", err)
		}
		if err := binary.Write(buf, binary.BigEndian, uint16(len(branch.data))); err != nil {
			return nil, fmt.Errorf("encode data length: %w", err)
		}
		if n, err := buf.Write(branch.data[:]); err != nil || n != len(branch.data) {
			return nil, fmt.Errorf("encode storage root hash: %w", err)
		}
		if err := binary.Write(buf, binary.BigEndian, uint16(len(branch.prevData))); err != nil {
			return nil, fmt.Errorf("encode prevData length: %w", err)
		}
		if n, err := buf.Write(branch.prevData[:]); err != nil || n != len(branch.prevData) {
			return nil, fmt.Errorf("encode prevData: %w", err)
		}
		if err := binary.Write(buf, binary.BigEndian, branch.prevStep); err != nil {
			return nil, fmt.Errorf("encode prevStep: %w", err)
		}
	}
	return buf.Bytes(), nil
}

func deserializeBranch(data []byte) (map[string]branch, error) {
	buf := bytes.NewBuffer(data)
	branches := make(map[string]branch)
	var count uint32
	if err := binary.Read(buf, binary.BigEndian, &count); err != nil {
		return nil, fmt.Errorf("decode storageRootHashes count: %w", err)
	}
	for i := uint32(0); i < count; i++ {
		var prefLen uint16
		if err := binary.Read(buf, binary.BigEndian, &prefLen); err != nil {
			return nil, fmt.Errorf("decode account key length: %w", err)
		}
		pref := make([]byte, prefLen)
		if n, err := buf.Read(pref); err != nil || n != int(prefLen) {
			return nil, fmt.Errorf("decode account key: %w", err)
		}
		var dataLen uint16
		if err := binary.Read(buf, binary.BigEndian, &dataLen); err != nil {
			return nil, fmt.Errorf("decode data length: %w", err)
		}
		data := make([]byte, dataLen)
		if n, err := buf.Read(data); err != nil || n != int(dataLen) {
			return nil, fmt.Errorf("decode data: %w", err)
		}
		var prevDataLen uint16
		if err := binary.Read(buf, binary.BigEndian, &prevDataLen); err != nil {
			return nil, fmt.Errorf("decode prevData length: %w", err)
		}
		prevData := make([]byte, prevDataLen)
		if n, err := buf.Read(prevData); err != nil || n != int(prevDataLen) {
			return nil, fmt.Errorf("decode prevData: %w", err)
		}
		var prevStep uint64
		if err := binary.Read(buf, binary.BigEndian, &prevStep); err != nil {
			return nil, fmt.Errorf("decode prevStep: %w", err)
		}
		// Let's not override "state" branch
		if bytes.Equal([]byte(pref), keyCommitmentState) {
			continue
		}
		branches[string(pref)] = branch{
			data:     data,
			prevData: prevData,
			prevStep: prevStep,
		}
	}
	return branches, nil
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

	trie.pendingAccounts[string(key)] = []byte{}

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

	trie.pendingStorage[string(append(trie.addr.Bytes(), key...))] = []byte{}

	var err error
	// TODO: defer hash calculation to trie.Hash() and trie.Commit().
	trie.dbm.WithSharedDomains(func(sd *erigon_state.SharedDomains) bool {
		sdCtx, hph := trie.getInjectedTrie(sd)
		sdCtx.TouchKey(erigon_kv.StorageDomain, string(append(trie.addr.Bytes(), key...)), nil)

		// Call ComputeCommitment to update the storage root.
		_, err = sd.ComputeCommitment(context.Background(), false, trie.num, "")
		if err != nil {
			panic("ComputeCommitment failed: " + err.Error())
		}

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
