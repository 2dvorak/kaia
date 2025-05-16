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
	"errors"
	"fmt"
	"math/big"
	"path"
	"sync"

	"github.com/erigontech/erigon-lib/commitment"
	"github.com/erigontech/erigon-lib/common/datadir"
	"github.com/erigontech/erigon-lib/config3"
	erigon_kv "github.com/erigontech/erigon-lib/kv"
	"github.com/erigontech/erigon-lib/kv/mdbx"
	"github.com/erigontech/erigon-lib/kv/temporal"
	erigon_state "github.com/erigontech/erigon-lib/state"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/crypto"
	"github.com/kaiachain/kaia/storage/database"
)

/*
disk database는 "flataccount" "flatstorage" 폴더 사용할껀데 일단은 Trie에게 kv 하나가 주어지는걸로 생각.

readonly account FlatTrie { num }
writable account FlatTrie { num, true } // writes as num+1
readonly storage FlatTrie { num, addr }
writable storage FlatTrie { num, addr, true } // writes as num+1

(optional)
trie.IsAccount
trie.IsStorage

account Get(key) // expect key is address
	ReadGT(key || num) or Read(key || 0...lastNum)
account Update(key, val)
	Write(addr || num+1, val) // history
	Write(addr || MAX, val)   // latest <-- rewind 관련 문제는 없을까?? 디비에 쓰지 말고 Get에서 캐쉬해두는게 나을까?
	Write(addr, "")           // account_set

storage Get(key)
	ReadGT(addr || key || num)
storage Update(key, val)
	Write(addr || key || num+1, val) // history
	Write(addr || key, "")           // storage_set

Hash()
	iter number of accounts * number of changes
	account_set, storage_set으로부터 전체 주소 목록을 얻은 다음에 Get(key) 전체조회
	리프 노드들을 트리로 재구성해서 루트해쉬 계산 - 첫번째 버전에서는 NewTrie(common.Hash{}).Update().Hash()로 시작.

유닛테스트에서는
	기대하는 key-value 모양대로 잘 써지는가
	임의의 블록넘버를 조회했을때 잘 나오는가



나중에 도입 방법

OpenTrie(root, {num, write?})
  Get(addr) = Read(addr || num+)
  Update(addr, value) = DB.Write(addr || newNum) 오피셜 상태변경인 경우

  *오피셜: 블록실행을 통한 상태변경
  *비오피셜: API call등에 의해 임시로 이뤄지는 상태변경, 작업후 버려지는 변경내역

OpenStorageTrie(root, {addr, num, write?})
  Get(slot) = Read(addr || slot || num+)
  Update(slot, value) = Write(addr || slot || newNum) 오피셜 상태변경인 경우


오피셜 상태변경이 아닐 때의 Update 동작? (i.e. !opts.write)
  1. 디비에 안 쓰고 메모리에만 갖고있다가 Get 할때 DB보다 우선적으로 리턴해준다
  2. 일반적인 서치에 안걸리는 방식으로 DB.write(addr || 0xffff + random)
  3. 별도의 데이터베이스를 사용한다 (statetrie가 아닌 tempstate같은) -- 이때도 여전히 서로다른 Trie instance끼리에는 구분이 되어야 함.

mdbx의 multi-value 기능을 사용하지 않고, 일단은 범용적인 single-value-kv-database (i.e. LevelDB, PebbleDB) 들에서 동작할 수 있게 만들어보자.


---
04.18

hph가 이더리움 스타일 해쉬를 계산할 수 있다는 것을 알았음. (i.e. Kaia's LegacyAccount)
이번에는 hph를 수정해서 카이아 스타일 해쉬를 계산하게 만들어야 함.

1. 카이아 코드로 정답지 만들기
statedb.New()..
sdb.SetBalance, SetNonce,... 해서 고정된 테스트 스테이트 하나 만들기
sdb.IntermediateRoot 해서 정답 해쉬 계산
트라이에서 인코딩된 어카운트 노드도 뽑아내기 NodeIterator? AccountSerializer?

2. 에리곤 코드로 정답이 나오게 하기
<s>acc.Balance, acc.Nonce,... 해서 똑같은 테스트케이스 입력</s>
카이아 스타일로 인코딩된 어카운트 노드 입력하기
ComputeCommitment 해서 정답 해쉬가 나오면 성공

hopefully 카이아 로직을 넣을 필요는 없을 것. 그저 인코딩된 어카운트 노드가 들어온다고 가정.
트라이면 트라이답게 Opaque key-value 자료구조로 있을 것이지 어디 주제넘게 데이터를 디코딩하려 하느냐.
*/

var (
	AccountKeyLength        = 20
	StorageKeyLength        = 20
	LatestBlockNumberSuffix = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	AccountSetPrefix        = []byte("AccountSet")
	StorageSetPrefix        = []byte("StorageSet")
	AccountPrefix           = []byte("Account")
	StoragePrefix           = []byte("Storage")
	terminatorHexByte       = byte(16) // max nibble value +1. Defines end of nibble line in the trie
)

var (
	ErrNotFound         = errors.New("data is not found with the given key")
	ErrInvalidKeyLength = errors.New("invalid key length")
)

var temporaryMdbx erigon_kv.RwDB
var rwtx erigon_kv.RwTx
var mu sync.RWMutex

func init() {
	var err error
	temporaryMdbx, err = mdbx.NewTemporaryMdbx(context.Background(), "/tmp")
	if err != nil {
		panic(err)
	}

	dirs := datadir.New(path.Join("/tmp", "flatdata"))
	agg, err := erigon_state.NewAggregator2(context.Background(), dirs, config3.DefaultStepSize, temporaryMdbx, nil)
	if err != nil {
		panic(err)
	}
	if err := agg.OpenFolder(); err != nil {
		panic(err)
	}
	tempdb, err := temporal.New(temporaryMdbx, agg)
	if err != nil {
		panic(err)
	}
	rwtx, err = tempdb.BeginRw(context.Background())
	if err != nil {
		panic(err)
	}
	mu = sync.RWMutex{}
}

// FlatTrie is not safe for concurrent use.
type FlatTrie struct {
	//TrieOpts

	db database.Database
	tx erigon_kv.Tx

	// change this to uint64
	num        *big.Int
	addr       common.Address
	writable   bool
	commitHash common.Hash
	hash       common.Hash
	hph        *commitment.HexPatriciaHashed
	sd         *erigon_state.SharedDomains

	diff map[string][]byte
}

func NewFlatTrie3(kv erigon_kv.RwTx) (*FlatTrie, error) {
	sd, err := erigon_state.NewSharedDomains(kv, nil)
	if err != nil {
		return nil, err
	}
	return &FlatTrie{
		sd:  sd,
		tx:  kv,
		hph: sd.GetCommitmentContext().Trie().(*commitment.HexPatriciaHashed),
		num: big.NewInt(0),
	}, nil
}

func NewFlatTrie2(db *Database, opts *TrieOpts) (*FlatTrie, error) {
	if opts == nil {
		opts = &TrieOpts{PruningBlockNumber: 0}
	}
	t := &FlatTrie{
		db:   db.diskDB.GetStateTrieDB(),
		num:  big.NewInt(int64(opts.PruningBlockNumber)),
		diff: make(map[string][]byte),
	}

	sd, err := openDB(db.diskDB.GetDBConfig().Dir)
	if err != nil {
		return nil, err
	}
	t.sd = sd
	t.hph = t.sd.GetCommitmentContext().Trie().(*commitment.HexPatriciaHashed)

	return t, nil
}

// baseDir shall be $DATA_DIR/klay/chaindata
func openDB(baseDir string) (*erigon_state.SharedDomains, error) {
	/*
		opts := mdbx.New(erigon_kv.ChainDB, nil).
			Accede(true)
		opts = opts.Path(path.Join(baseDir, "flatstate")) // flatstate, flatdata 둘 중 하나는 상관없을지도?
		db, err := opts.Open(context.Background())
		if err != nil {
			return nil, err
		}*/

	//db := temporaryMdbx

	/*dirs := datadir.New(path.Join(baseDir, "flatdata"))
	agg, err := erigon_state.NewAggregator2(context.Background(), dirs, config3.DefaultStepSize, db, nil)
	if err != nil {
		return nil, err
	}
	if err := agg.OpenFolder(); err != nil {
		return nil, err
	}
	tempdb, err := temporal.New(db, agg)
	if err != nil {
		return nil, err
	}
	tx, err := tempdb.BeginRw(context.Background())
	if err != nil {
		return nil, err
	}*/
	return erigon_state.NewSharedDomains(rwtx, nil)
}

func NewFlatTrie(db database.Database, opts *TrieOpts) (*FlatTrie, error) {
	if opts == nil {
		opts = &TrieOpts{PruningBlockNumber: 0}
	}
	t := &FlatTrie{
		db:   db,
		num:  big.NewInt(int64(opts.PruningBlockNumber)),
		diff: make(map[string][]byte),
	}
	/*mdbxopts := mdbx.New("flatkv", nil)
	rw, err := mdbxopts.Open(context.Background())
	if err != nil {
		return nil, err
	}*/

	mdbx, err := mdbx.NewTemporaryMdbx(context.Background(), "/tmp")
	if err != nil {
		return nil, err
	}
	dirs := datadir.New("temp-flatkv")
	agg, err := erigon_state.NewAggregator2(context.Background(), dirs, config3.DefaultStepSize, mdbx, nil)
	if err != nil {
		return nil, err
	}
	if err := agg.OpenFolder(); err != nil {
		panic(err)
	}
	tempdb, err := temporal.New(mdbx, agg)
	if err != nil {
		panic(err)
	}
	tx, err := tempdb.BeginRw(context.Background())
	if err != nil {
		return nil, err
	}
	t.tx = tx
	t.sd, err = erigon_state.NewSharedDomains(tx, nil)
	if err != nil {
		return nil, err
	}
	t.sd.GetCommitmentContext().Reset()
	t.hph = t.sd.GetCommitmentContext().Trie().(*commitment.HexPatriciaHashed)
	//t.hph = NewHexPatriciaHashed(common.AddressLength, nil, "/tmp", t.sd)
	//t.hph.ResetContext(t.sd.GetCommitmentContext())

	return t, nil
}

func NewFlatTrieWithOpts(db database.Database, num *big.Int, addr common.Address, writable bool) (*FlatTrie, error) {
	return &FlatTrie{
		db:       db,
		num:      num,
		addr:     addr,
		writable: writable,
		diff:     make(map[string][]byte),
	}, nil
}

func (t *FlatTrie) SetNum(num *big.Int) {
	t.num = num
}

func (t *FlatTrie) SetAddress(addr common.Address) {
	t.addr = addr
}

func (t *FlatTrie) SetWritable(writable bool) {
	t.writable = writable
}

// 1. Read from t.diff at (key)
// 2. Read from DB at (key, t.num) or (t.addr, key, t.num)
func (t *FlatTrie) TryGet(key []byte) ([]byte, error) {
	/*logger.Warn("FlatTrie TryGet", "key", key)
	if t.addr != (common.Address{}) {
		key = append(t.addr.Bytes(), key...)
	}
	if val, ok := t.diff[string(key)]; ok {
		return val, nil
	}
	it := t.db.NewIterator(key, t.num.FillBytes(make([]byte, 8)))
	if it.Next() {
		return it.Value(), nil
	}
	return nil, ErrNotFound*/
	mu.RLock()
	defer mu.RUnlock()
	val, _, err := t.sd.GetLatest(erigon_kv.AccountsDomain, key)
	fmt.Printf("TryGet: %x, %x, %v\n", key, val, err)
	if err != nil {
		return nil, err
	}
	return val, nil
}

func (t *FlatTrie) TryUpdate(key, value []byte) error {
	/*logger.Warn("FlatTrie TryUpdate", "key", key, "value", value)
	t.hash = common.Hash{}
	t.diff[string(key)] = value
	return nil*/

	//err := t.sd.DomainPut(erigon_kv.AccountsDomain, key, nil, value, nil, 0)

	// suppose value is encoded for hashing
	/*acc := accounts.Account{}
	err := acc.DecodeForHashing(value)
	if err != nil {
		return err
	}
	accBytes := accounts.SerialiseV3(&acc)
	err = t.sd.DomainPut(erigon_kv.AccountsDomain, key, nil, accBytes, nil, 0)
	if err != nil {
		return err
	}
	//storageByte
	return nil*/

	mu.Lock()
	defer mu.Unlock()
	fmt.Printf("TryUpdate: %x, %x\n", key, value)
	return t.sd.DomainPut(erigon_kv.AccountsDomain, key, nil, value, nil, 0)
}

func (t *FlatTrie) CommitHash() common.Hash {
	if t.commitHash != (common.Hash{}) {
		return t.commitHash
	}
	sc, err := NewSecureTrie(common.Hash{}, NewDatabase(database.NewMemoryDBManager()), nil)
	if err != nil {
		logger.Error("FlatTrie Hash NewSecureTrie error", "err", err)
		return common.Hash{}
	}
	var keySet [][]byte
	if t.addr == (common.Address{}) {
		keySet = t.AccountSet()
	} else {
		keySet = t.StorageSet()
	}
	for _, key := range keySet {
		val, err := t.db.Get(append(key[len(AccountSetPrefix):], LatestBlockNumberSuffix...))
		fmt.Printf("key: %x (%s), val: %x (%s)\n", key, string(key[len(AccountSetPrefix):]), val, string(val))
		if err != nil {
			logger.Error("FlatTrie Hash TryGet error", "err", err)
			panic(err)
			return common.Hash{}
		}
		err = sc.TryUpdate(key[len(AccountSetPrefix):], val)
		if err != nil {
			logger.Error("FlatTrie Hash TryUpdate error", "err", err)
			panic(err)
			return common.Hash{}
		}
	}
	t.commitHash = sc.Hash()
	return t.commitHash
}

/*
// hashKey returns the hash of key as an ephemeral buffer.
// The caller must not hold onto the return value because it will become
// invalid on the next call to hashKey or secKey.
func (t *FlatTrie) hashKey(key []byte) []byte {
	buf := make([]byte, common.HashLength)
	hashedKey := make([]byte, common.HashLength*2)
	h := newHasher(nil)
	h.sha.Reset()
	h.sha.Write(key)
	buf = h.sha.Sum(buf[:0])
	for i, c := range buf {
		hashedKey[i*2] = (c >> 4) & 0xf
		hashedKey[i*2+1] = c & 0xf
	}
	returnHasherToPool(h)
	return hashedKey
}
*/

func (t *FlatTrie) Hash() common.Hash {
	/*if t.hash != (common.Hash{}) {
		return t.hash
	}*/
	//hash, err := t.sd.ComputeCommitment(context.Background(), true, t.num.Uint64(), "asdf")
	hash, err := t.sd.ComputeCommitmentWithoutReset(context.Background(), false, t.num.Uint64(), "asdf")
	//hash, err := t.sd.GetCommitmentContext().Trie().Process(context.Background(), t.sd.GetUpdates(), "FlatTrie.Hash")
	if err != nil {
		logger.Error("FlatTrie Hash ComputeCommitment error", "err", err)
		return common.Hash{}
	}
	return common.BytesToHash(hash)
}

func (t *FlatTrie) HashSC() common.Hash {
	if t.hash != (common.Hash{}) {
		return t.hash
	}
	sc, err := NewSecureTrie(common.Hash{}, NewDatabase(database.NewMemoryDBManager()), nil)
	if err != nil {
		logger.Error("FlatTrie Hash NewSecureTrie error", "err", err)
		return common.Hash{}
	}
	var keySet [][]byte
	if t.addr == (common.Address{}) {
		keySet = t.AccountSet()
	} else {
		keySet = t.StorageSet()
	}
	for _, key := range keySet {
		val, err := t.db.Get(append(key[len(AccountSetPrefix):], LatestBlockNumberSuffix...))
		fmt.Printf("key: %x (%s), val: %x (%s)\n", key, string(key[len(AccountSetPrefix):]), val, string(val))
		if err != nil {
			logger.Error("FlatTrie Hash TryGet error", "err", err)
			panic(err)
			return common.Hash{}
		}
		err = sc.TryUpdate(key[len(AccountSetPrefix):], val)
		if err != nil {
			logger.Error("FlatTrie Hash TryUpdate error", "err", err)
			panic(err)
			return common.Hash{}
		}
	}
	for key, val := range t.diff {
		fmt.Printf("key: %x (%s), val: %x (%s)\n", []byte(key), key, val, string(val))
		err = sc.TryUpdate([]byte(key), val)
		if err != nil {
			logger.Error("FlatTrie Hash TryUpdate error", "err", err)
			panic(err)
			return common.Hash{}
		}
	}
	t.hash = sc.Hash()
	return t.hash
}

func (t *FlatTrie) AccountSet() [][]byte {
	it := t.db.NewIterator(AccountSetPrefix, nil)
	var keySet [][]byte
	for it.Next() {
		keySet = append(keySet, it.Key())
	}
	return keySet
}

func (t *FlatTrie) StorageSet() [][]byte {
	it := t.db.NewIterator(StorageSetPrefix, nil)
	var keySet [][]byte
	for it.Next() {
		keySet = append(keySet, it.Key())
	}
	return keySet
}

func (t *FlatTrie) Commit(cb LeafCallback) (common.Hash, error) {
	/*for strkey, val := range t.diff {
		key := []byte(strkey)
		var setKey []byte
		if t.addr != (common.Address{}) {
			key = append(t.addr.Bytes(), key...)
			setKey = append(StorageSetPrefix, key...)
		} else {
			setKey = append(AccountSetPrefix, key...)
		}
		curState, err := t.db.Get(key)
		if err != nil && err.Error() != "data is not found with the given key" {
			return common.Hash{}, err
		}
		err = t.db.Put(append(key, t.num.Add(t.num, big.NewInt(1)).FillBytes(make([]byte, 8))...), curState)
		if err != nil {
			return common.Hash{}, err
		}
		err = t.db.Put(append(key, LatestBlockNumberSuffix...), val)
		if err != nil {
			return common.Hash{}, err
		}
		err = t.db.Put(setKey, []byte{})
		if err != nil {
			return common.Hash{}, err
		}
	}
	t.hash = t.Hash()
	t.commitHash = t.hash
	t.num = t.num.Add(t.num, big.NewInt(1))
	t.diff = make(map[string][]byte)
	return t.hash, nil*/
	hash, err := t.sd.ComputeCommitmentWithoutReset(context.Background(), true, t.num.Uint64(), "asdf")
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(hash), nil
}

func (t *FlatTrie) CommitExt(cb LeafCallback) (common.ExtHash, error) {
	panic("not implemented")
}

func (t *FlatTrie) NodeIterator(startKey []byte) NodeIterator {
	// Create a new iterator that wraps the HexPatriciaHashed trie
	return newFlatTrieIterator(t, startKey)
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

	// Get the next entry from the trie
	val, _, err := it.trie.sd.GetLatest(erigon_kv.AccountsDomain, key)
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

func (t *FlatTrie) Prove(key []byte, fromLevel uint, proofDb database.DBManager) error {
	expectedRoot := t.Hash()
	proofTrie, _, err := t.sd.GetCommitmentContext().Witness(context.Background(), expectedRoot.Bytes(), "FlatTrie.Prove")
	if err != nil {
		return err
	}
	proof, err := proofTrie.Prove(key, int(fromLevel), t.addr != (common.Address{}))
	if err != nil {
		return err
	}
	for _, p := range proof {
		proofDb.GetMemDB().Put(crypto.Keccak256(p), p)
	}
	return nil
}

func (t *FlatTrie) GetKey(key []byte) []byte {
	panic("not implemented")
}

func (t *FlatTrie) HashExt() common.ExtHash {
	panic("not implemented")
}

func (t *FlatTrie) TryUpdateWithKeys(key, hashKey, hexKey, value []byte) error {
	return t.TryUpdate(key, value)
}

func (t *FlatTrie) TryDelete(key []byte) error {
	/*t.hash = common.Hash{}
	t.diff[string(key)] = nil
	return nil*/
	return t.TryUpdate(key, nil)
}

func (t *FlatTrie) Copy2() *FlatTrie {
	// NewSharedDomain() 하고, Hph는 serialize/deserialize 해서 복사
	// statedb copy test 통과하면 ok 근데 concurrency 문제 확인해봐야함
	sd, err := erigon_state.NewSharedDomains(t.tx, nil)
	if err != nil {
		return nil
	}
	s, err := t.hph.EncodeCurrentState(nil)
	if err != nil {
		return nil
	}
	hph := sd.GetCommitmentContext().Trie().(*commitment.HexPatriciaHashed)
	hph.SetState(s)
	return &FlatTrie{
		db:  t.db,
		tx:  t.tx,
		sd:  sd,
		hph: hph,
	}
}

func (t *FlatTrie) Copy() *FlatTrie {
	mdbx, err := mdbx.NewTemporaryMdbx(context.Background(), "/tmp")
	if err != nil {
		return nil
	}
	dirs := datadir.New("temp-flatkv")
	agg, err := erigon_state.NewAggregator2(context.Background(), dirs, config3.DefaultStepSize, mdbx, nil)
	if err != nil {
		return nil
	}
	if err := agg.OpenFolder(); err != nil {
		panic(err)
	}
	tempdb, err := temporal.New(mdbx, agg)
	if err != nil {
		panic(err)
	}
	tx, err := tempdb.BeginRw(context.Background())
	if err != nil {
		return nil
	}
	sd, err := erigon_state.NewSharedDomains(tx, nil)
	if err != nil {
		return nil
	}
	s, err := t.hph.EncodeCurrentState(nil)
	if err != nil {
		return nil
	}
	hph := sd.GetCommitmentContext().Trie().(*commitment.HexPatriciaHashed)
	hph.SetState(s)
	return &FlatTrie{
		db:  t.db,
		tx:  tx,
		sd:  sd,
		hph: hph,
	}
}

/*
type FlatKVIterator struct {
	db database.Database
	it database.Iterator
}

func NewFlatKVIterator(db database.Database, it database.Iterator) *FlatKVIterator {
	return &FlatKVIterator{
		db: db,
		it: it,
	}
}

func (it *FlatKVIterator) Next(bool) bool {
	return it.it.Next()
}

func (it *FlatKVIterator) Error() error {
	return it.it.Error()
}

func (it *FlatKVIterator) Key() []byte {
	return it.it.Key()
}

func (it *FlatKVIterator) Value() []byte {
	return it.it.Value()
}

func (it *FlatKVIterator) Hash() common.Hash {
	return common.Hash{}
}

func (it *FlatKVIterator) Parent() common.Hash {
	return common.Hash{}
}

func (it *FlatKVIterator) Path() []byte {
	return []byte{}
}

func (it *FlatKVIterator) Leaf() bool {
	return true
}

func (it *FlatKVIterator) LeafKey() []byte {
	return it.db.NewIterator(nil, nil).Key()
}

func (it *FlatKVIterator) LeafBlob() []byte {
	return it.db.NewIterator(nil, nil).Value()
}

func (it *FlatKVIterator) LeafProof() [][]byte {
	return [][]byte{}
}

func (it *FlatKVIterator) AddResolver(database.DBManager) {
}
*/
