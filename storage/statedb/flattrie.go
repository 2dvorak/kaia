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
	"path"

	"github.com/erigontech/erigon-lib/commitment"
	"github.com/erigontech/erigon-lib/common/datadir"
	erigon_kv "github.com/erigontech/erigon-lib/kv"
	"github.com/erigontech/erigon-lib/kv/mdbx"
	erigon_state "github.com/erigontech/erigon-lib/state"
	"github.com/kaiachain/kaia/common"
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

// FlatTrie is not safe for concurrent use.
type FlatTrie struct {
	//TrieOpts

	dbm database.DBManager

	// TODO-Kaia change this to uint64
	num      uint64
	addr     common.Address
	writable bool
	hphBuf   []byte
}

func NewFlatTrieWithDBManager(db database.DBManager) (*FlatTrie, error) {
	return &FlatTrie{
		num: 0,
		dbm: db,
	}, nil
}

func (t *FlatTrie) SetNum(num uint64) {
	t.num = num
}

func (t *FlatTrie) SetAddress(addr common.Address) {
	t.addr = addr
}

func (t *FlatTrie) SetWritable(writable bool) {
	t.writable = writable
}

type txWithCtx struct {
	erigon_kv.Tx
	ac *erigon_state.AggregatorRoTx
}

func WrapTxWithCtx(tx erigon_kv.Tx, ctx *erigon_state.AggregatorRoTx) *txWithCtx {
	return &txWithCtx{Tx: tx, ac: ctx}
}
func (tx *txWithCtx) AggTx() any { return tx.ac }

func (t *FlatTrie) getSd() (*erigon_state.SharedDomains, *erigon_state.AggregatorRoTx, erigon_kv.RwTx, *erigon_state.Aggregator, erigon_kv.RwDB, error) {
	aggStepSize := uint64(1)
	dirs := datadir.New(path.Join(t.dbm.GetDBConfig().Dir, "flatdata"))
	db := mdbx.New(erigon_kv.ChainDB, nil).
		Path(dirs.Chaindata).
		//Exclusive(false).
		MustOpen()
	agg, err := erigon_state.NewAggregator2(context.Background(), dirs, aggStepSize, db, nil)
	if err != nil {
		db.Close()
		return nil, nil, nil, nil, nil, err
	}
	err = agg.OpenFolder()
	if err != nil {
		agg.Close()
		db.Close()
		return nil, nil, nil, nil, nil, err
	}
	agg.DisableFsync()

	tx, err := db.BeginRw(context.Background())
	if err != nil {
		agg.Close()
		db.Close()
		return nil, nil, nil, nil, nil, err
	}
	ac := agg.BeginFilesRo()

	sd, err := erigon_state.NewSharedDomains(WrapTxWithCtx(tx, ac), nil)
	if err != nil {
		ac.Close()
		tx.Rollback()
		agg.Close()
		db.Close()
		return nil, nil, nil, nil, nil, err
	}
	return sd, ac, tx, agg, db, nil
}

// 1. Read from t.diff at (key)
// 2. Read from DB at (key, t.num) or (t.addr, key, t.num)
func (t *FlatTrie) TryGet(key []byte) ([]byte, error) {
	t.dbm.GetFlatMu().Lock()
	defer t.dbm.GetFlatMu().Unlock()
	sd, ac, tx, agg, db, err := t.getSd()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	defer agg.Close()
	defer tx.Rollback()
	defer ac.Close()
	defer sd.Close()

	val, _, err := sd.GetLatest(erigon_kv.AccountsDomain, key)
	if err != nil {
		return nil, err
	}
	// TODO-Kaia: I don't know why but this was needed
	buf := make([]byte, len(val))
	copy(buf[:], val)
	return buf, nil
}

func (t *FlatTrie) TryUpdate(key, value []byte) error {
	t.dbm.GetFlatMu().Lock()
	defer t.dbm.GetFlatMu().Unlock()
	sd, ac, tx, agg, db, err := t.getSd()
	if err != nil {
		return err
	}
	defer db.Close()
	defer agg.Close()
	// comit? rollback?
	defer tx.Rollback()
	defer ac.Close()
	defer sd.Close()

	hph := sd.GetCommitmentContext().Trie().(*commitment.HexPatriciaHashed)
	hph.SetState(t.hphBuf)

	err = sd.DomainPut(erigon_kv.AccountsDomain, key, nil, value, nil, 0)
	if err != nil {
		return err
	}

	err = sd.Flush(context.Background(), tx)
	if err != nil {
		return err
	}
	err = tx.Commit()
	if err != nil {
		return err
	}

	buf, err := hph.EncodeCurrentState(nil)
	if err != nil {
		return err
	}
	t.hphBuf = make([]byte, len(buf))
	copy(t.hphBuf, buf)
	return nil
}

func (t *FlatTrie) Hash() common.Hash {
	hash, _ := t.Commit(nil)
	return hash
}

// commit 할때는 diff map에 있는 것만 써야함?
// hash 할때는 domainPut 없이 hash만 만들 수 있어야함. commit을 하지 않아야 되기 때문
// put 없이 touchkey만 했을 때 해쉬계산만 되는지?

// 또하나는 diff가 10개인데 commit을 하면 flush되고 diff가 0개겟지만
// diff가 10개일때 해쉬를 하면 디프가 그대로 쌓여있음. 그래서 해쉬를 할때마다 hph를 불러오는건 비효율적
// 업데이트 할때마다 hph에 녹여낼 수 잇는지?
// 그리고 커밋할 때는 디프를 디비에 써주기만 하면 됨
func (t *FlatTrie) Commit(cb LeafCallback) (common.Hash, error) {
	t.dbm.GetFlatMu().Lock()
	defer t.dbm.GetFlatMu().Unlock()
	sd, ac, tx, agg, db, err := t.getSd()
	if err != nil {
		return common.Hash{}, err
	}
	defer db.Close()
	defer agg.Close()
	defer ac.Close()
	//defer tx.Rollback()
	defer sd.Close()

	hph := sd.GetCommitmentContext().Trie().(*commitment.HexPatriciaHashed)
	hph.SetState(t.hphBuf)

	// Instead of saving state, save state to hphBuf
	hash, err := sd.ComputeCommitment(context.Background(), false, t.num, "flattrie-commit")
	if err != nil {
		return common.Hash{}, err
	}
	err = sd.Flush(context.Background(), tx)
	if err != nil {
		return common.Hash{}, err
	}
	err = tx.Commit()
	if err != nil {
		return common.Hash{}, err
	}
	t.num++
	buf, err := hph.EncodeCurrentState(nil)
	if err != nil {
		return common.Hash{}, err
	}
	t.hphBuf = make([]byte, len(buf))
	copy(t.hphBuf, buf)
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
	it.trie.dbm.GetFlatMu().Lock()
	defer it.trie.dbm.GetFlatMu().Unlock()
	sd, ac, tx, agg, db, err := it.trie.getSd()
	if err != nil {
		it.err = err
		return false
	}
	defer db.Close()
	defer agg.Close()
	defer tx.Rollback()
	defer ac.Close()
	defer sd.Close()

	val, _, err := sd.GetLatest(erigon_kv.AccountsDomain, key)
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
	panic("not implemented")
	/*expectedRoot := t.Hash()
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
	return nil*/
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
	return t.TryUpdate(key, nil)
}

func (t *FlatTrie) Copy() *FlatTrie {
	return &FlatTrie{
		dbm:      t.dbm,
		num:      t.num,
		addr:     t.addr,
		writable: t.writable,
		hphBuf:   t.hphBuf,
	}
}
