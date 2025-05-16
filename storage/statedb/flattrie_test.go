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
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"

	erigon_common "github.com/erigontech/erigon-lib/common"
	"github.com/erigontech/erigon-lib/types/accounts"
	"github.com/kaiachain/kaia/blockchain/types"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/crypto"
	"github.com/kaiachain/kaia/storage/database"
)

/*
Create StateDB
Add accounts with random nonce,balance,etc.
Then calculate eth-style merkle root using state_test_util.go:useEthStateRootWithOption

Create HPH and Updates
For each address in the StateDB,
  val = StateDB.Trie().Get(key)
  updates.TouchPlainKey(key, val)
hph.Process(updates)
hph.Root()

- 이더리움 RLP 포맷 기준으로 roothash가 맞게 나온다면
  - 하려면 PatriciaContext를 하나 넣어줘야함. 이제보니까 SharedDomain이랑 MDBX까지 가져와야할듯
- 인코딩/디코딩 좀 고치면 쓸 수 있다 치고
- 트라이가 엄청 클 땐 왜 됨?? interface PatriciaContext = struct SharedDomainsCommitmentContext 에서 State IO를 담당. Branch Node랑 Leaf Node를 저장.
*/

// Used for testing
func newEmptyFlatTrie() *FlatTrie {
	trie, err := NewFlatTrie(database.NewMemDB(), nil)
	if err != nil {
		panic(err)
	}
	return trie
}

func TestFlatTrieInsert(t *testing.T) {
	/*
		trie := newEmptyFlatTrie()

		trie.TryUpdate([]byte("doe"), []byte("reindeer"))
		trie.TryUpdate([]byte("dog"), []byte("puppy"))
		trie.TryUpdate([]byte("dogglesworth"), []byte("cat"))

		exp := common.HexToHash("d4cd937e4a4368d7931a9cf51686b7e10abb3dce38a39000fd7902a092b64585")
		//root := trie.Hash()
		// Commit in order to flush the diff to the database
		root, err := trie.Commit(nil)
		if err != nil {
			t.Errorf("expected nil got %v", err)
		}
		if root != exp {
			t.Errorf("exp %x got %x", exp, root)
		}
		val, err := trie.kv.Get(append([]byte("doe"), LatestBlockNumberSuffix...))
		if err != nil {
			t.Errorf("expected nil got %v", err)
		}
		if !bytes.Equal(val, []byte("reindeer")) {
			t.Errorf("expected \"reindeer\" got %x", val)
		}
		_, err = trie.kv.Get(append(AccountSetPrefix, []byte("doe")...))
		if err != nil {
			t.Errorf("expected nil got %v", err)
		}

		trie = newEmptyFlatTrie()
		trie.TryUpdate([]byte("A"), []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))

		exp = common.HexToHash("e9e2935138352776cad724d31c9fa5266a5c593bb97726dd2a908fe6d53284df")
		root, err = trie.Commit(nil)
		if err != nil {
			t.Fatalf("commit error: %v", err)
		}
		if root != exp {
			t.Errorf("exp %x got %x", exp, root)
		}*/
}

func TestFlatTrieGet(t *testing.T) {
	/*
		trie := newEmptyFlatTrie()
		err := trie.TryUpdate(common.FromHex("0x0000000000000000000000000000000000000000"), []byte("state0"))
		if err != nil {
			t.Errorf("expected nil got %v", err)
		}
		err = trie.TryUpdate(common.FromHex("0x0000000000000000000000000000000000000001"), []byte("state1"))
		if err != nil {
			t.Errorf("expected nil got %v", err)
		}
		err = trie.TryUpdate(common.FromHex("0x0000000000000000000000000000000000000002"), []byte("state2"))
		if err != nil {
			t.Errorf("expected nil got %v", err)
		}

		for i := 0; i < 2; i++ {
			res, err := trie.TryGet(common.FromHex("0x0000000000000000000000000000000000000001"))
			if err != nil {
				t.Errorf("expected nil got %v", err)
			}
			if !bytes.Equal(res, []byte("state1")) {
				t.Errorf("expected \"state1\" got %x", res)
			}

			_, err = trie.TryGet(common.FromHex("0x000000000000000000000000000000000000dead"))
			if err == nil {
				t.Errorf("expected error got nil")
			}

			if i == 1 {
				return
			}
			trie.Commit(nil)
		}*/
}

func TestFlatTrieDelete(t *testing.T) {
	/*
		trie, _ := NewFlatTrie(database.NewMemDB(), nil)
		vals := []struct{ k, v string }{
			{"do", "verb"},
			{"klaytn", "wookiedoo"},
			{"horse", "stallion"},
			{"shaman", "horse"},
			{"doge", "coin"},
			{"klaytn", ""},
			{"dog", "puppy"},
			{"shaman", ""},
		}
		for _, val := range vals {
			if val.v != "" {
				err := trie.TryUpdate([]byte(val.k), []byte(val.v))
				if err != nil {
					t.Errorf("expected nil got %v", err)
				}
			} else {
				err := trie.TryDelete([]byte(val.k))
				if err != nil {
					t.Errorf("expected nil got %v", err)
				}
			}
		}
		hash := trie.Hash()
		exp := common.HexToHash("29b235a58c3c25ab83010c327d5932bcf05324b7d6b1185e650798034783ca9d")
		if hash != exp {
			t.Errorf("expected %x got %x", exp, hash)
		}*/
}

var (
	testAccount1 = common.FromHex("0x0000000000000000000000000000000000000001")
	testAccount2 = common.FromHex("0x0000000000000000000000000000000000000002")
)

func genRandomByteArrayOfLen(length uint) []byte {
	array := make([]byte, length)
	for i := uint(0); i < length; i++ {
		array[i] = byte(rand.Intn(256))
	}
	return array
}

func genRandomAccount() accounts.Account {
	//codeValue := genRandomByteArrayOfLen(128)
	//codeHash := common.BytesToHash(crypto.Keccak256(codeValue))
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	//random := rand.New(rand.NewSource(0))
	balance := new(big.Int).Rand(random, new(big.Int).Exp(common.Big2, common.Big256, nil))
	acc := accounts.NewAccount()
	acc.Initialised = true
	acc.Nonce = uint64(random.Int63())
	acc.Balance.SetFromBig(balance)
	acc.Root = erigon_common.Hash(types.EmptyRootHash.Bytes())
	acc.CodeHash = erigon_common.Hash(crypto.Keccak256Hash(nil).Bytes())
	acc.Incarnation = 0
	return acc
}

func genRandomKeyValue() (key, value []byte) {
	key = genRandomByteArrayOfLen(common.AddressLength)
	acc := genRandomAccount()
	value = make([]byte, acc.EncodingLengthForHashing())
	acc.EncodeForHashing(value)
	return
}

func TestFlatTrieHash(t *testing.T) {
	var hash1, hash2 common.Hash
	trie := newEmptyFlatTrie()
	secureTrie, err := NewSecureTrie(common.Hash{}, NewDatabase(database.NewMemoryDBManager()), nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	for _ = range 1000 {
		key, value := genRandomKeyValue()
		err = trie.TryUpdate(key, value)
		if err != nil {
			t.Errorf("expected nil got %v", err)
		}
		err = secureTrie.TryUpdate(key, value)
		if err != nil {
			t.Errorf("expected nil got %v", err)
		}
	}

	hash1 = trie.Hash()
	hash2 = secureTrie.Hash()
	if hash1 != hash2 {
		t.Errorf("expected %x got %x", hash1, hash2)
	}
}

func decodeHex(in string) []byte {
	payload, err := hex.DecodeString(in)
	if err != nil {
		panic(err)
	}
	return payload
}

func TestTest(t *testing.T) {
	items := []struct {
		key   []byte
		value []byte
		root  []byte
	}{
		{common.Hex2Bytes("d293f7799bd6c75b82c2802542e2999c14f47e35"), common.Hex2Bytes("01c580648001c0"), common.Hex2Bytes("a40be308ce374a97528c11381f1938b9ecdce54fe84d3a79194f4f0cf6e2cee7")},
		{common.Hex2Bytes("ebbbacfb87fbfdec9011cfad2462782b3f8a8d88"), common.Hex2Bytes("01c564808001c0"), common.Hex2Bytes("bebfd49040b60a3c2905b57f9e2ab0cf7f1d49b5946cbb456a612aa75b57d382")},
		{common.Hex2Bytes("de20ec601c1d770a9ec6e89b2639cd63203514c4"), common.Hex2Bytes("01f849c580808001c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0de75942ed4731d491798b4a82bc5937553e715a97b76fc5987e35ee3cd2ee68380"), common.Hex2Bytes("4a4669650a2fa9da4ac84e32240bf5f780d04a95d277c48f244536c64b8742cc")},
		{common.Hex2Bytes("e8170332ea5a606146e5a9e9deb8dcec0287047c"), common.Hex2Bytes("01c580808001c0"), common.Hex2Bytes("b725baf13982da7a87f7d97901e02fd05d186e1b8abb2cf5fd3b9bcb5ec125c7")},
		{common.Hex2Bytes("fe90e344274e129d656e03ffd0d0dc0b6518788d"), common.Hex2Bytes("01e680640102a1038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75"), common.Hex2Bytes("93d2881f108149b0b1d0d87305c324905d8877f687ca6c4135d75905200ecf80")},
		{common.Hex2Bytes("7bdf109bf068c37c97d5c84196417e034320f3fc"), common.Hex2Bytes("01c781c881c88001c0"), common.Hex2Bytes("b03cb4d3dc6c82a58b0661f3a2d342a9334f930dbe394bec4f9c528f86526860")},
		{common.Hex2Bytes("69470b1abc45767a122bc5ebb6d8a1c97e4ff935"), common.Hex2Bytes("01f84bc782012c808001c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0d058a2d3336759c22976856de49b828b8282e64b9d2b2d0d0d94fc44928d8e4c80"), common.Hex2Bytes("0a1e51568e4b084ea6054f65a12d318fa996526fdcdb5f3c0deae08b2228ffbd")},
		{common.Hex2Bytes("115cd038daf5cc477c7116beab167e550f41b0d4"), common.Hex2Bytes("01c7820190808001c0"), common.Hex2Bytes("2a1784dfee1338f532ccd181c1848bddc1153b0100314345acf761725d12655d")},
		{common.Hex2Bytes("74ef9c1339963462581a5b96720711e7cfec22eb"), common.Hex2Bytes("01f84bc7808201f48001c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a067cbae6de159c9d9be7017bb0a3b6be6770c0233c5f4d476523728e0520ca7bb80"), common.Hex2Bytes("aab328f3aaad005d5b5bb45b945640b9d1612ca445806e471e2f0ca2457ea1fd")},
		{common.Hex2Bytes("5d76c9950b78dcfa47ec195f56d11a4afa8708f3"), common.Hex2Bytes("01f84dc98202588202588001c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a02a5787ab5c11885b8b30f1a3aea5c05d48e17eb18f94210555e34a3a965b655a80"), common.Hex2Bytes("1f359a878bdea26f8eecaa6b6fff8306b870d4b3b18871975aebc68f12c8ea51")},
	}

	trie, err := NewSecureTrie(common.Hash{}, NewDatabase(database.NewMemoryDBManager()), nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	flatTrie := newEmptyFlatTrie()
	for _, item := range items {
		err = trie.TryUpdate(item.key, item.value)
		if err != nil {
			t.Errorf("expected nil got %v", err)
		}
		err = flatTrie.TryUpdate(item.key, item.value)
		if err != nil {
			t.Errorf("expected nil got %v", err)
		}
		hash1, err := trie.Commit(nil)
		if err != nil {
			t.Errorf("expected nil got %v", err)
		}
		hash2, err := flatTrie.Commit(nil)
		if err != nil {
			t.Errorf("expected nil got %v", err)
		}
		if !bytes.Equal(hash1.Bytes(), hash2.Bytes()) {
			t.Errorf("expected %x got %x", hash1, hash2)
		}
	}
	root := trie.Hash()
	fmt.Printf("root: %x\n", root)
	t.Fatal("stop here")
}

func TestKairos(t *testing.T) {
	trie := newEmptyFlatTrie()
	trie.TryUpdate(common.Hex2Bytes("0000000000000000000000000000000000000400"), common.Hex2Bytes("02f849c580808003c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a06c39846f5ab402760078b7bfd16c99e687c75bcb5ec65ac8f3054bad18136f0980"))
	trie.TryUpdate(common.Hex2Bytes("4937a6f664630547f6b0c3c235c4f03a64ca36b1"), common.Hex2Bytes("01da8095446c3b15f9926687d2c40534fdb5640000000000008001c0"))

	sc, _ := NewSecureTrie(common.Hash{}, NewDatabase(database.NewMemoryDBManager()), nil)
	sc.TryUpdate(common.Hex2Bytes("0000000000000000000000000000000000000400"), common.Hex2Bytes("02f849c580808003c0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a06c39846f5ab402760078b7bfd16c99e687c75bcb5ec65ac8f3054bad18136f0980"))
	sc.TryUpdate(common.Hex2Bytes("4937a6f664630547f6b0c3c235c4f03a64ca36b1"), common.Hex2Bytes("01da8095446c3b15f9926687d2c40534fdb5640000000000008001c0"))

	root := trie.Hash()
	root2 := sc.Hash()
	fmt.Printf("root: %x\n", root)
	fmt.Printf("root2: %x\n", root2)
	t.Fatal("stop here")
}

func TestProve(t *testing.T) {
	trie := newEmptyFlatTrie()
	trie2, err := NewSecureTrie(common.Hash{}, NewDatabase(database.NewMemoryDBManager()), nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	//trie.TryUpdate(common.Hex2Bytes("d293f7799bd6c75b82c2802542e2999c14f47e35"), common.Hex2Bytes("01c580648001c0"))
	//trie2.TryUpdate(common.Hex2Bytes("d293f7799bd6c75b82c2802542e2999c14f47e35"), common.Hex2Bytes("01c580648001c0"))
	acc := genRandomAccount()
	buf := make([]byte, acc.EncodingLengthForHashing())
	acc.EncodeForHashing(buf)
	trie.TryUpdate(common.Hex2Bytes("d293f7799bd6c75b82c2802542e2999c14f47e35"), buf)
	trie2.TryUpdate(common.Hex2Bytes("d293f7799bd6c75b82c2802542e2999c14f47e35"), buf)

	proofTrie, _, err := trie.sd.GetCommitmentContext().Witness(context.Background(), trie2.Hash().Bytes(), "FlatTrie.Prove")
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	proofDb := database.NewMemoryDBManager()
	err = trie.Prove(common.Hex2Bytes("d293f7799bd6c75b82c2802542e2999c14f47e35"), 0, proofDb)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	/*rl := erigon_trie.NewRetainList(0)
	it := erigon_trie.NewIterator(proofTrie, rl, false)
	for {
		itemType, hex1, aValue, hash, value := it.Next()
		if itemType == erigon_trie.AccountStreamItem {
			fmt.Printf("proofTrie: %x\n", hex1)
			fmt.Printf("proofTrie: %x\n", value)
		}
		_, _ = aValue, hash
	}*/

	proof, err := proofTrie.Prove(common.Hex2Bytes("d293f7799bd6c75b82c2802542e2999c14f47e35"), 0, false)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	for _, p := range proof {
		fmt.Printf("proof: %x\n", p)
	}

	it2 := proofDb.GetMemDB().NewIterator(nil, nil)
	for it2.Next() {
		fmt.Printf("proofDb: %x\n", it2.Key())
		fmt.Printf("proofDb: %x\n", it2.Value())
	}

	val, err, _ := VerifyProof(trie2.Hash(), common.Hex2Bytes("d293f7799bd6c75b82c2802542e2999c14f47e35"), proofDb)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	if !bytes.Equal(val, common.Hex2Bytes("01c580648001c0")) {
		t.Errorf("expected 01c580648001c0 got %x", val)
	}
}
