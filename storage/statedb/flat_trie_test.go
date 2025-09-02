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
	"crypto/ecdsa"
	"math/big"
	"math/rand"
	"testing"

	"github.com/erigontech/erigon-lib/commitment"
	"github.com/erigontech/erigon-lib/kaiatrie"
	"github.com/erigontech/erigon-lib/state"
	"github.com/kaiachain/kaia/blockchain/types/account"
	"github.com/kaiachain/kaia/blockchain/types/accountkey"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/common/hexutil"
	"github.com/kaiachain/kaia/crypto"
	"github.com/kaiachain/kaia/params"
	"github.com/kaiachain/kaia/rlp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_FlatTrie_Import(t *testing.T) {
	t.Log(commitment.ModeDirect)
	t.Log(len(state.Schema))
	t.Log(kaiatrie.ModeRawBytes)
}

func Test_FlatTrie_Random(t *testing.T) {
	r := rand.New(rand.NewSource(42)) // for determinism
	accounts, storages := randTrie(t, r)

	// To use in other test files
	// fmt.Printf("accounts = [][2]string{\n")
	// for _, a := range accounts {
	// 	fmt.Printf("  {\"%s\", \"%s\"},\n", a[0], a[1])
	// }
	// fmt.Printf("}\n")

	// Correct answer calculated by SecureTrie
	stateRoot1, storageRoots1 := calcTrieRoots(t, func() trieInterface { return newEmptySecureTrie() }, func(common.Address) trieInterface { return newEmptySecureTrie() }, accounts, storages)

	// Check the answer with FlatTrie
	fnNewFlatAccountTrie := func() trieInterface {
		flatAccountTrie, err := NewFlatAccountTrie(&TrieOpts{
			BaseBlockNumber: 0,
			CommitGenesis:   true,
		})
		require.NoError(t, err)
		return flatAccountTrie
	}
	fnNewFlatStorageTrie := func(addr common.Address) trieInterface {
		flatStorageTrie, err := NewFlatStorageTrie(addr, &TrieOpts{
			BaseBlockNumber: 0,
			CommitGenesis:   true,
		})
		require.NoError(t, err)
		return flatStorageTrie
	}
	stateRoot2, storageRoots2 := calcTrieRoots(t, fnNewFlatAccountTrie, fnNewFlatStorageTrie, accounts, storages)

	assert.Equal(t, stateRoot1, stateRoot2)
	for addr, root := range storageRoots1 {
		assert.Equal(t, root, storageRoots2[addr])
	}
}

type trieInterface interface {
	TryUpdate(key, value []byte) error
	Hash() common.Hash
}

func calcTrieRoots(t *testing.T, fnNewAccountTrie func() trieInterface, fnNewStorageTrie func(common.Address) trieInterface, accounts [][2]string, storages [][3]string) (string, map[string]string) {
	accountTrie := fnNewAccountTrie()
	for i := 0; i < len(accounts); i++ {
		k, v := hexutil.MustDecode(accounts[i][0]), hexutil.MustDecode(accounts[i][1])
		require.NoError(t, accountTrie.TryUpdate(k, v))
	}
	stateRoot := accountTrie.Hash().Hex()
	t.Logf("stateRoot = %s", stateRoot)

	storageTries := make(map[string]trieInterface)
	storageRoots := make(map[string]string)
	for i := 0; i < len(storages); i++ {
		addrS, k, v := storages[i][0], hexutil.MustDecode(storages[i][1]), hexutil.MustDecode(storages[i][2])
		if _, ok := storageTries[addrS]; !ok {
			storageTries[addrS] = fnNewStorageTrie(common.HexToAddress(addrS))
		}
		// as in state_object.go:updateStorageTrie
		v, _ = rlp.EncodeToBytes(bytes.TrimLeft(v, "\x00"))
		require.NoError(t, storageTries[addrS].TryUpdate(k, v))
	}
	for addr, trie := range storageTries {
		storageRoots[addr] = trie.Hash().Hex()
		t.Logf("storageRoot[%s] = %s", addr, storageRoots[addr])
	}

	return stateRoot, storageRoots
}

// Random accounts generator

func randTrie(t *testing.T, r *rand.Rand) ([][2]string, [][3]string) {
	accounts := make([][2]string, 64)
	storages := make([][3]string, 0)
	for i := 0; i < len(accounts); i++ {
		if i%2 == 0 { // EOA
			accounts[i] = [2]string{randAddr(r).Hex(), hexutil.Encode(randEOA(t, r))}
			continue
		} else { // SCA
			addr := randAddr(r).Hex()
			storage := make([][3]string, r.Intn(64)) // [0, 63]
			for j := 0; j < len(storage); j++ {
				// value with some leading zeros
				value := randHash(r).Bytes()
				value = value[:r.Intn(32)]
				value = common.BytesToHash(value).Bytes()
				// as in state_object.go:updateStorageTrie
				value, _ = rlp.EncodeToBytes(bytes.TrimLeft(value[:], "\x00"))
				storage[j] = [3]string{addr, randHash(r).Hex(), hexutil.Encode(value)}
			}
			storageRoot := correctStorageRoot(storage)
			accounts[i] = [2]string{addr, hexutil.Encode(randSCA(t, r, storageRoot))}
			storages = append(storages, storage...)
		}
	}
	return accounts, storages
}

func correctStorageRoot(storage [][3]string) common.Hash {
	trie := newEmptySecureTrie()
	for i := 0; i < len(storage); i++ {
		k, v := []byte(storage[i][1]), []byte(storage[i][2])
		trie.TryUpdate(k, v)
	}
	return trie.Hash()
}

func randEOA(t *testing.T, r *rand.Rand) []byte {
	acc, err := account.NewAccountWithMap(account.ExternallyOwnedAccountType, map[account.AccountValueKeyType]interface{}{
		account.AccountValueKeyNonce:         uint64(r.Int()),
		account.AccountValueKeyBalance:       big.NewInt(r.Int63()),
		account.AccountValueKeyHumanReadable: false,
		account.AccountValueKeyAccountKey:    randAccountKey(r),
	})
	require.NoError(t, err)

	ser := account.NewAccountSerializerWithAccount(acc)
	data, err := rlp.EncodeToBytes(ser)
	require.NoError(t, err)
	return data
}

func randSCA(t *testing.T, r *rand.Rand, storageRoot common.Hash) []byte {
	acc, err := account.NewAccountWithMap(account.SmartContractAccountType, map[account.AccountValueKeyType]interface{}{
		account.AccountValueKeyNonce:         uint64(r.Int()),
		account.AccountValueKeyBalance:       big.NewInt(r.Int63()),
		account.AccountValueKeyHumanReadable: false,
		account.AccountValueKeyAccountKey:    accountkey.NewAccountKeyFail(),
		account.AccountValueKeyStorageRoot:   storageRoot,
		account.AccountValueKeyCodeHash:      randHash(r),
		account.AccountValueKeyCodeInfo:      params.CodeInfo(0x10),
	})
	require.NoError(t, err)

	ser := account.NewAccountSerializerWithAccount(acc)
	data, err := rlp.EncodeToBytes(ser)
	require.NoError(t, err)
	return data
}

func randAccountKey(r *rand.Rand) accountkey.AccountKey {
	ty := r.Intn(5)
	switch ty {
	case 0:
		return accountkey.NewAccountKeyLegacy()
	case 1:
		return accountkey.NewAccountKeyPublicWithValue(randPub(r))
	case 2:
		return accountkey.NewAccountKeyFail()
	case 3:
		n := r.Intn(9) + 1 // [1, MaxNumKeysForMultiSig]
		m := 1
		if n > 1 {
			m = r.Intn(n-1) + 1 // [1, n]
		}
		keys := make(accountkey.WeightedPublicKeys, n)
		for i := 0; i < n; i++ {
			keys[i] = accountkey.NewWeightedPublicKey(uint(r.Intn(10)), (*accountkey.PublicKeySerializable)(randPub(r)))
		}
		return accountkey.NewAccountKeyWeightedMultiSigWithValues(uint(m), keys)
	default:
		return accountkey.NewAccountKeyRoleBasedWithValues([]accountkey.AccountKey{
			randAccountKey(r),
			randAccountKey(r),
			randAccountKey(r),
		})
	}
}

func randPub(r *rand.Rand) *ecdsa.PublicKey {
	privB := make([]byte, 32)
	r.Read(privB)
	priv := crypto.ToECDSAUnsafe(privB)
	return &priv.PublicKey
}

func randAddr(r *rand.Rand) common.Address {
	h := make([]byte, 20)
	r.Read(h)
	return common.BytesToAddress(h)
}

func randHash(r *rand.Rand) common.Hash {
	h := make([]byte, 32)
	r.Read(h)
	return common.BytesToHash(h)
}
