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
	"bytes"
	"fmt"
	"testing"

	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/crypto"
	"github.com/kaiachain/kaia/storage/database"
	"github.com/kaiachain/kaia/storage/pathstate"
	pathtrie "github.com/kaiachain/kaia/storage/pathstate/trie"
)

// TestPathTrieRootMatchesSecureTrie verifies that the path-based account trie
// computes exactly the same root as the legacy hash-based SecureTrie for the
// same key/value set, across inserts, updates, and deletes, and that data
// survives a commit + reopen cycle.
func TestPathTrieRootMatchesSecureTrie(t *testing.T) {
	legacyDB := NewDatabase(database.NewMemoryDBManager())
	secure, err := NewSecureTrie(common.Hash{}, legacyDB, nil)
	if err != nil {
		t.Fatal(err)
	}

	psdb := pathstate.ForKV(database.NewMemDB())
	path, err := NewPathAccountTrie(psdb, common.Hash{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	type kv struct{ k, v []byte }
	var kvs []kv
	for i := 0; i < 1500; i++ {
		key := crypto.Keccak256([]byte(fmt.Sprintf("key-%d", i)))[:20] // address-like keys
		val := crypto.Keccak256([]byte(fmt.Sprintf("val-%d", i)))
		kvs = append(kvs, kv{key, val})
	}
	for _, e := range kvs {
		if err := secure.TryUpdate(e.k, e.v); err != nil {
			t.Fatal(err)
		}
		if err := path.TryUpdate(e.k, e.v); err != nil {
			t.Fatal(err)
		}
	}
	// Overwrite some, delete some.
	for i := 0; i < 300; i++ {
		newVal := crypto.Keccak256([]byte(fmt.Sprintf("newval-%d", i)))
		if err := secure.TryUpdate(kvs[i].k, newVal); err != nil {
			t.Fatal(err)
		}
		if err := path.TryUpdate(kvs[i].k, newVal); err != nil {
			t.Fatal(err)
		}
		kvs[i].v = newVal
	}
	for i := 300; i < 500; i++ {
		if err := secure.TryDelete(kvs[i].k); err != nil {
			t.Fatal(err)
		}
		if err := path.TryDelete(kvs[i].k); err != nil {
			t.Fatal(err)
		}
	}
	kvs = append(kvs[:300], kvs[500:]...)

	if secure.Hash() != path.Hash() {
		t.Fatalf("root mismatch: secure %x path %x", secure.Hash(), path.Hash())
	}

	// Commit the path trie into the path database and reopen at the new root.
	root, err := path.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	if root != secure.Hash() {
		t.Fatalf("committed root mismatch: secure %x path %x", secure.Hash(), root)
	}
	reopened, err := NewPathAccountTrie(psdb, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range kvs {
		got, err := reopened.TryGet(e.k)
		if err != nil {
			t.Fatalf("TryGet(%x): %v", e.k, err)
		}
		if !bytes.Equal(got, e.v) {
			t.Fatalf("TryGet(%x) = %x, want %x", e.k, got, e.v)
		}
	}

	// A second block on top: update a few keys and commit again.
	child := reopened
	for i := 0; i < 50; i++ {
		newVal := crypto.Keccak256([]byte(fmt.Sprintf("block2-%d", i)))
		if err := child.TryUpdate(kvs[i].k, newVal); err != nil {
			t.Fatal(err)
		}
		if err := secure.TryUpdate(kvs[i].k, newVal); err != nil {
			t.Fatal(err)
		}
	}
	root2, err := child.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	if root2 != secure.Hash() {
		t.Fatalf("second block root mismatch: secure %x path %x", secure.Hash(), root2)
	}
	if _, err := NewPathAccountTrie(psdb, root2, nil); err != nil {
		t.Fatal(err)
	}
}

// TestPathStorageTrieAggregation verifies that storage tries register their
// node sets with the account trie and everything lands in one layer.
func TestPathStorageTrieAggregation(t *testing.T) {
	psdb := pathstate.ForKV(database.NewMemDB())
	at, err := NewPathAccountTrie(psdb, common.Hash{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	opts := &TrieOpts{PathAccountTrie: at}

	addr := common.BytesToAddress(crypto.Keccak256([]byte("contract"))[:20])
	st, err := NewPathStorageTrie(psdb, addr, common.Hash{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		k := crypto.Keccak256([]byte(fmt.Sprintf("slot-%d", i)))
		v := crypto.Keccak256([]byte(fmt.Sprintf("data-%d", i)))[:8]
		if err := st.TryUpdate(k, v); err != nil {
			t.Fatal(err)
		}
	}
	storageRoot, err := st.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	if storageRoot == (common.Hash{}) || storageRoot == pathtrie.EmptyRootHash {
		t.Fatal("unexpected empty storage root")
	}

	// Put an account leaf referencing nothing in particular (opaque value)
	// and commit the aggregate.
	if err := at.TryUpdate(addr.Bytes(), storageRoot.Bytes()); err != nil {
		t.Fatal(err)
	}
	root, err := at.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Reopen both tries at the committed state and read a slot back.
	at2, err := NewPathAccountTrie(psdb, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	st2, err := NewPathStorageTrie(psdb, addr, storageRoot, &TrieOpts{PathAccountTrie: at2})
	if err != nil {
		t.Fatal(err)
	}
	k := crypto.Keccak256([]byte("slot-7"))
	want := crypto.Keccak256([]byte("data-7"))[:8]
	got, err := st2.TryGet(k)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("storage readback mismatch: got %x want %x", got, want)
	}
}
