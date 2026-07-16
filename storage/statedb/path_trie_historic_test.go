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
	"testing"

	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/storage/database"
	"github.com/kaiachain/kaia/storage/pathstate"
)

// newArchivePathDB returns an archive-enabled path-state database over a
// fresh in-memory store.
func newArchivePathDB(t *testing.T) *pathstate.Database {
	kv := database.NewMemDB()
	if err := kv.Put(pathstate.ArchiveMarkerKey, []byte{1}); err != nil {
		t.Fatal(err)
	}
	db := pathstate.ForKV(kv)
	if !db.ArchiveEnabled() {
		t.Fatal("archive marker not honored")
	}
	return db
}

// commitBlock opens the account trie at parentRoot, applies mutations, and
// commits, returning the new root.
func commitBlock(t *testing.T, db *pathstate.Database, parentRoot common.Hash, genesis bool, mutate func(at *PathAccountTrie)) common.Hash {
	opts := &TrieOpts{CommitGenesis: genesis}
	at, err := NewPathAccountTrie(db, parentRoot, opts)
	if err != nil {
		t.Fatal(err)
	}
	mutate(at)
	root, err := at.Commit(nil)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestHistoricPathTrieReads(t *testing.T) {
	db := newArchivePathDB(t)

	acct1 := common.BytesToAddress([]byte{0x11}).Bytes()
	acct2 := common.BytesToAddress([]byte{0x22}).Bytes()

	v1 := []byte("account1-v1")
	v1b := []byte("account1-v2")
	v2 := []byte("account2-v1")

	// Block 0 (genesis): acct1=v1, acct2=v2
	root0 := commitBlock(t, db, common.Hash{}, true, func(at *PathAccountTrie) {
		if err := at.TryUpdate(acct1, v1); err != nil {
			t.Fatal(err)
		}
		if err := at.TryUpdate(acct2, v2); err != nil {
			t.Fatal(err)
		}
	})
	// Block 1: acct1=v1b
	root1 := commitBlock(t, db, root0, false, func(at *PathAccountTrie) {
		if err := at.TryUpdate(acct1, v1b); err != nil {
			t.Fatal(err)
		}
	})
	// Block 2: delete acct2
	root2 := commitBlock(t, db, root1, false, func(at *PathAccountTrie) {
		if err := at.TryDelete(acct2); err != nil {
			t.Fatal(err)
		}
	})

	if n, ok := db.BlockOfRoot(root1); !ok || n != 1 {
		t.Fatalf("BlockOfRoot(root1) = %d, %v; want 1, true", n, ok)
	}

	checks := []struct {
		root common.Hash
		key  []byte
		want []byte
	}{
		{root0, acct1, v1},
		{root0, acct2, v2},
		{root1, acct1, v1b},
		{root1, acct2, v2},
		{root2, acct1, v1b},
		{root2, acct2, nil},
	}
	for i, c := range checks {
		ht, err := NewHistoricPathTrie(db, c.root, nil)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if ht.Hash() != c.root {
			t.Fatalf("case %d: Hash() = %x, want %x", i, ht.Hash(), c.root)
		}
		got, err := ht.TryGet(c.key)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if !bytes.Equal(got, c.want) {
			t.Fatalf("case %d: TryGet = %q, want %q", i, got, c.want)
		}
	}

	// Mutations must fail.
	ht, _ := NewHistoricPathTrie(db, root1, nil)
	if err := ht.TryUpdate(acct1, []byte("x")); err == nil {
		t.Fatal("historic trie accepted a write")
	}
}

func TestHistoricStorageWipeBarrier(t *testing.T) {
	db := newArchivePathDB(t)

	contract := common.BytesToAddress([]byte{0xc0})
	slotA := []byte("slot-a")
	slotB := []byte("slot-b")
	valA1 := []byte("value-a1")
	valB1 := []byte("value-b1")
	valA2 := []byte("value-a2")

	// Block 0: create contract with slots A and B.
	root0 := commitBlock(t, db, common.Hash{}, true, func(at *PathAccountTrie) {
		st, err := NewPathStorageTrie(db, contract, common.Hash{}, &TrieOpts{PathAccountTrie: at})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.TryUpdate(slotA, valA1); err != nil {
			t.Fatal(err)
		}
		if err := st.TryUpdate(slotB, valB1); err != nil {
			t.Fatal(err)
		}
		storageRoot, err := st.Commit(nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := at.TryUpdate(contract.Bytes(), storageRoot.Bytes()); err != nil {
			t.Fatal(err)
		}
	})

	// Block 1: selfdestruct the contract (account delete = storage wipe).
	root1 := commitBlock(t, db, root0, false, func(at *PathAccountTrie) {
		if err := at.TryDelete(contract.Bytes()); err != nil {
			t.Fatal(err)
		}
	})

	// Block 2: re-create the contract, writing only slot A.
	root2 := commitBlock(t, db, root1, false, func(at *PathAccountTrie) {
		st, err := NewPathStorageTrie(db, contract, common.Hash{}, &TrieOpts{PathAccountTrie: at})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.TryUpdate(slotA, valA2); err != nil {
			t.Fatal(err)
		}
		storageRoot, err := st.Commit(nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := at.TryUpdate(contract.Bytes(), storageRoot.Bytes()); err != nil {
			t.Fatal(err)
		}
	})

	readSlot := func(root common.Hash, slot []byte) []byte {
		ht, err := NewHistoricPathTrie(db, root, nil)
		if err != nil {
			t.Fatal(err)
		}
		st, err := NewHistoricStorageTrie(db, contract, common.Hash{}, &TrieOpts{HistoricAccountTrie: ht})
		if err != nil {
			t.Fatal(err)
		}
		got, err := st.TryGet(slot)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	// As of block 0: both slots live.
	if got := readSlot(root0, slotA); !bytes.Equal(got, valA1) {
		t.Fatalf("block0 slotA = %q, want %q", got, valA1)
	}
	if got := readSlot(root0, slotB); !bytes.Equal(got, valB1) {
		t.Fatalf("block0 slotB = %q, want %q", got, valB1)
	}
	// As of block 1 (after selfdestruct): both wiped.
	if got := readSlot(root1, slotA); got != nil {
		t.Fatalf("block1 slotA = %q, want nil (wiped)", got)
	}
	if got := readSlot(root1, slotB); got != nil {
		t.Fatalf("block1 slotB = %q, want nil (wiped)", got)
	}
	// As of block 2 (re-created): only slot A, with the new value; slot B must
	// NOT resurrect its pre-selfdestruct value.
	if got := readSlot(root2, slotA); !bytes.Equal(got, valA2) {
		t.Fatalf("block2 slotA = %q, want %q", got, valA2)
	}
	if got := readSlot(root2, slotB); got != nil {
		t.Fatalf("block2 slotB = %q, want nil (must not resurrect)", got)
	}
}
