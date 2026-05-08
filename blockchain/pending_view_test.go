// Copyright 2026 The kaia Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package blockchain

import (
	"testing"

	"github.com/kaiachain/kaia/blockchain/types"
	"github.com/kaiachain/kaia/common"
	"github.com/stretchr/testify/assert"
)

func TestPendingView_SetDeleteSnapshot(t *testing.T) {
	v := newPendingView()
	addrA := common.HexToAddress("0x1")
	addrB := common.HexToAddress("0x2")
	txsA := types.Transactions{types.NewTransaction(0, addrA, nil, 0, nil, nil)}
	txsB := types.Transactions{types.NewTransaction(0, addrB, nil, 0, nil, nil)}

	v.set(addrA, txsA)
	v.set(addrB, txsB)
	snap := v.snapshot()
	assert.Len(t, snap, 2)
	assert.Equal(t, txsA, snap[addrA])
	assert.Equal(t, txsB, snap[addrB])

	// set with empty slice removes the entry.
	v.set(addrA, nil)
	snap = v.snapshot()
	assert.Len(t, snap, 1)
	_, ok := snap[addrA]
	assert.False(t, ok)

	v.delete(addrB)
	assert.Empty(t, v.snapshot())
}

func TestPendingView_SnapshotIsolatesOuterMap(t *testing.T) {
	v := newPendingView()
	addr := common.HexToAddress("0x1")
	v.set(addr, types.Transactions{types.NewTransaction(0, addr, nil, 0, nil, nil)})

	consumer := v.snapshot()
	delete(consumer, addr) // mutate caller's outer map

	// Subsequent snapshot must still contain the entry.
	again := v.snapshot()
	assert.Contains(t, again, addr)
}

func TestPendingView_Clear(t *testing.T) {
	v := newPendingView()
	for i := 0; i < 32; i++ {
		addr := common.BigToAddress(common.Big1)
		addr[0] = byte(i)
		v.set(addr, types.Transactions{types.NewTransaction(0, addr, nil, 0, nil, nil)})
	}
	assert.Len(t, v.snapshot(), 32)

	v.clear()
	assert.Empty(t, v.snapshot())
}
