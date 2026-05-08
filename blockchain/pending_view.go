// Copyright 2026 The kaia Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package blockchain

import (
	"sync"

	"github.com/kaiachain/kaia/blockchain/types"
	"github.com/kaiachain/kaia/common"
)

// pendingView is an eventually-consistent, lock-free read view of the
// pool.pending map. Writers under pool.mu publish per-account updates via
// set/delete; readers (miner) call snapshot() without taking pool.mu.
//
// Per-account slices are immutable from the consumer's perspective: they are
// snapshots of txList.cache captured at publish time. The txList may later
// re-slice or replace its own cache, but it never mutates the elements of a
// previously-published slice. Tx pointers are themselves immutable.
//
// snapshot() is NOT a consistent point-in-time view across accounts. Callers
// (block builder) tolerate cross-account staleness because each tx is
// re-validated at apply time.
type pendingView struct {
	accounts sync.Map // common.Address -> types.Transactions
}

func newPendingView() *pendingView { return &pendingView{} }

// set publishes a fresh slice for addr. Empty slices are deleted instead, so
// the view never carries empty-account entries.
func (v *pendingView) set(addr common.Address, txs types.Transactions) {
	if len(txs) == 0 {
		v.accounts.Delete(addr)
		return
	}
	v.accounts.Store(addr, txs)
}

func (v *pendingView) delete(addr common.Address) {
	v.accounts.Delete(addr)
}

// clear wipes the view. Only called from rare global events (SetGasPrice,
// Clear), never the steady-state writer path.
func (v *pendingView) clear() {
	v.accounts.Clear()
}

// snapshot returns a fresh outer map; the caller may mutate it in place
// (e.g., FilterTransactionWithBaseFee). Per-account slices are aliased and
// must be treated as read-only.
func (v *pendingView) snapshot() map[common.Address]types.Transactions {
	out := make(map[common.Address]types.Transactions)
	v.accounts.Range(func(k, val any) bool {
		out[k.(common.Address)] = val.(types.Transactions)
		return true
	})
	return out
}
