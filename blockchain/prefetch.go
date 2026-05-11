// Modifications Copyright 2024 The Kaia Authors

package blockchain

import (
	"context"

	"github.com/kaiachain/kaia/blockchain/state"
	"github.com/kaiachain/kaia/blockchain/types"
	"github.com/kaiachain/kaia/common"
)

type stateAtReader interface {
	StateAt(root common.Hash) (*state.StateDB, error)
}

// PrefetchBlockState warms the trieDB node cache via a disposable StateDB.
// ctx cancels on shutdown/superseded spec-exec so the goroutine doesn't leak.
func PrefetchBlockState(ctx context.Context, stateReader stateAtReader, parentRoot common.Hash, txs []*types.Transaction, signer types.Signer) {
	if stateReader == nil || len(txs) == 0 {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Warn("PrefetchBlockState recovered from panic", "err", r)
			}
		}()
		statedb, err := stateReader.StateAt(parentRoot)
		if err != nil {
			return
		}
		for _, tx := range txs {
			select {
			case <-ctx.Done():
				return
			default:
			}
			from, err := types.Sender(signer, tx)
			if err != nil {
				continue
			}
			statedb.Exist(from)
			to := tx.To()
			if to == nil {
				continue
			}
			// GetCodeHash already loads the recipient account trie node.
			if statedb.GetCodeHash(*to) == types.EmptyCodeHash {
				continue
			}
			// Contract call: warm bytecode and touch the zero slot only to force
			// lazy storage-trie initialization of the root node.
			statedb.GetCode(*to)
			statedb.GetState(*to, common.Hash{})
		}
	}()
}
