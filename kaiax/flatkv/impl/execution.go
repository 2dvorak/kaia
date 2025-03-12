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

package impl

import (
	"bytes"

	"github.com/kaiachain/kaia/blockchain/types"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/rlp"
)

func (k *FlatKVModule) PostInsertBlock(block *types.Block) error {
	key := append(common.Int64ToByteBigEndian(block.NumberU64()), block.Hash().Bytes()...)
	io := bytes.NewBuffer(nil)
	if err := rlp.Encode(io, block.Header()); err != nil {
		return err
	}
	value := io.Bytes()
	if err := k.Put(key, value); err != nil {
		return err
	}
	return nil
}
