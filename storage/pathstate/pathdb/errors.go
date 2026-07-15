// Modifications Copyright 2026 The Kaia Authors
// Copyright 2023 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.
//
// This file is derived from triedb/pathdb/errors.go (go-ethereum v1.13.15).

package pathdb

import (
	"errors"
	"fmt"

	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/common/hexutil"
)

var (
	// errDatabaseReadOnly is returned if the database is opened in read only mode
	// to prevent any mutation.
	errDatabaseReadOnly = errors.New("read only")

	// errSnapshotStale is returned from data accessors if the underlying layer
	// layer had been invalidated due to the chain progressing forward far enough
	// to not maintain the layer's original state.
	errSnapshotStale = errors.New("layer stale")

	// errStateUnrecoverable is returned if state is required to be reverted to
	// a destination without associated state history available.
	errStateUnrecoverable = errors.New("state is unrecoverable")

	// errUnexpectedNode is returned if the requested node with specified path is
	// not hash matched with expectation.
	errUnexpectedNode = errors.New("unexpected node")
)

func newUnexpectedNodeError(loc string, expHash common.Hash, gotHash common.Hash, owner common.Hash, path []byte, blob []byte) error {
	blobHex := "nil"
	if len(blob) > 0 {
		blobHex = hexutil.Encode(blob)
	}
	return fmt.Errorf("%w, loc: %s, node: (%x %v), %x!=%x, blob: %s", errUnexpectedNode, loc, owner, path, expHash, gotHash, blobHex)
}
