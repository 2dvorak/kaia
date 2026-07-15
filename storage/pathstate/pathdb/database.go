// Modifications Copyright 2026 The Kaia Authors
// Copyright 2022 The go-ethereum Authors
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
// This file is derived from triedb/pathdb/database.go (go-ethereum v1.13.15).
// State history (freezer) support and the snap-sync Disable/Enable machinery
// have been removed: this database only maintains the in-memory diff layers on
// top of a single persisted disk layer, so deep-reorg rollback is unsupported.

package pathdb

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/storage/database"
	"github.com/kaiachain/kaia/storage/pathstate/rawdb"
	"github.com/kaiachain/kaia/storage/pathstate/trienode"
	"github.com/kaiachain/kaia/storage/pathstate/triestate"
)

const (
	// maxDiffLayers is the maximum diff layers allowed in the layer tree.
	maxDiffLayers = 128

	// defaultCleanSize is the default memory allowance of clean cache.
	defaultCleanSize = 16 * 1024 * 1024

	// maxBufferSize is the maximum memory allowance of node buffer.
	// Too large nodebuffer will cause the system to pause for a long
	// time when write happens. Also, the largest batch that pebble can
	// support is 4GB, node will panic if batch size exceeds this limit.
	maxBufferSize = 256 * 1024 * 1024

	// DefaultBufferSize is the default memory allowance of node buffer
	// that aggregates the writes from above until it's flushed into the
	// disk. It's meant to be used once the initial sync is finished.
	// Do not increase the buffer size arbitrarily, otherwise the system
	// pause time will increase when the database writes happen.
	DefaultBufferSize = 64 * 1024 * 1024
)

// layer is the interface implemented by all state layers which includes some
// public methods and some additional methods for internal usage.
type layer interface {
	// Node retrieves the trie node with the node info. An error will be returned
	// if the read operation exits abnormally. For example, if the layer is already
	// stale, or the associated state is regarded as corrupted. Notably, no error
	// will be returned if the requested node is not found in database.
	Node(owner common.Hash, path []byte, hash common.Hash) ([]byte, error)

	// rootHash returns the root hash for which this layer was made.
	rootHash() common.Hash

	// stateID returns the associated state id of layer.
	stateID() uint64

	// parentLayer returns the subsequent layer of it, or nil if the disk was reached.
	parentLayer() layer

	// update creates a new layer on top of the existing layer diff tree with
	// the provided dirty trie nodes along with the state change set.
	//
	// Note, the maps are retained by the method to avoid copying everything.
	update(root common.Hash, id uint64, block uint64, nodes map[common.Hash]map[string]*trienode.Node, states *triestate.Set) *diffLayer

	// journal commits an entire diff hierarchy to disk into a single journal entry.
	// This is meant to be used during shutdown to persist the layer without
	// flattening everything down (bad for reorgs).
	journal(w io.Writer) error
}

// Config contains the settings for database.
type Config struct {
	StateHistory   uint64 // Number of recent blocks to maintain state history for (unused: state history disabled)
	CleanCacheSize int    // Maximum memory allowance (in bytes) for caching clean nodes
	DirtyCacheSize int    // Maximum memory allowance (in bytes) for caching dirty nodes
	ReadOnly       bool   // Flag whether the database is opened in read only mode.
}

// sanitize checks the provided user configurations and changes anything that's
// unreasonable or unworkable.
func (c *Config) sanitize() *Config {
	conf := *c
	if conf.DirtyCacheSize > maxBufferSize {
		logger.Warn("Sanitizing invalid node buffer size", "provided", common.StorageSize(conf.DirtyCacheSize), "updated", common.StorageSize(maxBufferSize))
		conf.DirtyCacheSize = maxBufferSize
	}
	return &conf
}

// Defaults contains default settings for Ethereum mainnet.
//
// StateHistory is intentionally left at zero because state history is disabled
// in this port.
var Defaults = &Config{
	CleanCacheSize: defaultCleanSize,
	DirtyCacheSize: DefaultBufferSize,
}

// ReadOnly is the config in order to open database in read only mode.
var ReadOnly = &Config{ReadOnly: true}

// Database is a multiple-layered structure for maintaining in-memory trie nodes.
// It consists of one persistent base layer backed by a key-value store, on top
// of which arbitrarily many in-memory diff layers are stacked. The memory diffs
// can form a tree with branching, but the disk layer is singleton and common to
// all.
//
// State history has been removed from this port, therefore reorgs deeper than
// the retained in-memory diff layers cannot be rolled back.
//
// At most one readable and writable database can be opened at the same time in
// the whole system which ensures that only one database writer can operate disk
// state.
type Database struct {
	// readOnly is the flag whether the mutation is allowed to be applied.
	// It will be set automatically when the database is journaled during
	// the shutdown to reject all following unexpected mutations.
	readOnly   bool              // Flag if database is opened in read only mode
	bufferSize int               // Memory allowance (in bytes) for caching dirty nodes
	config     *Config           // Configuration for database
	diskdb     database.Database // Persistent storage for matured trie nodes
	tree       *layerTree        // The group for all known layers
	lock       sync.RWMutex      // Lock to prevent mutations from happening at the same time
}

// New attempts to load an already existing layer from a persistent key-value
// store (with a number of memory layers from a journal). If the journal is not
// matched with the base persistent layer, all the recorded diff layers are discarded.
func New(diskdb database.Database, config *Config) *Database {
	if config == nil {
		config = Defaults
	}
	config = config.sanitize()

	db := &Database{
		readOnly:   config.ReadOnly,
		bufferSize: config.DirtyCacheSize,
		config:     config,
		diskdb:     diskdb,
	}
	// Construct the layer tree by resolving the in-disk singleton state
	// and in-memory layer journal.
	db.tree = newLayerTree(db.loadLayers())

	logger.Warn("Path-based state scheme is an experimental feature")
	return db
}

// Reader retrieves a layer belonging to the given state root.
func (db *Database) Reader(root common.Hash) (layer, error) {
	l := db.tree.get(root)
	if l == nil {
		return nil, fmt.Errorf("state %#x is not available", root)
	}
	return l, nil
}

// Update adds a new layer into the tree, if that can be linked to an existing
// old parent. It is disallowed to insert a disk layer (the origin of all). Apart
// from that this function will flatten the extra diff layers at bottom into disk
// to only keep 128 diff layers in memory by default.
//
// The passed in maps(nodes, states) will be retained to avoid copying everything.
// Therefore, these maps must not be changed afterwards.
func (db *Database) Update(root common.Hash, parentRoot common.Hash, block uint64, nodes *trienode.MergedNodeSet, states *triestate.Set) error {
	// Hold the lock to prevent concurrent mutations.
	db.lock.Lock()
	defer db.lock.Unlock()

	// Short circuit if the mutation is not allowed.
	if err := db.modifyAllowed(); err != nil {
		return err
	}
	if err := db.tree.add(root, parentRoot, block, nodes, states); err != nil {
		return err
	}
	// Keep 128 diff layers in the memory, persistent layer is 129th.
	// - head layer is paired with HEAD state
	// - head-1 layer is paired with HEAD-1 state
	// - head-127 layer(bottom-most diff layer) is paired with HEAD-127 state
	// - head-128 layer(disk layer) is paired with HEAD-128 state
	return db.tree.cap(root, maxDiffLayers)
}

// Commit traverses downwards the layer tree from a specified layer with the
// provided state root and all the layers below are flattened downwards. It
// can be used alone and mostly for test purposes.
func (db *Database) Commit(root common.Hash, report bool) error {
	// Hold the lock to prevent concurrent mutations.
	db.lock.Lock()
	defer db.lock.Unlock()

	// Short circuit if the mutation is not allowed.
	if err := db.modifyAllowed(); err != nil {
		return err
	}
	return db.tree.cap(root, 0)
}

// Recover rollbacks the database to a specified historical point. State history
// is disabled in this port, so rollback is never supported.
func (db *Database) Recover(root common.Hash, loader triestate.TrieLoader) error {
	return errors.New("state rollback is not supported (state history disabled)")
}

// Recoverable returns the indicator if the specified state is recoverable. State
// history is disabled in this port, so no state is ever recoverable.
func (db *Database) Recoverable(root common.Hash) bool {
	return false
}

// Close closes the trie database and releases the held resources.
func (db *Database) Close() error {
	db.lock.Lock()
	defer db.lock.Unlock()

	// Set the database to read-only mode to prevent all
	// following mutations.
	db.readOnly = true

	// Release the memory held by clean cache.
	db.tree.bottom().resetCache()
	return nil
}

// Size returns the current storage size of the memory cache in front of the
// persistent database layer.
func (db *Database) Size() (diffs common.StorageSize, nodes common.StorageSize) {
	db.tree.forEach(func(layer layer) {
		if diff, ok := layer.(*diffLayer); ok {
			diffs += common.StorageSize(diff.memory)
		}
		if disk, ok := layer.(*diskLayer); ok {
			nodes += disk.size()
		}
	})
	return diffs, nodes
}

// Initialized returns an indicator if the state data is already
// initialized in path-based scheme.
func (db *Database) Initialized(genesisRoot common.Hash) bool {
	var inited bool
	db.tree.forEach(func(layer layer) {
		if layer.rootHash() != emptyRootHash {
			inited = true
		}
	})
	return inited
}

// SetBufferSize sets the node buffer size to the provided value(in bytes).
func (db *Database) SetBufferSize(size int) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	if size > maxBufferSize {
		logger.Info("Capped node buffer size", "provided", common.StorageSize(size), "adjusted", common.StorageSize(maxBufferSize))
		size = maxBufferSize
	}
	db.bufferSize = size
	return db.tree.bottom().setBufferSize(db.bufferSize)
}

// Scheme returns the node scheme used in the database.
func (db *Database) Scheme() string {
	return rawdb.PathScheme
}

// modifyAllowed returns the indicator if mutation is allowed. This function
// assumes the db.lock is already held.
func (db *Database) modifyAllowed() error {
	if db.readOnly {
		return errDatabaseReadOnly
	}
	return nil
}
