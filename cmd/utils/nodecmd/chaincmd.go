// Modifications Copyright 2024 The Kaia Authors
// Modifications Copyright 2018 The klaytn Authors
// Copyright 2015 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.
//
// This file is derived from cmd/geth/chaincmd.go (2018/06/04).
// Modified and improved for the klaytn development.
// Modified and improved for the Kaia development.

package nodecmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/kaiachain/kaia/blockchain"
	"github.com/kaiachain/kaia/blockchain/types"
	"github.com/kaiachain/kaia/blockchain/types/account"
	"github.com/kaiachain/kaia/cmd/utils"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/common/hexutil"
	"github.com/kaiachain/kaia/governance"
	"github.com/kaiachain/kaia/log"
	"github.com/kaiachain/kaia/params"
	"github.com/kaiachain/kaia/rlp"
	"github.com/kaiachain/kaia/storage/database"
	"github.com/kaiachain/kaia/storage/statedb"
	"github.com/urfave/cli/v2"
)

var logger = log.NewModuleLogger(log.CMDUtilsNodeCMD)

var (
	InitCommand = &cli.Command{
		Action:    initGenesis,
		Name:      "init",
		Usage:     "Bootstrap and initialize a new genesis block",
		ArgsUsage: "<genesisPath>",
		Flags: []cli.Flag{
			utils.DbTypeFlag,
			utils.SingleDBFlag,
			utils.NumStateTrieShardsFlag,
			utils.DynamoDBTableNameFlag,
			utils.DynamoDBRegionFlag,
			utils.DynamoDBIsProvisionedFlag,
			utils.DynamoDBReadCapacityFlag,
			utils.DynamoDBWriteCapacityFlag,
			utils.DynamoDBReadOnlyFlag,
			utils.LevelDBCompressionTypeFlag,
			utils.DataDirFlag,
			utils.ChainDataDirFlag,
			utils.RocksDBSecondaryFlag,
			utils.RocksDBCacheSizeFlag,
			utils.RocksDBDumpMallocStatFlag,
			utils.RocksDBFilterPolicyFlag,
			utils.RocksDBCompressionTypeFlag,
			utils.RocksDBBottommostCompressionTypeFlag,
			utils.RocksDBDisableMetricsFlag,
			utils.RocksDBMaxOpenFilesFlag,
			utils.RocksDBCacheIndexAndFilterFlag,
			utils.OverwriteGenesisFlag,
			utils.LivePruningFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The init command initializes a new genesis block and definition for the network.
This is a destructive action and changes the network in which you will be
participating.

It expects the genesis file as argument.`,
	}

	DumpGenesisCommand = &cli.Command{
		Action:    dumpGenesis,
		Name:      "dumpgenesis",
		Usage:     "Dumps genesis block JSON configuration to stdout",
		ArgsUsage: "",
		Flags: []cli.Flag{
			utils.MainnetFlag,
			utils.KairosFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The dumpgenesis command dumps the genesis block configuration in JSON format to stdout.`,
	}

	DbGetCommand = &cli.Command{
		Action:    dbGet,
		Name:      "dbget",
		Usage:     "Read a key from the underlying key-value database",
		ArgsUsage: "",
		Flags: []cli.Flag{
			utils.MainnetFlag,
			utils.KairosFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The dumpgenesis command dumps the genesis block configuration in JSON format to stdout.`,
	}

	IterTrieCommand = &cli.Command{
		Action:    iterTrie,
		Name:      "itertrie",
		Usage:     "Iterate over the trie and count the number of nodes by their types",
		ArgsUsage: "",
	}
)

func dbGet(ctx *cli.Context) error {
	dbname := ctx.Args().First()
	key := ctx.Args().Get(1)

	// Open an initialise both full and light databases
	stack := MakeFullNode(ctx)
	parallelDBWrite := !ctx.Bool(utils.NoParallelDBWriteFlag.Name)
	singleDB := ctx.Bool(utils.SingleDBFlag.Name)
	numStateTrieShards := ctx.Uint(utils.NumStateTrieShardsFlag.Name)

	dbtype := database.DBType(ctx.String(utils.DbTypeFlag.Name)).ToValid()
	if len(dbtype) == 0 {
		logger.Crit("invalid dbtype", "dbtype", ctx.String(utils.DbTypeFlag.Name))
	}
	dbc := &database.DBConfig{
		Dir: "chaindata", DBType: dbtype, ParallelDBWrite: parallelDBWrite,
		SingleDB: singleDB, NumStateTrieShards: numStateTrieShards,
		LevelDBCacheSize: 0, PebbleDBCacheSize: 0, OpenFilesLimit: 0,
	}
	chainDB := stack.OpenDatabase(dbc)
	defer chainDB.Close()

	var dbEntryType database.DBEntryType
	switch dbname {
	case "header", "h":
		dbEntryType = 1 // headerDB
	case "body", "b":
		dbEntryType = database.BodyDB
	case "state", "s":
		dbEntryType = database.StateTrieDB
	default:
		return fmt.Errorf("unknown dbname '%s'", dbname)
	}
	db := chainDB.GetDatabase(dbEntryType)
	//fmt.Printf("Opening DB name '%s' entry '%d'\n", dbname, dbEntryType)

	keyBytes, err := hexutil.Decode(key)
	if err != nil {
		return err
	}

	// CanonicalHash(0)  "h" + numBE + "n" -> hash
	// key 0x6800000000000000006e
	// val 0xc72e5293c3c3ba38ed8ae910f780e4caaa9fb95e79784f7ab74c3c262ea7137e
	// hash := chainDB.ReadCanonicalHash(0)
	// fmt.Printf("%x\n", hash)

	// Header(0, 0xcf...)  "h" + numBE + hash -> rlp(header)
	// key 0x680000000000000000c72e5293c3c3ba38ed8ae910f780e4caaa9fb95e79784f7ab74c3c262ea7137e
	// val 0xf9....
	// rlp decode `ken dbget header 0x680000000000000000c72e5293c3c3ba38ed8ae910f780e4caaa9fb95e79784f7ab74c3c262ea7137e` | jq -r ".[2]"
	// stateRoot 23a9977c16397aa93fc8caf303abdf054e92adb2b99c5f35b89af6566d1a8cd0

	// towards account address 0x854ca8508c8be2bb1f3c244045786410cb7d5d0a
	// echo '854ca8508c8be2bb1f3c244045786410cb7d5d0a' | xxd -r -p | keccak-256sum
	// secure account address b408da3d631c0b1216ba459576b64c83dbb43f1d120f1f99b253cf8f03fd7343
	//
	// TrieNode(hash)  hash -> node
	//
	// key 0x23a9977c16397aa93fc8caf303abdf054e92adb2b99c5f35b89af6566d1a8cd0
	// val extension node[0xb] = a809f9a29d68fe866e414e4736330e1a598f63818adb822d2ef4a8e6991d43ab
	//
	// key 0xa809f9a29d68fe866e414e4736330e1a598f63818adb822d2ef4a8e6991d43ab
	// val extension node[0x4] = 34fbba9b7b56524bccbef3172898af3b25bdc991db80131fe54ad042ec52e45e
	//
	// key 0x34fbba9b7b56524bccbef3172898af3b25bdc991db80131fe54ad042ec52e45e
	// val 01ce80893635c9adc5dea000008001c0 = 0x01 (EOA type) + 0xce80893635c9adc5dea000008001c0 (rlp(account))
	//     = ["","3635c9adc5dea00000","","01",[]] = [nonce, balance, humanReadable, keytype, key]

	// keyBytes = append(append([]byte("h"), common.Int64ToByteBigEndian(0)...), []byte("n")...)

	// address book
	// first transaction 1021409
	// 128 multiple would be 1021440
	// stateroot 0x965730f029c4017f252105a6dc8f59efcb0a78edd4e73c1b1bf58e87669ba2c7

	// towards account address 0x0000000000000000000000000000000000000400
	// secure account address 0xb6b2f533015b984fcca3017c4f65e78a2c013f37867ff35e58a7b7e801cefa7a

	// key 0x965730f029c4017f252105a6dc8f59efcb0a78edd4e73c1b1bf58e87669ba2c7
	// val extension node[0xb] = 867ae43d846631c26374bcaa918e6fa023eab8e222f4948d84bc3f80c77f000d

	// key 0x867ae43d846631c26374bcaa918e6fa023eab8e222f4948d84bc3f80c77f000d
	// val extension node[0x4] = 048cfacd231ca8142b5f4892b51ef21f8e6987d4005acf552ee5e7cb825cd6e4

	// key 0x048cfacd231ca8142b5f4892b51ef21f8e6987d4005acf552ee5e7cb825cd6e4
	// val extension node [0xb] = 02d5f909b9a30baaf329ad705632f8d1a75907b2f987f86cf48c5d203217db98

	// key 0x02d5f909b9a30baaf329ad705632f8d1a75907b2f987f86cf48c5d203217db98
	// val leaf node = 02f849c580808003c0a01f591f3165167de9239aa286740d80559397eba6863a1c38fb4f3d6bea6aab2ba06c39846f5ab402760078b7bfd16c99e687c75bcb5ec65ac8f3054bad18136f0980

	// rlp decode = [["","","","03",[]],"1f591f3165167de9239aa286740d80559397eba6863a1c38fb4f3d6bea6aab2b","6c39846f5ab402760078b7bfd16c99e687c75bcb5ec65ac8f3054bad18136f09",""]

	// state root 0x1f591f3165167de9239aa286740d80559397eba6863a1c38fb4f3d6bea6aab2b
	// towards slot index 0
	// secure slot index 5380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312a

	// key 0x1f591f3165167de9239aa286740d80559397eba6863a1c38fb4f3d6bea6aab2b
	// val extension node[0x5] = 67ab18c91017ae7efe795c8929b36c8d5299610de8737229c5e57a94d66b9540

	// key 0x67ab18c91017ae7efe795c8929b36c8d5299610de8737229c5e57a94d66b9540
	// val leaf node = 949c95f812f36ac26d7a9b2eac26eaaed11b2fc6bc

	val, err := db.Get(keyBytes)
	if err != nil {
		return err
	}

	fmt.Printf("0x%x\n", val)

	return nil
}

var emptyRoot = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

type TrieStat struct {
	leafCount, leafSize, midCount, midSize uint64
}

func (s *TrieStat) Add(other *TrieStat) {
	s.leafCount += other.leafCount
	s.leafSize += other.leafSize
	s.midCount += other.midCount
	s.midSize += other.midSize
}

type TotalStat struct {
	accountStat   *TrieStat
	storageStat   *TrieStat
	storageBySize map[uint64]*TrieStat // keyed by (number of leaf / 10)
	codeHashes    map[string]uint64    // codehash -> size. During trie iteration, codeHashes[hash] = 0. After the iteration, sizes are filled.
	codeSize      uint64
	mu            sync.Mutex
}

type counts struct {
	accLeafCount   uint64
	accInnerCount  uint64
	accLeafSize    uint64
	accInnerSize   uint64
	strgLeafCount  uint64
	strgInnerCount uint64
	strgLeafSize   uint64
	strgInnerSize  uint64
	codeSize       uint64
}

// iterTrie gets the db name from the flag then iterates over the trie and count the number of nodes by their types.
// Also, it calculates the total size of each type of nodes.
// It prints the results to stdout.
func iterTrie(ctx *cli.Context) error {
	dbName := ctx.Args().First()
	if len(dbName) == 0 {
		return fmt.Errorf("dbname is not set")
	}

	// Open an initialise both full and light databases
	stack := MakeFullNode(ctx)
	parallelDBWrite := !ctx.Bool(utils.NoParallelDBWriteFlag.Name)
	singleDB := ctx.Bool(utils.SingleDBFlag.Name)
	numStateTrieShards := ctx.Uint(utils.NumStateTrieShardsFlag.Name)

	dbtype := database.DBType(ctx.String(utils.DbTypeFlag.Name)).ToValid()
	if len(dbtype) == 0 {
		logger.Crit("invalid dbtype", "dbtype", ctx.String(utils.DbTypeFlag.Name))
	}
	dbc := &database.DBConfig{
		Dir: "chaindata", DBType: dbtype, ParallelDBWrite: parallelDBWrite,
		SingleDB: singleDB, NumStateTrieShards: numStateTrieShards,
		LevelDBCacheSize: 0, PebbleDBCacheSize: 0, OpenFilesLimit: 0,
	}
	chainDB := stack.OpenDatabase(dbc)
	defer chainDB.Close()

	var dbEntryType database.DBEntryType
	switch dbName {
	case "header", "h":
		dbEntryType = 1 // headerDB
	case "body", "b":
		dbEntryType = database.BodyDB
	case "state", "s":
		dbEntryType = database.StateTrieDB
	default:
		return fmt.Errorf("unknown dbname '%s'", dbName)
	}
	db := chainDB.GetDatabase(dbEntryType)
	_ = db

	/*
		// Wrap the database in a DBManager
		dbManager := database.NewDBManager(db)

		// Use dbManager instead of db
		stateDB := statedb.NewDatabase(dbManager)

		// Use stateDB instead of db
		trie, err := statedb.NewTrie(common.Hash{}, stateDB, nil)
		if err != nil {
			return err
		}*/

	sdb := statedb.NewDatabase(chainDB)
	var trie *statedb.Trie
	var err error
	root := ctx.Args().Get(1)
	if len(root) != 0 {
		rootBuf, err := hexutil.Decode(root)
		if err != nil {
			return err
		}
		rootHash := common.BytesToHash(rootBuf)
		trie, err = statedb.NewTrie(rootHash, sdb, nil)
		if err != nil {
			return err
		}
	} else {
		trie, err = statedb.NewTrie(common.Hash{}, sdb, nil)
		if err != nil {
			return err
		}
	}

	stat := &TotalStat{
		accountStat:   &TrieStat{},
		storageStat:   &TrieStat{},
		storageBySize: make(map[uint64]*TrieStat),
		codeHashes:    make(map[string]uint64),
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			doIterFrom(i, chainDB.GetStateTrieDB(), sdb, trie, stat)
		}()
	}
	wg.Wait()

	for hash := range stat.codeHashes {
		blob := chainDB.ReadCode(common.HexToHash(hash))
		stat.codeHashes[hash] = uint64(len(blob))
		stat.codeSize += uint64(len(blob))
	}
	stat.codeHashes = nil // too much data will be spewed.
	spew.Dump(stat)

	/*
		//var leafCount uint64
		//var innerCount uint64
		//var leafSize uint64
		//var innerSize uint64
		//var count uint64

		//counts := &counts{}
		//countsMu := &sync.RWMutex{}

		startTime := time.Now()
		mu := &sync.RWMutex{}
		// use map to prevent adding up bytecode size for same code hash
		codeHashMap := make(map[common.Hash]struct{})

		innerSizeMap := make(map[uint64]uint64)
		isMu := &sync.RWMutex{}
		leafSizeMap := make(map[uint64]uint64)
		lsMu := &sync.RWMutex{}

		var wg sync.WaitGroup
		numRoutines := 16
		//ch := make(chan int, numRoutines)

		for i := 0; i < numRoutines; i++ {
			wg.Add(1)
			// divide 0x0 to 0xf into numRoutines parts
			//iterStart := []byte{byte(i * (0x100 / numRoutines))}
			go func() {
				defer wg.Done()
				doIterTrie(byte(i*0x10), chainDB, db, trie, startTime, codeHashMap, mu, innerSizeMap, isMu, leafSizeMap, lsMu)
			}()
		}
		wg.Wait()
		//return nil
		/*

			iter := trie.NodeIterator([]byte{byte(0xa0)})
			for iter.Next(true) {
				count++
				fmt.Printf("path: %x\n", iter.Path())
				if count%10000 == 0 {
					elapsed := time.Since(startTime)
					fmt.Printf("path: %x, elapsed: %s\n", iter.Path(), elapsed)
				}

				// NOTE preorder traversal, print path in every 10000th iter then estimate total time
				// if it takes too long, try with lower block number

				//fmt.Printf("key: %x, val: %x\n", iter.Path(), iter.Hash())
				if iter.Leaf() {
					//fmt.Printf("leaf key: %x, val: %x\n", iter.LeafKey(), iter.LeafBlob())
					leafCount++
					blob := iter.LeafBlob()
					leafSize += uint64(len(blob))

					// check if block has contract account data
					serializer := account.NewAccountSerializer()
					if err := rlp.DecodeBytes(blob, serializer); err != nil {
						logger.Error("Failed to decode state object", "err", err)
						return nil
					}
					acc := serializer.GetAccount()
					if acc.Type() != account.SmartContractAccountType {
						continue
					}
					contract, true := acc.(*account.SmartContractAccount)
					if !true {
						return nil
					}

					// get storage root and code hash
					storageRoot := contract.GetStorageRoot()
					codeHashBytes := contract.GetCodeHash()
					codeHash := common.BytesToHash(codeHashBytes)

					wg.Add(1)
					ch <- 1
					go func() {
						defer func() {
							wg.Done()
							<-ch
						}()
						doIterStorageTrie(storageRoot, codeHash, chainDB, db, startTime, codeHashMap, mu, innerSizeMap, isMu, leafSizeMap, lsMu, counts, countsMu)
					}()
				} else {
					val, err := db.Get(iter.Hash().Bytes())
					if err != nil {
						fmt.Printf("err: %v, key: %x\n", err, iter.Hash())
						return err
					}
					//fmt.Printf("key: %x, val: %x\n", iter.Hash(), val)
					innerCount++
					innerSize += uint64(len(val))
				}
				continue
				/*
					if bytes.Equal(iter.Hash().Bytes(), common.Hash{}.Bytes()) {
						continue
					}
					val, err := db.Get(iter.Hash().Bytes())
					if err != nil {
						fmt.Printf("err: %v, key: %x\n", err, iter.Hash())
						return err
					}
					fmt.Printf("key: %x, val: %x\n", iter.Hash(), val)
					node, err := statedb.DecodeNode(iter.Hash().Bytes(), val)
					if err != nil {
						fmt.Printf("err: %v, key: %x\n", err, iter.Hash())
						return err
					}
					fmt.Printf("node type: %v\n", reflect.TypeOf(node))
			}
		//wg.Wait()

		//fmt.Printf("leafCount: %d, innerCount: %d, leafSize: %d, innerSize: %d\n", leafCount, innerCount, leafSize, innerSize)
		//fmt.Printf("codeSize: %d\n", counts.codeSize)
		//fmt.Printf("strgLeafCount: %d, strgInnerCount: %d, strgLeafSize: %d, strgInnerSize: %d\n", counts.strgLeafCount, counts.strgInnerCount, counts.strgLeafSize, counts.strgInnerSize)
		for k, v := range innerSizeMap {
			fmt.Printf("innerSizeMap[%d]: %d\n", k, v)
		}
		for k, v := range leafSizeMap {
			fmt.Printf("leafSizeMap[%d]: %d\n", k, v)
		}*/

	return nil

}

// Iterate from [0x10*index, 0x10*(index+1))
func doIterFrom(index int, db database.Database, sdb *statedb.Database, trie *statedb.Trie, stat *TotalStat) {
	var (
		startPrefix = byte(0x10 * index)
		endPrefix   = byte(0x10 * (index + 1))
	)

	iter := trie.NodeIterator([]byte{startPrefix})
	for iter.Next(true) {
		path := iter.Path()
		if len(path) > 0 && path[0] > endPrefix {
			break
		}

		if iter.Leaf() {
			blob := iter.LeafBlob()

			// Record account leaf
			stat.mu.Lock()
			stat.accountStat.leafCount++
			stat.accountStat.leafSize += uint64(len(blob))
			stat.mu.Unlock()

			// Iterate storage trie if exists
			serializer := account.NewAccountSerializer()
			if err := rlp.DecodeBytes(blob, serializer); err != nil {
				fmt.Printf("Error decoding account blob=%x err=%v", blob, err)
				return
			}
			acc := serializer.GetAccount()
			if pacc := account.GetProgramAccount(acc); pacc != nil {
				// Record code hash
				codeHash := hexutil.Encode(pacc.GetCodeHash())
				stat.mu.Lock()
				stat.codeHashes[codeHash] = 0
				stat.mu.Unlock()

				// Iterate storage trie
				doIterStorage(pacc.GetStorageRoot(), db, sdb, stat)
			}

		} else {
			blob, err := db.Get(iter.Hash().Bytes())
			if err != nil {
				fmt.Printf("err db.Get(account midHash) hash=%x err=%v", iter.Hash(), err)
			}

			// Record account mid
			stat.mu.Lock()
			stat.accountStat.midCount++
			stat.accountStat.midSize += uint64(len(blob))
			stat.mu.Unlock()
		}
	}
}

func doIterStorage(storageRoot common.ExtHash, db database.Database, sdb *statedb.Database, stat *TotalStat) {
	if storageRoot.Unextend() == emptyRoot {
		return
	}

	trie, err := statedb.NewStorageTrie(storageRoot, sdb, nil)
	if err != nil {
		fmt.Printf("error opening storage trie err=%v", err)
	}

	currStat := &TrieStat{} // to be added to stat.storageStat AND stat.storageBySize[...]
	iter := trie.NodeIterator(nil)
	for iter.Next(true) {
		if iter.Path() == nil || common.EmptyHash(iter.Hash()) {
			//continue
		}
		fmt.Printf("root: 0x%x, path: %x, isLeaf: %v\n", storageRoot, iter.Path(), iter.Leaf())

		if iter.Leaf() {
			blob := iter.LeafBlob()

			// Record storage leaf
			currStat.leafCount++
			currStat.leafSize += uint64(len(blob))
		} else {
			blob, err := db.Get(iter.Hash().Bytes())
			if err != nil {
				fmt.Printf("err db.Get(storage midHash) hash=%x err=%v", iter.Hash(), err)
			}

			// Record storage mid
			currStat.midCount++
			currStat.midSize += uint64(len(blob))
		}
	}

	sizeBucket := currStat.leafCount / 10

	stat.mu.Lock()
	stat.storageStat.Add(currStat)
	if stat.storageBySize[sizeBucket] == nil {
		stat.storageBySize[sizeBucket] = currStat
	} else {
		stat.storageBySize[sizeBucket].Add(currStat)
	}
	stat.mu.Unlock()
}

func doIterStorageTrie(storageRoot common.ExtHash, codeHash common.Hash, chainDB database.DBManager, db database.Database, startTime time.Time, codeHashMap map[common.Hash]struct{}, chMu *sync.RWMutex, innerSizeMap map[uint64]uint64, isMu *sync.RWMutex, leafSizeMap map[uint64]uint64, lsMu *sync.RWMutex, counts *counts, countsMu *sync.RWMutex) error {

	// add up bytecode size
	chMu.RLock()
	// check if code hash is already in the map
	if _, ok := codeHashMap[codeHash]; !ok {
		chMu.RUnlock()
		chMu.Lock()
		codeHashMap[codeHash] = struct{}{}
		chMu.Unlock()
		// fetch code from db
		//code, err := db.Get(codeHashBytes)

		//if err != nil {
		//	fmt.Printf("err getting code: %v, key: %x\n", err, codeHash)
		//	return err
		//}
		code := chainDB.ReadCode(codeHash)
		countsMu.Lock()
		counts.codeSize += uint64(len(code))
		countsMu.Unlock()
	} else {
		chMu.RUnlock()
	}

	if storageRoot.Unextend() == emptyRoot {
		return nil
	}

	storageTrie, err := statedb.NewStorageTrie(storageRoot, statedb.NewDatabase(chainDB), nil)
	//fmt.Printf("storageTrie: %v\n", storageTrie)
	if err != nil {
		fmt.Printf("err getting storage trie: %v, key: %x\n", err, storageRoot)
		return err
	}

	// iterate over the storage trie
	var storageLeafCount uint64
	var storageInnerCount uint64
	var storageLeafSize uint64
	var storageInnerSize uint64
	storageIter := storageTrie.NodeIterator([]byte{})
	for storageIter.Next(true) {
		if storageIter.Leaf() {
			storageLeafCount++

			blob := storageIter.LeafBlob()
			countsMu.Lock()
			counts.strgLeafCount++
			counts.strgLeafSize += uint64(len(blob))
			countsMu.Unlock()
			storageLeafSize += uint64(len(blob))
		} else {
			if storageIter.Path() == nil {
				continue
			}
			if bytes.Equal(storageIter.Hash().Bytes(), common.Hash{}.Bytes()) {
				continue
			}
			storageInnerCount++
			val, err := db.Get(storageIter.Hash().Bytes())
			if err != nil {
				fmt.Printf("err getting storage node: %v, key: %x, path: %x\n", err, storageIter.Hash(), storageIter.Path())
				continue
			}
			countsMu.Lock()
			counts.strgInnerCount++
			counts.strgInnerSize += uint64(len(val))
			countsMu.Unlock()
			storageInnerSize += uint64(len(val))
		}
		// if storageLeafCount is <10, add the size to sizeMap with key 0
		// if storageLeafCount is <20, add the size to sizeMap with key 10
		// if storageLeafCount is <30, add the size to sizeMap with key 20
		// ...
		isMu.Lock()
		innerSizeMap[10*storageLeafCount/10] += storageInnerSize
		isMu.Unlock()
		lsMu.Lock()
		leafSizeMap[10*storageLeafCount/10] += storageLeafSize
		lsMu.Unlock()
	}
	return nil
}

func doIterTrie(iterStart byte, chainDB database.DBManager, db database.Database, trie *statedb.Trie, startTime time.Time, codeHashMap map[common.Hash]struct{}, chMu *sync.RWMutex, innerSizeMap map[uint64]uint64, isMu *sync.RWMutex, leafSizeMap map[uint64]uint64, lsMu *sync.RWMutex) error {
	var accLeafCount uint64
	var accInnerCount uint64
	var accLeafSize uint64
	var accInnerSize uint64
	var strgLeafCount uint64
	var strgInnerCount uint64
	var strgLeafSize uint64
	var strgInnerSize uint64
	var codeSize uint64
	var count uint64
	iter := trie.NodeIterator([]byte{iterStart})
	for iter.Next(true) {
		if iter.Path()[0] > iterStart/0x10 {
			break
		}
		count++
		if count%10000 == 0 {
			elapsed := time.Since(startTime)
			fmt.Printf("path: %x, elapsed: %s\n", iter.Path(), elapsed)
		}
		fmt.Printf("start: %x, path: %x\n", iterStart, iter.Path())

		// NOTE preorder traversal, print path in every 10000th iter then estimate total time
		// if it takes too long, try with lower block number

		//fmt.Printf("key: %x, val: %x\n", iter.Path(), iter.Hash())
		if iter.Leaf() {
			//fmt.Printf("leaf key: %x, val: %x\n", iter.LeafKey(), iter.LeafBlob())
			accLeafCount++
			blob := iter.LeafBlob()
			accLeafSize += uint64(len(blob))

			// check if block has contract account data
			serializer := account.NewAccountSerializer()
			if err := rlp.DecodeBytes(blob, serializer); err != nil {
				logger.Error("Failed to decode state object", "err", err)
				return nil
			}
			acc := serializer.GetAccount()
			if acc.Type() != account.SmartContractAccountType {
				continue
			}
			contract, true := acc.(*account.SmartContractAccount)
			if !true {
				return nil
			}

			// get storage root and code hash
			storageRoot := contract.GetStorageRoot()
			codeHashBytes := contract.GetCodeHash()
			codeHash := common.BytesToHash(codeHashBytes)

			// add up bytecode size
			chMu.RLock()
			// check if code hash is already in the map
			if _, ok := codeHashMap[codeHash]; !ok {
				chMu.RUnlock()
				chMu.Lock()
				codeHashMap[codeHash] = struct{}{}
				chMu.Unlock()
				// fetch code from db
				//code, err := db.Get(codeHashBytes)

				//if err != nil {
				//	fmt.Printf("err getting code: %v, key: %x\n", err, codeHash)
				//	return err
				//}
				code := chainDB.ReadCode(codeHash)
				codeSize += uint64(len(code))
			} else {
				chMu.RUnlock()
				continue
			}

			if storageRoot.Unextend() == emptyRoot {
				continue
			}

			// get the storage trie
			//storageTrie, err := statedb.NewTrie(storageRoot.Unextend(), statedb.NewDatabase(chainDB), nil)
			storageTrie, err := statedb.NewStorageTrie(storageRoot, statedb.NewDatabase(chainDB), nil)
			//fmt.Printf("storageTrie: %v\n", storageTrie)
			if err != nil {
				fmt.Printf("err getting storage trie: %v, key: %x\n", err, storageRoot)
				return err
			}

			// iterate over the storage trie
			var storageLeafCount uint64
			var storageInnerCount uint64
			var storageLeafSize uint64
			var storageInnerSize uint64
			storageIter := storageTrie.NodeIterator([]byte{})
			for storageIter.Next(true) {
				if storageIter.Leaf() {
					storageLeafCount++
					strgLeafCount++
					blob := storageIter.LeafBlob()
					strgLeafSize += uint64(len(blob))
					storageLeafSize += uint64(len(blob))
				} else {
					if storageIter.Path() == nil {
						continue
					}
					strgInnerCount++
					storageInnerCount++
					val, err := db.Get(storageIter.Hash().Bytes())
					if err != nil {
						fmt.Printf("err getting storage node: %v, key: %x, path: %x\n", err, storageIter.Hash(), storageIter.Path())
						return err
					}
					strgInnerSize += uint64(len(val))
					storageInnerSize += uint64(len(val))
				}
				// if storageLeafCount is <10, add the size to sizeMap with key 0
				// if storageLeafCount is <20, add the size to sizeMap with key 10
				// if storageLeafCount is <30, add the size to sizeMap with key 20
				// ...
				isMu.Lock()
				innerSizeMap[10*storageLeafCount/10] += storageInnerSize
				isMu.Unlock()
				lsMu.Lock()
				leafSizeMap[10*storageLeafCount/10] += storageLeafSize
				lsMu.Unlock()
			}
		} else {
			val, err := db.Get(iter.Hash().Bytes())
			if err != nil {
				fmt.Printf("err: %v, key: %x\n", err, iter.Hash())
				return err
			}
			//fmt.Printf("key: %x, val: %x\n", iter.Hash(), val)
			accInnerCount++
			accInnerSize += uint64(len(val))
		}
		continue
	}

	fmt.Printf("iterStart: 0x%x, accLeafCount: %d, accInnerCount: %d, accLeafSize: %d, accInnerSize: %d\n", iterStart, accLeafCount, accInnerCount, accLeafSize, accInnerSize)
	fmt.Printf("iterStart: 0x%x, strgLeafCount: %d, strgInnerCount: %d, strgLeafSize: %d, strgInnerSize: %d\n", iterStart, strgLeafCount, strgInnerCount, strgLeafSize, strgInnerSize)
	fmt.Printf("iterStart: 0x%x, codeSize: %d\n", iterStart, codeSize)

	return nil
}

// initGenesis will initialise the given JSON format genesis file and writes it as
// the zero'd block (i.e. genesis) or will fail hard if it can't succeed.
func initGenesis(ctx *cli.Context) error {
	// Make sure we have a valid genesis JSON
	genesisPath := ctx.Args().First()
	if len(genesisPath) == 0 {
		logger.Crit("Must supply path to genesis JSON file")
	}
	file, err := os.Open(genesisPath)
	if err != nil {
		logger.Crit("Failed to read genesis file", "err", err)
	}
	defer file.Close()

	genesis := new(blockchain.Genesis)
	if err := json.NewDecoder(file).Decode(genesis); err != nil {
		logger.Crit("Invalid genesis file", "err", err)
		return err
	}
	if genesis.Config == nil {
		logger.Crit("Genesis config is not set")
	}

	// Update undefined config with default values
	genesis.Config.SetDefaultsForGenesis()

	// Validate config values
	if err := ValidateGenesisConfig(genesis); err != nil {
		logger.Crit("Invalid genesis", "err", err)
	}

	// Set genesis.Governance and reward intervals
	govSet := governance.GetGovernanceItemsFromChainConfig(genesis.Config)
	govItemBytes, err := json.Marshal(govSet.Items())
	if err != nil {
		logger.Crit("Failed to json marshaling governance data", "err", err)
	}
	if genesis.Governance, err = rlp.EncodeToBytes(govItemBytes); err != nil {
		logger.Crit("Failed to encode initial settings. Check your genesis.json", "err", err)
	}
	params.SetStakingUpdateInterval(genesis.Config.Governance.Reward.StakingUpdateInterval)
	params.SetProposerUpdateInterval(genesis.Config.Governance.Reward.ProposerUpdateInterval)

	// Open an initialise both full and light databases
	stack := MakeFullNode(ctx)
	parallelDBWrite := !ctx.Bool(utils.NoParallelDBWriteFlag.Name)
	singleDB := ctx.Bool(utils.SingleDBFlag.Name)
	numStateTrieShards := ctx.Uint(utils.NumStateTrieShardsFlag.Name)
	overwriteGenesis := ctx.Bool(utils.OverwriteGenesisFlag.Name)
	livePruning := ctx.Bool(utils.LivePruningFlag.Name)

	dbtype := database.DBType(ctx.String(utils.DbTypeFlag.Name)).ToValid()
	if len(dbtype) == 0 {
		logger.Crit("invalid dbtype", "dbtype", ctx.String(utils.DbTypeFlag.Name))
	}

	var dynamoDBConfig *database.DynamoDBConfig
	if dbtype == database.DynamoDB {
		dynamoDBConfig = &database.DynamoDBConfig{
			TableName:          ctx.String(utils.DynamoDBTableNameFlag.Name),
			Region:             ctx.String(utils.DynamoDBRegionFlag.Name),
			IsProvisioned:      ctx.Bool(utils.DynamoDBIsProvisionedFlag.Name),
			ReadCapacityUnits:  ctx.Int64(utils.DynamoDBReadCapacityFlag.Name),
			WriteCapacityUnits: ctx.Int64(utils.DynamoDBWriteCapacityFlag.Name),
			ReadOnly:           ctx.Bool(utils.DynamoDBReadOnlyFlag.Name),
		}
	}
	rocksDBConfig := database.GetDefaultRocksDBConfig()
	if dbtype == database.RocksDB {
		rocksDBConfig = &database.RocksDBConfig{
			Secondary:                 ctx.Bool(utils.RocksDBSecondaryFlag.Name),
			DumpMallocStat:            ctx.Bool(utils.RocksDBDumpMallocStatFlag.Name),
			DisableMetrics:            ctx.Bool(utils.RocksDBDisableMetricsFlag.Name),
			CacheSize:                 ctx.Uint64(utils.RocksDBCacheSizeFlag.Name),
			CompressionType:           ctx.String(utils.RocksDBCompressionTypeFlag.Name),
			BottommostCompressionType: ctx.String(utils.RocksDBBottommostCompressionTypeFlag.Name),
			FilterPolicy:              ctx.String(utils.RocksDBFilterPolicyFlag.Name),
			MaxOpenFiles:              ctx.Int(utils.RocksDBMaxOpenFilesFlag.Name),
			CacheIndexAndFilter:       ctx.Bool(utils.RocksDBCacheIndexAndFilterFlag.Name),
		}
	}

	for _, name := range []string{"chaindata"} { // Removed "lightchaindata" since Kaia doesn't use it
		dbc := &database.DBConfig{
			Dir: name, DBType: dbtype, ParallelDBWrite: parallelDBWrite,
			SingleDB: singleDB, NumStateTrieShards: numStateTrieShards,
			LevelDBCacheSize: 0, PebbleDBCacheSize: 0, OpenFilesLimit: 0,
			DynamoDBConfig: dynamoDBConfig, RocksDBConfig: rocksDBConfig,
		}
		chainDB := stack.OpenDatabase(dbc)

		chainDB.GetDatabase(database.BodyDB)

		// Initialize DeriveSha implementation
		blockchain.InitDeriveSha(genesis.Config)

		_, hash, err := blockchain.SetupGenesisBlock(chainDB, genesis, params.UnusedNetworkId, false, overwriteGenesis)
		if err != nil {
			logger.Crit("Failed to write genesis block", "err", err)
		}

		// Write governance items to database
		// If governance data already exist, it'll be skipped with an error log and will not return an error
		gov := governance.NewMixedEngineNoInit(genesis.Config, chainDB)
		if err := gov.WriteGovernance(0, govSet, governance.NewGovernanceSet()); err != nil {
			logger.Crit("Failed to write governance items", "err", err)
		}

		// Write the live pruning flag to database
		if livePruning {
			logger.Info("Writing live pruning flag to database")
			chainDB.WritePruningEnabled()
		}

		logger.Info("Successfully wrote genesis state", "database", name, "hash", hash.String())
		chainDB.Close()
	}
	return nil
}

func dumpGenesis(ctx *cli.Context) error {
	genesis := MakeGenesis(ctx)
	if genesis == nil {
		genesis = blockchain.DefaultGenesisBlock()
	}
	if err := json.NewEncoder(os.Stdout).Encode(genesis); err != nil {
		logger.Crit("could not encode genesis")
	}
	return nil
}

func MakeGenesis(ctx *cli.Context) *blockchain.Genesis {
	var genesis *blockchain.Genesis
	switch {
	case ctx.Bool(utils.MainnetFlag.Name):
		genesis = blockchain.DefaultGenesisBlock()
	case ctx.Bool(utils.KairosFlag.Name):
		genesis = blockchain.DefaultKairosGenesisBlock()
	}
	return genesis
}

func ValidateGenesisConfig(g *blockchain.Genesis) error {
	if g.Config.ChainID == nil {
		return errors.New("chainID is not specified")
	}

	if g.Config.Clique == nil && g.Config.Istanbul == nil {
		return errors.New("consensus engine should be configured")
	}

	if g.Config.Clique != nil && g.Config.Istanbul != nil {
		return errors.New("only one consensus engine can be configured")
	}

	if g.Config.Governance == nil || g.Config.Governance.Reward == nil {
		return errors.New("governance and reward policies should be configured")
	}

	if g.Config.Governance.Reward.ProposerUpdateInterval == 0 || g.Config.Governance.Reward.
		StakingUpdateInterval == 0 {
		return errors.New("proposerUpdateInterval and stakingUpdateInterval cannot be zero")
	}

	if g.Config.Istanbul != nil {
		if err := governance.CheckGenesisValues(g.Config); err != nil {
			return err
		}

		// TODO-Kaia: Add validation logic for other GovernanceModes
		// Check if governingNode is properly set
		if strings.ToLower(g.Config.Governance.GovernanceMode) == "single" {
			var found bool

			istanbulExtra, err := types.ExtractIstanbulExtra(&types.Header{Extra: g.ExtraData})
			if err != nil {
				return err
			}

			for _, v := range istanbulExtra.Validators {
				if v == g.Config.Governance.GoverningNode {
					found = true
					break
				}
			}
			if !found {
				return errors.New("governingNode is not in the validator list")
			}
		}
	}
	return nil
}
