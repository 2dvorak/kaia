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
	"reflect"
	"strings"
	"time"

	"github.com/kaiachain/kaia/blockchain"
	"github.com/kaiachain/kaia/blockchain/types"
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

	val, err := db.Get(keyBytes)
	if err != nil {
		return err
	}

	fmt.Printf("0x%x\n", val)

	return nil
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

	var trie *statedb.Trie
	var err error
	root := ctx.Args().Get(1)
	if len(root) != 0 {
		rootBuf, err := hexutil.Decode(root)
		if err != nil {
			return err
		}
		rootHash := common.BytesToHash(rootBuf)
		trie, err = statedb.NewTrie(rootHash, statedb.NewDatabase(chainDB), nil)
		if err != nil {
			return err
		}
	} else {
		trie, err = statedb.NewTrie(common.Hash{}, statedb.NewDatabase(chainDB), nil)
		if err != nil {
			return err
		}
	}

	var leafCount uint64
	var innerCount uint64
	var leafSize uint64
	var innerSize uint64
	var count uint64
	iter := trie.NodeIterator([]byte{})
	startTime := time.Now()
	for iter.Next(true) {
		count++
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
			leafSize += uint64(len(iter.LeafBlob()))
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

	fmt.Printf("leafCount: %d, innerCount: %d, leafSize: %d, innerSize: %d\n", leafCount, innerCount, leafSize, innerSize)

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
