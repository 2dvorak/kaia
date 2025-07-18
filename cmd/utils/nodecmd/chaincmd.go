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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/c2h5oh/datasize"
	"github.com/kaiachain/kaia/blockchain"
	"github.com/kaiachain/kaia/blockchain/types"
	"github.com/kaiachain/kaia/cmd/utils"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/common/hexutil"
	headergov_impl "github.com/kaiachain/kaia/kaiax/gov/headergov/impl"
	"github.com/kaiachain/kaia/log"
	"github.com/kaiachain/kaia/params"
	"github.com/kaiachain/kaia/storage/database"
	"github.com/kaiachain/kaia/storage/statedb"
	"github.com/urfave/cli/v2"

	"github.com/erigontech/erigon-lib/common/datadir"
	"github.com/erigontech/erigon-lib/kv"
	"github.com/erigontech/erigon-lib/kv/mdbx"
	"github.com/erigontech/erigon-lib/kv/order"
	erigon_state "github.com/erigontech/erigon-lib/state"
	erigon_cmd_utils "github.com/erigontech/erigon/cmd/utils"
	erigon_node "github.com/erigontech/erigon/node"
	erigon_app "github.com/erigontech/erigon/turbo/app"
	"github.com/erigontech/erigon/turbo/debug"
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
			utils.FlatTrieFlag,
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

	IterTableCommand = &cli.Command{
		Action:    iterTable,
		Name:      "iterTable",
		Usage:     "Iterate over the table and count the number of nodes by their types",
		ArgsUsage: "",
		Flags: []cli.Flag{
			// For compatibility with erigon
			&cli.StringFlag{
				Name:  erigon_cmd_utils.DbPageSizeFlag.Name,
				Usage: "Set the size of the mdbx page size",
				Value: "4KB",
			},
			&cli.StringFlag{
				Name:  erigon_cmd_utils.DbSizeLimitFlag.Name,
				Usage: "Set the size of the mdbx database size limit",
				Value: "100GB",
			},
		},
	}

	IterTrieCommand = &cli.Command{
		Action:    iterTrie,
		Name:      "itertrie",
		Usage:     "Iterate over the trie and print the key-value pairs",
		ArgsUsage: "",
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
The dbget command dumps the key-value from database.`,
	}

	KvGetCommand = &cli.Command{
		Action:    kvGet,
		Name:      "kvget",
		Usage:     "Read a key from the flattrie",
		ArgsUsage: "<dbname> <key> [<blockNum>]",
		Flags: []cli.Flag{
			utils.MainnetFlag,
			utils.KairosFlag,
		},
		Category: "BLOCKCHAIN COMMANDS",
		Description: `
The kvget command reads a key from the flattrie.`,
	}
)

func iterTrie(ctx *cli.Context) error {
	root := ctx.Args().First()

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

	//db := chainDB.GetDatabase(database.StateTrieDB)

	// open trie
	st, err := statedb.NewSecureTrie(common.HexToHash(root), statedb.NewDatabase(chainDB), &statedb.TrieOpts{})
	if err != nil {
		return fmt.Errorf("Failed to open trie: %v", err)
	}

	it := st.NodeIterator(nil)
	for it.Next(true) {
		if it.Leaf() {
			fmt.Printf("hashed key: %x, rlp encoded value: %x\n", it.LeafKey(), it.LeafBlob())
		}
	}
	return nil
}

func iterTable(cliCtx *cli.Context) error {
	logger, _, _, _ := debug.Setup(cliCtx, true /* rootLogger */)

	// For compatibility with erigon
	cliCtx.Set(erigon_cmd_utils.DbPageSizeFlag.Name, "4KB")
	cliCtx.Set(erigon_cmd_utils.DbSizeLimitFlag.Name, (1 * datasize.TB).String())
	stack, err := erigon_app.MakeNodeWithDefaultConfig(cliCtx, logger)
	if err != nil {
		return err
	}
	defer stack.Close()

	chaindb, err := erigon_node.OpenDatabase(cliCtx.Context, stack.Config(), kv.ChainDB, "", false, logger)
	if err != nil {
		return fmt.Errorf("Failed to open database: %v", err)
	}
	defer chaindb.Close()

	all := chaindb.AllTables()

	// Just dump all the tables for now
	for table, _ := range all {
		fmt.Printf("table %s\n", table)
		chaindb.View(cliCtx.Context, func(tx kv.Tx) error {
			stream, err := tx.Range(table, nil, nil, order.Asc, -1)
			if err != nil {
				return fmt.Errorf("Failed to get acc: %v", err)
			}
			for stream.HasNext() {
				k, v, err := stream.Next()
				if err != nil {
					return fmt.Errorf("Failed to get acc: %v", err)
				}
				fmt.Printf("key=0x%-80x, val=0x%-80x\n", k, v)
			}
			return nil
		})
	}
	return nil
}

func kvGet(cliCtx *cli.Context) error {
	dbname := cliCtx.Args().First()
	key := cliCtx.Args().Get(1)
	keyBytes, err := hexutil.Decode(key)
	if err != nil {
		return fmt.Errorf("Failed to decode key: %v", err)
	}
	blockNum := cliCtx.Args().Get(2)

	logger, _, _, _ := debug.Setup(cliCtx, true /* rootLogger */)

	// For compatibility with erigon
	/*cliCtx.Set(erigon_cmd_utils.DbPageSizeFlag.Name, "4KB")
	cliCtx.Set(erigon_cmd_utils.DbSizeLimitFlag.Name, (1 * datasize.TB).String())
	stack, err := erigon_app.MakeNodeWithDefaultConfig(cliCtx, logger)
	if err != nil {
		return err
	}
	defer stack.Close()

	chaindb, err := erigon_node.OpenDatabase(cliCtx.Context, stack.Config(), kv.ChainDB, "", false, logger)
	if err != nil {
		return fmt.Errorf("Failed to open database: %v", err)
	}
	defer chaindb.Close()*/

	var domain kv.Domain
	switch dbname {
	case "accounts":
		domain = kv.AccountsDomain
	case "storage":
		domain = kv.StorageDomain
	case "code":
		domain = kv.CodeDomain
	case "commitments":
		domain = kv.CommitmentDomain
	}

	dirs := datadir.New(path.Join(cliCtx.String(utils.DataDirFlag.Name), "klay/chaindata/flattrie")) // TODO-Kaia: use $DATADIR/klay/chaindata/flattrie
	fmt.Printf("dirs: %s\n", dirs.Chaindata)
	os.MkdirAll(dirs.Chaindata, 0755)
	db := mdbx.New(kv.ChainDB, logger).
		//InMem(dirs.Chaindata). // path to persisted data
		Path(dirs.Chaindata).
		GrowthStep(32 * 1024 * 1024).
		MapSize(2 * 1024 * 1024 * 1024).
		MustOpen()

	// Set aggStep to 1
	aggStep := uint64(1) // ??
	agg, err := erigon_state.NewAggregator2(context.Background(), dirs, aggStep, db, logger)
	if err != nil {
		panic(err)
	}
	err = agg.OpenFolder() // ??
	if err != nil {
		panic(err)
	}
	agg.DisableFsync() // ??

	tx, err := db.BeginRw(context.Background())
	if err != nil {
		panic("cannot open mdbx db: " + err.Error())
	}

	aggCtx := agg.BeginFilesRo()
	wrappedTx := database.WrapTxWithCtx(tx, aggCtx)
	sd, err := erigon_state.NewSharedDomains(wrappedTx, logger)
	if err != nil {
		panic("cannot open shared domains: " + err.Error())
	}

	if cliCtx.Args().Len() < 3 {
		val, _, err := sd.GetLatest(domain, keyBytes)
		if err != nil {
			return fmt.Errorf("Failed to get value: %v", err)
		}
		fmt.Printf("latest val: %x\n", val)
	} else {
		blockNumUint, err := strconv.ParseUint(blockNum, 10, 64)
		if err != nil {
			return fmt.Errorf("Failed to parse block number: %v", err)
		}
		aggTx := sd.AggTx().(*erigon_state.AggregatorRoTx)
		val, _, err := aggTx.GetAsOf(sd.Tx(), domain, keyBytes, blockNumUint+1)
		if err != nil {
			return fmt.Errorf("Failed to get value: %v", err)
		}
		fmt.Printf("block %d val: %x\n", blockNumUint, val)
	}
	return nil
}

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
	case "header":
	case "h":
		dbEntryType = 1 // headerDB
	case "body":
	case "b":
		dbEntryType = database.BodyDB
	case "state", "s":
		dbEntryType = database.StateTrieDB
	}
	db := chainDB.GetDatabase(dbEntryType)

	keyBytes, err := hexutil.Decode(key)
	if err != nil {
		return err
	}

	val, err := db.Get(keyBytes)
	if err != nil {
		return err
	}

	fmt.Printf("%x\n", val)
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
	genesis.Governance = headergov_impl.GetGenesisGovBytes(genesis.Config)
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

		// Initialize DeriveSha implementation
		blockchain.InitDeriveSha(genesis.Config)

		_, hash, err := blockchain.SetupGenesisBlock(chainDB, genesis, params.UnusedNetworkId, false, overwriteGenesis)
		if err != nil {
			logger.Crit("Failed to write genesis block", "err", err)
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
