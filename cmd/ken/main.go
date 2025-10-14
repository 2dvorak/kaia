// Modifications Copyright 2024 The Kaia Authors
// Modifications Copyright 2018 The klaytn Authors
// Copyright 2016 The go-ethereum Authors
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
// This file is derived from cmd/geth/main.go (2018/06/04).
// Modified and improved for the klaytn development.
// Modified and improved for the Kaia development.

package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/kaiachain/kaia/api/debug"
	"github.com/kaiachain/kaia/cmd/utils"
	"github.com/kaiachain/kaia/cmd/utils/nodecmd"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/console"
	"github.com/kaiachain/kaia/log"
	"github.com/urfave/cli/v2"
)

var (
	logger = log.NewModuleLogger(log.CMDKEN)

	// The app that holds all commands and flags.
	app = utils.NewApp(nodecmd.GetGitCommit(), "The command line interface for Kaia Endpoint Node")

	// Context for cache stats printer
	cacheStatsCtx    context.Context
	cacheStatsCancel context.CancelFunc
)

func init() {
	// Initialize the CLI app and start ken
	app.Action = nodecmd.RunKaiaNode
	app.HideVersion = true // we have a command to print the version
	app.Copyright = "Copyright 2018-2024 The Kaia Authors"
	app.Commands = []*cli.Command{
		// See utils/nodecmd/chaincmd.go:
		nodecmd.InitCommand,
		nodecmd.DumpGenesisCommand,

		// See utils/nodecmd/accountcmd.go
		nodecmd.AccountCommand,

		// See utils/nodecmd/consolecmd.go:
		nodecmd.GetConsoleCommand(utils.KenNodeFlags(), utils.CommonRPCFlags),
		nodecmd.AttachCommand,

		// See utils/nodecmd/versioncmd.go:
		nodecmd.VersionCommand,

		// See utils/nodecmd/dumpconfigcmd.go:
		nodecmd.GetDumpConfigCommand(utils.KenNodeFlags(), utils.CommonRPCFlags),

		// See utils/nodecmd/db_migration.go:
		nodecmd.MigrationCommand,

		// See utils/nodecmd/util.go:
		nodecmd.UtilCommand,

		// See utils/nodecmd/snapshot.go:
		nodecmd.SnapshotCommand,
	}
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Flags = utils.KenAppFlags()

	app.CommandNotFound = nodecmd.CommandNotExist
	app.OnUsageError = nodecmd.OnUsageError
	app.Before = func(ctx *cli.Context) error {
		// Run the original BeforeRunNode
		if err := nodecmd.BeforeRunNode(ctx); err != nil {
			return err
		}

		// Start cache stats printer (prints every 1 minute)
		cacheStatsCtx, cacheStatsCancel = context.WithCancel(context.Background())
		startCacheStatsPrinter(cacheStatsCtx, 1*time.Minute)
		logger.Info("Started cache statistics printer", "interval", "1 minute")

		return nil
	}
	app.After = func(ctx *cli.Context) error {
		// Stop cache stats printer
		if cacheStatsCancel != nil {
			cacheStatsCancel()
		}

		// Print final address hex cache statistics before exit
		printCacheStatsOnExit()
		debug.Exit()
		console.Stdin.Close() // Resets terminal mode.
		return nil
	}
}

func main() {
	// Set NodeTypeFlag to en
	utils.NodeTypeFlag.Value = "en"

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// printCacheStatsOnExit prints address hex cache statistics when ken exits
func printCacheStatsOnExit() {
	stats := common.GetAddressCacheStats()
	logger.Info("═══════════════════════════════════════════════════════════════")
	logger.Info("Address Hex Cache Statistics")
	logger.Info("═══════════════════════════════════════════════════════════════")
	logger.Info("Cache Configuration",
		"size", stats.CacheSize,
		"used", stats.CacheLen,
		"usage%", fmt.Sprintf("%.1f", float64(stats.CacheLen)/float64(stats.CacheSize)*100))
	logger.Info("Hit Ratio Statistics",
		"hitRatio%", fmt.Sprintf("%.2f", stats.HitRatio),
		"hits", stats.Hits,
		"misses", stats.Misses,
		"total", stats.Total)
	logger.Info("Memory Statistics",
		"currentMB", fmt.Sprintf("%.2f", float64(stats.CurrentMemory)/1024/1024),
		"deltaMB", fmt.Sprintf("%.2f", float64(stats.MemoryDelta)/1024/1024))
	logger.Info("Runtime", "uptime", stats.Uptime.Round(1000000000)) // Round to seconds
	logger.Info("═══════════════════════════════════════════════════════════════")
}
