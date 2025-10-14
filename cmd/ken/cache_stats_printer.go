// Copyright 2024 The Kaia Authors
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

package main

import (
	"context"
	"time"

	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/log"
)

var cacheLogger = log.NewModuleLogger(log.Node)

// startCacheStatsPrinter starts a background goroutine that periodically prints cache statistics
func startCacheStatsPrinter(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				// Print final stats before exiting
				stats := common.GetAddressCacheStats()
				cacheLogger.Info("═══════════════════════════════════════════════════════════════")
				cacheLogger.Info("FINAL Address Hex Cache Statistics")
				cacheLogger.Info("═══════════════════════════════════════════════════════════════")
				cacheLogger.Info("Cache Statistics",
					"size", stats.CacheSize,
					"used", stats.CacheLen,
					"usage%", float64(stats.CacheLen)/float64(stats.CacheSize)*100)
				cacheLogger.Info("Hit Ratio",
					"ratio%", stats.HitRatio,
					"hits", stats.Hits,
					"misses", stats.Misses,
					"total", stats.Total)
				cacheLogger.Info("Memory",
					"current_MB", float64(stats.CurrentMemory)/1024/1024,
					"delta_MB", float64(stats.MemoryDelta)/1024/1024)
				cacheLogger.Info("Uptime", "duration", stats.Uptime.Round(time.Second))
				cacheLogger.Info("═══════════════════════════════════════════════════════════════")
				return

			case <-ticker.C:
				stats := common.GetAddressCacheStats()

				// Log cache statistics
				cacheLogger.Info("─── Address Hex Cache Stats ───",
					"hitRatio%", stats.HitRatio,
					"hits", stats.Hits,
					"misses", stats.Misses,
					"cacheUsed", stats.CacheLen,
					"cacheSize", stats.CacheSize,
					"memMB", float64(stats.CurrentMemory)/1024/1024,
					"uptime", stats.Uptime.Round(time.Second))
			}
		}
	}()
}
