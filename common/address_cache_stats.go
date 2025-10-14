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

package common

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"time"
)

var (
	// Cache statistics
	addressCacheHits            atomic.Uint64
	addressCacheMisses          atomic.Uint64
	addressCacheStatsStartTime  time.Time
	addressCacheInitialMemStats runtime.MemStats
)

func init() {
	addressCacheStatsStartTime = time.Now()
	runtime.ReadMemStats(&addressCacheInitialMemStats)
}

// AddressCacheStats holds comprehensive cache statistics
type AddressCacheStats struct {
	// Cache configuration
	CacheSize int
	CacheLen  int

	// Hit statistics
	Hits     uint64
	Misses   uint64
	Total    uint64
	HitRatio float64

	// Memory statistics
	InitialMemory uint64
	CurrentMemory uint64
	MemoryDelta   uint64

	// Runtime statistics
	Uptime time.Duration
}

// GetAddressCacheStats returns comprehensive cache statistics
func GetAddressCacheStats() *AddressCacheStats {
	hits := addressCacheHits.Load()
	misses := addressCacheMisses.Load()
	total := hits + misses

	var hitRatio float64
	if total > 0 {
		hitRatio = float64(hits) / float64(total) * 100.0
	}

	// Get current memory stats
	var currentMem runtime.MemStats
	runtime.ReadMemStats(&currentMem)

	cacheSize, cacheLen := getAddressHexCacheInfo()

	stats := &AddressCacheStats{
		CacheSize:     cacheSize,
		CacheLen:      cacheLen,
		Hits:          hits,
		Misses:        misses,
		Total:         total,
		HitRatio:      hitRatio,
		InitialMemory: addressCacheInitialMemStats.Alloc,
		CurrentMemory: currentMem.Alloc,
		MemoryDelta:   currentMem.Alloc - addressCacheInitialMemStats.Alloc,
		Uptime:        time.Since(addressCacheStatsStartTime),
	}

	return stats
}

// PrintAddressCacheStats prints formatted cache statistics
func PrintAddressCacheStats() {
	stats := GetAddressCacheStats()

	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║         Address Hex Cache Statistics                         ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Printf("Cache Size:    %d entries\n", stats.CacheSize)
	fmt.Printf("Cache Used:    %d entries (%.1f%% full)\n",
		stats.CacheLen, float64(stats.CacheLen)/float64(stats.CacheSize)*100)
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Printf("Hit Ratio:     %.2f%%\n", stats.HitRatio)
	fmt.Printf("  Hits:        %d\n", stats.Hits)
	fmt.Printf("  Misses:      %d\n", stats.Misses)
	fmt.Printf("  Total:       %d\n", stats.Total)
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Printf("Memory Usage:  %.2f MB\n", float64(stats.CurrentMemory)/1024/1024)
	fmt.Printf("Memory Delta:  %.2f MB\n", float64(stats.MemoryDelta)/1024/1024)
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Printf("Uptime:        %v\n", stats.Uptime.Round(time.Second))
	fmt.Println("═══════════════════════════════════════════════════════════════")
}

// ResetAddressCacheStats resets all cache statistics
func ResetAddressCacheStats() {
	addressCacheHits.Store(0)
	addressCacheMisses.Store(0)
	addressCacheStatsStartTime = time.Now()
	runtime.ReadMemStats(&addressCacheInitialMemStats)
}

// recordCacheHit increments the cache hit counter
func recordCacheHit() {
	addressCacheHits.Add(1)
}

// recordCacheMiss increments the cache miss counter
func recordCacheMiss() {
	addressCacheMisses.Add(1)
}
