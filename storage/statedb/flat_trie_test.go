package statedb

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/c2h5oh/datasize"
	"github.com/erigontech/erigon-lib/commitment"
	libcommon "github.com/erigontech/erigon-lib/common"
	"github.com/erigontech/erigon-lib/common/datadir"
	erigon_kv "github.com/erigontech/erigon-lib/kv"
	"github.com/erigontech/erigon-lib/kv/mdbx"
	erigon_log "github.com/erigontech/erigon-lib/log/v3"
	erigon_state "github.com/erigontech/erigon-lib/state"
	erigon_accounts "github.com/erigontech/erigon-lib/types/accounts"
	"github.com/holiman/uint256"
	"github.com/kaiachain/kaia/blockchain/types/account"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/rlp"
	"github.com/kaiachain/kaia/storage/database"
	"github.com/stretchr/testify/require"
)

func newEmptyDBManager() database.DBManager {
	dir, _ := os.MkdirTemp(os.TempDir(), "flat-trie-test")
	fmt.Printf("tmp: %s\n", dir)
	dbm := database.NewDBManager(&database.DBConfig{
		SingleDB: false,
		Dir:      dir,
	})
	return dbm
}

func getSharedDomain(t *testing.T) (*erigon_state.SharedDomains, func()) {
	aggStepSize := uint64(1)
	dir, _ := os.MkdirTemp(t.TempDir(), "flatdata")
	dirs := datadir.New(dir)
	logger := erigon_log.New()
	db := mdbx.New(erigon_kv.ChainDB, logger).
		//Path(dirs.Chaindata).
		InMem(dirs.Chaindata).
		GrowthStep(32 * datasize.MB).
		MapSize(2 * datasize.GB).
		MustOpen()
	agg, err := erigon_state.NewAggregator2(context.Background(), dirs, aggStepSize, db, logger)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	err = agg.OpenFolder()
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	agg.DisableFsync()

	ac := agg.BeginFilesRo()
	tx, err := db.BeginRw(context.Background())
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	sd, err := erigon_state.NewSharedDomains(database.WrapTxWithCtx(tx, ac), nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	// it's in the aggregator test, but why?
	mc := agg.BeginFilesRo()

	sd.SetTxNum(0)
	sd.SetBlockNum(0)

	return sd, func() {
		mc.Close()
		sd.Close()
		tx.Rollback()
		ac.Close()
		agg.Close()
		db.Close()
	}
}
func TestSharedDomainStorageUpdates(t *testing.T) {
	sd, close := getSharedDomain(t)
	defer close()

	if commitment.CurrentAccountDeserialiseMode != commitment.AccountDeserialiseModeErigonV3 {
		mode := commitment.CurrentAccountDeserialiseMode
		commitment.CurrentAccountDeserialiseMode = commitment.AccountDeserialiseModeErigonV3
		defer func() {
			commitment.CurrentAccountDeserialiseMode = mode
		}()
	}

	// test storage trie. Kairos contract 0x9fdd7a341308e969527bd6c928068edee8399807 at block #505584
	//updateStorage: key: 0000000000000000000000000000000000000000000000000000000000000003, val: a0424820546f6b656e000000000000000000000000000000000000000000000010
	//updateStorage: key: 0000000000000000000000000000000000000000000000000000000000000004, val: a04248540000000000000000000000000000000000000000000000000000000006
	//updateStorage: key: 0000000000000000000000000000000000000000000000000000000000000005, val: 95efef9fe22a5e1ae68baea7069dcb1ac607ed78cf12
	//updateStorage: key: 0000000000000000000000000000000000000000000000000000000000000002, val: 8c033b2e3c9fd0803ce8000000
	//updateStorage: key: 3eaa2d76dda4c78c477b7231cb487c2b8fa646a998125bc96085f54b529e14a6, val: 8c033b2e3c9fd0803ce8000000
	storageUpdates := []struct {
		slot  []byte
		value []byte
	}{
		{common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000003"), common.Hex2Bytes("a0424820546f6b656e000000000000000000000000000000000000000000000010")},
		{common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000004"), common.Hex2Bytes("a04248540000000000000000000000000000000000000000000000000000000006")},
		{common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000005"), common.Hex2Bytes("95efef9fe22a5e1ae68baea7069dcb1ac607ed78cf12")},
		{common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000002"), common.Hex2Bytes("8c033b2e3c9fd0803ce8000000")},
		{common.Hex2Bytes("3eaa2d76dda4c78c477b7231cb487c2b8fa646a998125bc96085f54b529e14a6"), common.Hex2Bytes("8c033b2e3c9fd0803ce8000000")},
	}

	addr := common.HexToAddress("0x9fdd7a341308e969527bd6c928068edee8399807")

	acc := erigon_accounts.Account{
		Nonce:       1,
		Balance:     *uint256.NewInt(0),
		CodeHash:    libcommon.HexToHash("e4fc5786883b715cd4ea3e4970357eafcd8d76c992023c590fe934d655c20dcb"),
		Incarnation: 0,
	}
	buf := erigon_accounts.SerialiseV3(&acc)

	for _, update := range storageUpdates {
		sd.DomainPut(erigon_kv.StorageDomain, addr.Bytes(), update.slot, update.value[1:], nil, 0)
	}
	sd.DomainPut(erigon_kv.AccountsDomain, addr.Bytes(), nil, buf, nil, 0)

	root, err := sd.ComputeCommitment(context.Background(), true, 0, "asdf")
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	secureTrie, err := NewSecureTrie(common.Hash{}, NewDatabase(database.NewMemoryDBManager()), nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	for _, update := range storageUpdates {
		secureTrie.TryUpdate(update.slot, update.value)
	}
	storageRoot := secureTrie.Hash()

	acc2 := &account.LegacyAccount{
		Nonce:    1,
		Balance:  big.NewInt(0),
		Root:     storageRoot,
		CodeHash: common.Hex2Bytes("e4fc5786883b715cd4ea3e4970357eafcd8d76c992023c590fe934d655c20dcb"),
	}
	buf2, err := rlp.EncodeToBytes(acc2)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	st2, err := NewSecureTrie(common.Hash{}, NewDatabase(database.NewMemoryDBManager()), nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	if err = st2.TryUpdate(addr.Bytes(), buf2); err != nil {
		t.Errorf("expected nil got %v", err)
	}
	root2 := st2.Hash()

	require.Equal(t, root, root2.Bytes())
}
