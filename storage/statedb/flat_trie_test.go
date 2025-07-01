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
	"github.com/kaiachain/kaia/blockchain/types"
	"github.com/kaiachain/kaia/blockchain/types/account"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/crypto"
	"github.com/kaiachain/kaia/rlp"
	"github.com/kaiachain/kaia/storage/database"
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
func TestFlatTrie(t *testing.T) {
	//dbm := newEmptyDBManager()

	aggStepSize := uint64(10)
	dir, _ := os.MkdirTemp(t.TempDir(), "flatdata")
	dirs := datadir.New(dir)
	logger := erigon_log.New()
	db := mdbx.New(erigon_kv.ChainDB, logger).
		Path(dirs.Chaindata).
		//InMem(dirs.Chaindata).
		GrowthStep(32 * datasize.MB).
		MapSize(2 * datasize.GB).
		MustOpen()
	defer db.Close()
	agg, err := erigon_state.NewAggregator2(context.Background(), dirs, aggStepSize, db, logger)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	defer agg.Close()
	err = agg.OpenFolder()
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	agg.DisableFsync()

	ac := agg.BeginFilesRo()
	defer ac.Close()
	tx, err := db.BeginRw(context.Background())
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	defer tx.Rollback()

	sd, err := erigon_state.NewSharedDomains(database.WrapTxWithCtx(tx, ac), nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	defer sd.Close()

	// it's in the aggregator test, but why?
	mc := agg.BeginFilesRo()
	defer mc.Close()

	sd.SetTxNum(0)
	sd.SetBlockNum(0)

	// test storage trie. Kairos contract 0x9fdd7a341308e969527bd6c928068edee8399807 0x9fdd7a341308e969527bd6c928068edee8399807 at block #505584
	// updateStorage: key: 0000000000000000000000000000000000000000000000000000000000000003, val: a0424820546f6b656e000000000000000000000000000000000000000000000010
	//updateStorage: key: 0000000000000000000000000000000000000000000000000000000000000004, val: a04248540000000000000000000000000000000000000000000000000000000006
	//updateStorage: key: 0000000000000000000000000000000000000000000000000000000000000005, val: 95efef9fe22a5e1ae68baea7069dcb1ac607ed78cf12
	//updateStorage: key: 0000000000000000000000000000000000000000000000000000000000000002, val: 8c033b2e3c9fd0803ce8000000
	//updateStorage: key: 3eaa2d76dda4c78c477b7231cb487c2b8fa646a998125bc96085f54b529e14a6, val: 8c033b2e3c9fd0803ce8000000

	addr := common.HexToAddress("0x1")
	slot := common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000005")
	hashedSlot := crypto.Keccak256(slot)
	_ = hashedSlot
	value := common.Hex2Bytes("95efef9fe22a5e1ae68baea7069dcb1ac607ed78cf12")
	hashedValue := crypto.Keccak256(value)
	_ = hashedValue
	acc := erigon_accounts.Account{
		Nonce:    0,
		Balance:  *uint256.NewInt(0),
		CodeHash: libcommon.HexToHash(types.EmptyCodeHash.Hex()),
		//CodeHash:    libcommon.HexToHash("e4fc5786883b715cd4ea3e4970357eafcd8d76c992023c590fe934d655c20dcb"),
		Incarnation: 0,
	}
	buf := erigon_accounts.SerialiseV3(&acc)
	_ = buf

	secureTrie, err := NewSecureTrie(common.Hash{}, NewDatabase(database.NewMemoryDBManager()), nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	//if err = secureTrie.TryUpdate(common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000005"), common.Hex2Bytes("95efef9fe22a5e1ae68baea7069dcb1ac607ed78cf12")); err != nil {
	if err = secureTrie.TryUpdate(slot, value); err != nil {
		t.Errorf("expected nil got %v", err)
	}
	fmt.Printf("secureTrie.root: %x\n", secureTrie.Hash())

	if err = sd.DomainPut(erigon_kv.AccountsDomain, addr.Bytes(), nil, buf, nil, 0); err != nil {
		t.Errorf("expected nil got %v", err)
	}
	if err = sd.DomainPut(erigon_kv.StorageDomain, addr.Bytes(), slot, value, nil, 0); err != nil {
		t.Errorf("expected nil got %v", err)
	}

	root, err := sd.ComputeCommitment(context.Background(), true, 0, "asdf")
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	hph := sd.GetCommitmentContext().Trie().(*commitment.HexPatriciaHashed)
	s, _ := hph.EncodeCurrentState(nil)
	fmt.Printf("%x\n", s)

	//tx.Commit()
	// k: 00000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000005, v: 95efef9fe22a5e1ae68baea7069dcb1ac607ed78cf12, step: 0
	sd.IterateStoragePrefix([]byte{}, func(k []byte, v []byte, step uint64) error {
		fmt.Printf("k: %x, v: %x, step: %d\n", k, v, step)
		return nil
	})
	// empty val or 000107000101 or 000020e4fc5786883b715cd4ea3e4970357eafcd8d76c992023c590fe934d655c20dcb00
	if val, _, err := sd.GetLatest(erigon_kv.AccountsDomain, addr.Bytes()); err != nil {
		t.Errorf("expected nil got %v", err)
	} else {
		fmt.Printf("GetLatest(AccountsDomain, addr): %x\n", val)
	}
	// empty val
	if val, _, err := sd.GetLatest(erigon_kv.AccountsDomain, append(addr.Bytes(), slot...)); err != nil {
		t.Errorf("expected nil got %v", err)
	} else {
		fmt.Printf("GetLatest(AccountsDomain, addr+slot): %x\n", val)
	}
	// 95efef9fe22a5e1ae68baea7069dcb1ac607ed78cf12
	if val, _, err := sd.GetLatest(erigon_kv.StorageDomain, append(addr.Bytes(), slot...)); err != nil {
		t.Errorf("expected nil got %v", err)
	} else {
		fmt.Printf("GetLatest(StorageDomain, addr+slot): %x\n", val)
	}
	// empty val
	if val, _, err := sd.GetLatest(erigon_kv.CommitmentDomain, root); err != nil {
		t.Errorf("expected nil got %v", err)
	} else {
		fmt.Printf("GetLatest(CommitmentDomain, commit): %x\n", val)
	}
	// empty val
	if val, _, err := sd.GetLatest(erigon_kv.StorageDomain, addr.Bytes()); err != nil {
		t.Errorf("expected nil got %v", err)
	} else {
		fmt.Printf("GetLatest(StorageDomain, addr): %x\n", val)
	}

	fmt.Printf("root: %x\n", root)

	t.Fail()
}

func TestSecureTrieAndErigonTrie(t *testing.T) {
	aggStepSize := uint64(10)
	dir, _ := os.MkdirTemp(t.TempDir(), "flatdata")
	dirs := datadir.New(dir)
	logger := erigon_log.New()
	db := mdbx.New(erigon_kv.ChainDB, logger).
		Path(dirs.Chaindata).
		//InMem(dirs.Chaindata).
		GrowthStep(32 * datasize.MB).
		MapSize(2 * datasize.GB).
		MustOpen()
	defer db.Close()
	agg, err := erigon_state.NewAggregator2(context.Background(), dirs, aggStepSize, db, logger)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	defer agg.Close()
	err = agg.OpenFolder()
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	agg.DisableFsync()

	ac := agg.BeginFilesRo()
	defer ac.Close()
	tx, err := db.BeginRw(context.Background())
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	defer tx.Rollback()

	sd, err := erigon_state.NewSharedDomains(database.WrapTxWithCtx(tx, ac), nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	defer sd.Close()

	// it's in the aggregator test, but why?
	mc := agg.BeginFilesRo()
	defer mc.Close()

	sd.SetTxNum(0)
	sd.SetBlockNum(0)

	// prepare account with storage
	addr := common.HexToAddress("0x1")
	_ = addr
	slot := common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000005")
	hashedSlot := crypto.Keccak256(slot)
	_ = hashedSlot
	value := common.Hex2Bytes("95efef9fe22a5e1ae68baea7069dcb1ac607ed78cf12")
	hashedValue := crypto.Keccak256(value)
	_ = hashedValue
	acc := erigon_accounts.Account{
		Nonce:    0,
		Balance:  *uint256.NewInt(0),
		CodeHash: libcommon.HexToHash(types.EmptyCodeHash.Hex()),
		//CodeHash:    libcommon.HexToHash("e4fc5786883b715cd4ea3e4970357eafcd8d76c992023c590fe934d655c20dcb"),
		Incarnation: 0,
	}
	buf := erigon_accounts.SerialiseV3(&acc)

	// get secure trie
	storageTrie, err := NewSecureTrie(common.Hash{}, NewDatabase(database.NewMemoryDBManager()), nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	if err = storageTrie.TryUpdate(slot, value); err != nil {
		t.Errorf("expected nil got %v", err)
	}
	root := storageTrie.Hash()
	fmt.Printf("secureTrie.root: %x\n", root)

	ethacc, err := account.NewAccountWithType(account.SmartContractAccountType)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	pa := account.GetProgramAccount(ethacc)
	pa.SetBalance(big.NewInt(0))
	pa.SetNonce(0)
	pa.SetHumanReadable(false)
	pa.SetStorageRoot(root.ExtendZero())
	pa.SetCodeHash(libcommon.HexToHash(types.EmptyCodeHash.Hex()).Bytes())

	buf, err = rlp.EncodeToBytes(pa)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	fmt.Printf("pa: %x\n", buf)

	// get erigon trie

	sd.DomainPut(erigon_kv.AccountsDomain, addr.Bytes(), nil, buf, nil, 0)
	sd.DomainPut(erigon_kv.StorageDomain, addr.Bytes(), slot, value, nil, 0)

	r, err := sd.ComputeCommitment(context.Background(), true, 0, "asdf")
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	fmt.Printf("r: %x\n", r)
	t.Fail()
}
