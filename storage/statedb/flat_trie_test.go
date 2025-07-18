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

func getSharedDomain(t *testing.T) (*erigon_state.SharedDomains, func(bool)) {
	aggStepSize := uint64(1)
	dir, _ := os.MkdirTemp(t.TempDir(), "flatdata")
	dirs := datadir.New(dir)
	logger := erigon_log.New()
	db := mdbx.New(erigon_kv.ChainDB, logger).
		Path(dirs.Chaindata).
		//InMem(dirs.Chaindata).
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

	//sd.SetTxNum(0)
	//sd.SetBlockNum(0)

	return sd, func(commit bool) {
		mc.Close()
		sd.Close()
		if commit {
			tx.Commit()
		} else {
			tx.Rollback()
		}
		ac.Close()
		agg.Close()
		db.Close()
	}
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

func TestHexPatriciaHashedStorageRoot(t *testing.T) {
	mode := commitment.CurrentAccountDeserialiseMode
	defer func() {
		commitment.CurrentAccountDeserialiseMode = mode
	}()
	commitment.CurrentAccountDeserialiseMode = commitment.AccountDeserialiseModeErigonV3

	sd, close := getSharedDomain(t)
	//defer close()

	addr := common.HexToAddress("0x1")
	slot := common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000005")
	value := common.Hex2Bytes("95efef9fe22a5e1ae68baea7069dcb1ac607ed78cf12")

	sd.DomainPut(erigon_kv.AccountsDomain, addr.Bytes(), nil, common.Hex2Bytes("00000000"), nil, 0)
	sd.DomainPut(erigon_kv.StorageDomain, addr.Bytes(), slot, value, nil, 0)

	root, err := sd.ComputeCommitment(context.Background(), true, 0, "asdf")
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	fmt.Printf("root: %x\n", root)

	root2, ok := sd.GetStorageRootHash(addr.Bytes())
	if !ok {
		t.Errorf("expected true got false")
	}
	fmt.Printf("root2: %x\n", root2)

	hph := sd.GetCommitmentContext().Trie().(*commitment.HexPatriciaHashed)
	hphBuf, err := hph.EncodeCurrentState(nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	close(false)

	sd2, close2 := getSharedDomain(t)
	defer close2(false)

	hph2 := sd2.GetCommitmentContext().Trie().(*commitment.HexPatriciaHashed)
	err = hph2.SetState(hphBuf)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	root3, ok := hph2.GetStorageRootHash(addr.Bytes())
	if !ok {
		t.Errorf("expected true got false")
	}
	fmt.Printf("root3: %x\n", root3)

	t.Fail()
}

func TestSharedDomainStorageUpdates(t *testing.T) {
	sd, close := getSharedDomain(t)

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

	// First try with eth encoding
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

	storageRoot2, ok := sd.GetStorageRootHash(addr.Bytes())
	if !ok {
		t.Errorf("expected true got false")
	}
	fmt.Printf("storageRoot2: %x\n", storageRoot2)
	require.Equal(t, storageRoot.Bytes(), storageRoot2[:])
	close(false)

	// Now try with kaia encoding
	commitment.CurrentAccountDeserialiseMode = commitment.AccountDeserialiseModeKaia
	sd2, close2 := getSharedDomain(t)

	acc3, err := account.NewAccountWithType(account.SmartContractAccountType)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	acc3.SetBalance(big.NewInt(0))
	acc3.SetNonce(1)
	acc3.SetHumanReadable(false)
	pa := account.GetProgramAccount(acc3)
	pa.SetCodeHash(common.Hex2Bytes("e4fc5786883b715cd4ea3e4970357eafcd8d76c992023c590fe934d655c20dcb"))
	pa.SetStorageRoot(storageRoot.ExtendZero())
	buf3, err := rlp.EncodeToBytes(acc3)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	sd2.DomainPut(erigon_kv.AccountsDomain, addr.Bytes(), nil, buf3, nil, 0)
	for _, update := range storageUpdates {
		sd2.DomainPut(erigon_kv.StorageDomain, addr.Bytes(), update.slot, update.value[1:], nil, 0)
	}
	_, err = sd2.ComputeCommitment(context.Background(), true, 0, "asdf")
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	root3, ok := sd2.GetStorageRootHash(addr.Bytes())
	if !ok {
		t.Errorf("expected true got false")
	}
	require.Equal(t, storageRoot.Bytes(), root3[:])
	hph := sd2.GetCommitmentContext().Trie().(*commitment.HexPatriciaHashed)
	hphBuf, err := hph.EncodeCurrentState(nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	close2(false)

	// See if the storageRootHash map is correctly encoded then decoded
	// using EncodeCurrentState and SetState.
	sd3, close3 := getSharedDomain(t)
	_, err = sd3.ComputeCommitment(context.Background(), true, 0, "asdf")
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	root4, ok := sd3.GetStorageRootHash(addr.Bytes())
	if ok {
		t.Errorf("expected false got true")
	}
	require.Equal(t, common.Hash{}, common.BytesToHash(root4[:]))
	hph2 := sd3.GetCommitmentContext().Trie().(*commitment.HexPatriciaHashed)
	err = hph2.SetState(hphBuf)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	root5, ok := hph2.GetStorageRootHash(addr.Bytes())
	if !ok {
		t.Errorf("expected true got false")
	}
	require.Equal(t, storageRoot.Bytes(), root5[:])
	close3(false)
}

// See if the storage root hash is not calculated for non-existent account.
func TestSharedDomainStorageUpdatesNonExistentAccount(t *testing.T) {
	sd, close := getSharedDomain(t)
	defer close(false)

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

	// First try with eth encoding
	acc := erigon_accounts.Account{
		Nonce:       8,
		Balance:     *uint256.NewInt(0),
		CodeHash:    libcommon.HexToHash("e4fc5786883b715cd4ea3e4970357eafcd8d76c992023c590fe934d655c20dcb"),
		Incarnation: 0,
	}
	buf := erigon_accounts.SerialiseV3(&acc)
	_ = buf

	for _, update := range storageUpdates {
		sd.DomainPut(erigon_kv.StorageDomain, addr.Bytes(), update.slot, update.value[1:], nil, 0)
	}

	_, err := sd.ComputeCommitment(context.Background(), true, 0, "asdf")
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	// Should not be able to get the storage root hash
	// because the account does not exist, storage root hash would not be calculated.
	_, ok := sd.GetStorageRootHash(addr.Bytes())
	if ok {
		t.Errorf("expected false got true")
	}
}

// Update storage and account in the same block,
// then update storage in the next block.
// See if the next block's storage root is correct.
func TestSharedDomainStorageUpdateNextBlock(t *testing.T) {
	sd, close := getSharedDomain(t)

	firstStep := 5

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
		{common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000006"), common.Hex2Bytes("9462c7998273966cd2f219bb44f60b2870fa538622")},
	}

	addr := common.HexToAddress("0x9fdd7a341308e969527bd6c928068edee8399807")

	acc := erigon_accounts.Account{
		Nonce:       8,
		Balance:     *uint256.NewInt(0),
		CodeHash:    libcommon.HexToHash("e4fc5786883b715cd4ea3e4970357eafcd8d76c992023c590fe934d655c20dcb"),
		Incarnation: 0,
	}
	buf := erigon_accounts.SerialiseV3(&acc)

	for i, update := range storageUpdates {
		if i == firstStep {
			break
		}
		sd.DomainPut(erigon_kv.StorageDomain, addr.Bytes(), update.slot, update.value[1:], nil, 0)
	}
	sd.DomainPut(erigon_kv.AccountsDomain, addr.Bytes(), nil, buf, nil, 0)

	_, err := sd.ComputeCommitment(context.Background(), true, 0, "asdf")
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	root, ok := sd.GetStorageRootHash(addr.Bytes())
	if !ok {
		t.Errorf("expected true got false")
	}
	require.Equal(t, common.HexToHash("41fbe8aca458c42a31464a6eff4e221b66f6ffd341a6836c33bf677f63810329"), common.BytesToHash(root[:]))

	hph := sd.GetCommitmentContext().Trie().(*commitment.HexPatriciaHashed)
	hphBuf, err := hph.EncodeCurrentState(nil)
	_ = hphBuf
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	// save state
	val, _, err := sd.GetLatest(erigon_kv.CommitmentDomain, common.Hex2Bytes("0074e154f798380c6c99de41fa3748df6aae9984372f8c3fe3a6fdc390b270a858"))
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	fmt.Printf("val: %x\n", val)
	close(true)

	// Next block
	sd2, close2 := getSharedDomain(t)
	//sd2.SetTxNum(1)
	//sd2.SetBlockNum(1)
	hph2 := sd2.GetCommitmentContext().Trie().(*commitment.HexPatriciaHashed)
	err = hph2.SetState(hphBuf)
	val, _, err = sd2.GetLatest(erigon_kv.CommitmentDomain, common.Hex2Bytes("0074e154f798380c6c99de41fa3748df6aae9984372f8c3fe3a6fdc390b270a858"))
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	fmt.Printf("val: %x\n", val)
	hph2.SetTrace(true)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	// Maybe try with updated account?
	acc.Nonce = 9
	buf = erigon_accounts.SerialiseV3(&acc)
	for i, update := range storageUpdates {
		if i < firstStep {
			continue
		}
		sd2.DomainPut(erigon_kv.StorageDomain, addr.Bytes(), update.slot, update.value[1:], nil, 0)
	}
	sd2.DomainPut(erigon_kv.AccountsDomain, addr.Bytes(), nil, buf, nil, 0)

	sd2.SetTxNum(1)
	sd2.SetBlockNum(1)
	_, err = sd2.ComputeCommitment(context.Background(), true, 1, "asdf")
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	root2, ok := sd2.GetStorageRootHash(addr.Bytes())
	if !ok {
		t.Errorf("expected true got false")
	}
	fmt.Printf("root2: %x\n", root2)

	close2(false)

	t.Fail()
}

func TestFlatTrieUpdateStorage(t *testing.T) {
	if commitment.CurrentAccountDeserialiseMode != commitment.AccountDeserialiseModeKaia {
		mode := commitment.CurrentAccountDeserialiseMode
		commitment.CurrentAccountDeserialiseMode = commitment.AccountDeserialiseModeKaia
		defer func() {
			commitment.CurrentAccountDeserialiseMode = mode
		}()
	}
	dbm := newEmptyDBManager()
	defer dbm.Close()

	addr := common.HexToAddress("0x1")

	firstStep := 5

	storageUpdates := []struct {
		slot  []byte
		value []byte
	}{
		{common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000004"), common.Hex2Bytes("a04248540000000000000000000000000000000000000000000000000000000006")},
		{common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000005"), common.Hex2Bytes("95efef9fe22a5e1ae68baea7069dcb1ac607ed78cf12")},
		{common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000002"), common.Hex2Bytes("8c033b2e3c9fd0803ce8000000")},
		{common.Hex2Bytes("3eaa2d76dda4c78c477b7231cb487c2b8fa646a998125bc96085f54b529e14a6"), common.Hex2Bytes("8c033b2e3c9fd0803ce8000000")},
		{common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000003"), common.Hex2Bytes("a0424820546f6b656e000000000000000000000000000000000000000000000010")},
		{common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000006"), common.Hex2Bytes("9462c7998273966cd2f219bb44f60b2870fa538622")},
	}
	// keccak256(0000000000000000000000000000000000000001) 								= 1468288056310c82aa4c01a7e12a10f8111a0560e72b700555479031b86c357d
	// keccak256(0000000000000000000000000000000000000000000000000000000000000004) 		= 8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b
	// keccak256(a04248540000000000000000000000000000000000000000000000000000000006) 	= 0f5461fe0dd9b7910b06da44d3dec8663708a91020b05b7a3e52174dd7237bd8
	// keccak256(0000000000000000000000000000000000000000000000000000000000000005) 		= 036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0
	// keccak256(95efef9fe22a5e1ae68baea7069dcb1ac607ed78cf12) 							= 3e1f630eb0070c55a628250a5f1d44c35714373c048d5d4532ad06ae6436be67
	// keccak256(0000000000000000000000000000000000000000000000000000000000000002) 		= 405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace
	// keccak256(3eaa2d76dda4c78c477b7231cb487c2b8fa646a998125bc96085f54b529e14a6) 		= 0cd65e093dee948a51b22ec3b3c8ee528f14efa34c115bb0990272f8b55f387a
	// keccak256(8c033b2e3c9fd0803ce8000000) 											= b446aee5d855207a6a14959727414750ac55862ec4b496a8e1fddf3f41c3581d
	// keccak256(0000000000000000000000000000000000000000000000000000000000000003) 		= c2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b
	// keccak256(a0424820546f6b656e000000000000000000000000000000000000000000000010) 	= 38bdc1298a985592a99e1b47ac077a52713f327d7cb4c2aa88829d34c0ace87c
	// keccak256(0000000000000000000000000000000000000000000000000000000000000006) 		= f652222313e28459528d920b65115c16c04f3efc82aaedc97be59f3f377c0d3f
	// keccak256(9462c7998273966cd2f219bb44f60b2870fa538622) 							= 7556a9771d415c5e3bec733480022571611e8accafc473f1068bfc933451e1b4

	f, err := NewFlatTrieWithDBManager(common.Hash{}, dbm, &addr, &TrieOpts{
		Prefetching:        true,
		PruningBlockNumber: 0,
		TrieBlockNumber:    0,
		IsGenesis:          true,
	})
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	st, err := NewSecureTrie(common.Hash{}, NewDatabase(dbm), nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	for i, update := range storageUpdates {
		if i == firstStep {
			break
		}
		if err := f.TryUpdate(update.slot, update.value); err != nil {
			t.Errorf("expected nil got %v", err)
		}
		if err := st.TryUpdate(update.slot, update.value); err != nil {
			t.Errorf("expected nil got %v", err)
		}
		root1 := f.Hash()
		fmt.Printf("root1: %x\n", root1)
		root2 := st.Hash()
		fmt.Printf("root2: %x\n", root2)
		//require.Equal(t, root1, root2, i)
	}
	require.Equal(t, f.Hash(), st.Hash())

	f2, err := NewFlatTrieWithDBManager(f.Hash(), dbm, &addr, &TrieOpts{
		TrieBlockNumber: 1,
	})
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	for i, update := range storageUpdates {
		if i < firstStep {
			continue
		}
		if err := f2.TryUpdate(update.slot, update.value); err != nil {
			t.Errorf("expected nil got %v", err)
		}
		if err := st.TryUpdate(update.slot, update.value); err != nil {
			t.Errorf("expected nil got %v", err)
		}
		root3 := f2.Hash()
		root4 := st.Hash()
		require.Equal(t, root3, root4, i)
	}

	t.Fail()
}

func TestFlatTrieStorage571906(t *testing.T) {
	dbm := newEmptyDBManager()
	defer dbm.Close()

	addr := common.HexToAddress("0xfb390fe9eacaaf75d88bc8ce82038219da25a0ba")

	/*
		From archive node itertrie
		./build/bin/ken --datadir data itertrie 0xf1ef081ee354c3d1ff6ec6188c3dd3c181553fb049b2807d3bf9a22d7dbd8487

		// keccak(0000000000000000000000000000000000000000000000000000000000000005)
		key: 036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0, value: 06
		// keccak(697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f206512)
		key: 0e3a43cacfe637fe91115c50d493ae9516b9ff6b288a7409a9367ab72d5ce102, value: 843b9aca00
		// keccak(a6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49)
		key: 0eb5be412f275a18f6e4d622aee4ff40b21467c926224771b782d4c095d1444b, value: 12
		// keccak(8819ef417987f8ae7a81f42cdfb18815282fe989326fbff903d13cf0e03ace2b)
		key: 0f330b5986b4b5cd78d97c486641eccc150d851a200723accc40f7788f396019, value: 94ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95
		// keccak(75f96ab15d697e93042dc45b5c896c4b27e89bb6eaf39475c5c371cb2513f7d6)
		key: 181863daaf01f6a2e46f43a4bd0a30f4bf514c424d89a6e8d267c22ed2e4144d, value: 8307e626
		// keccak(c5069e24aaadb2addc3e52e868fcf3f4f8acf5a87e24300992fd4540c2a87eee)
		key: 198a76745cf3cf8e13b3d6175ffeca2d499ef48a12b1ea4dd717fd23cc0c861a, value: 94ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95
		// keccak(3e5fec24aa4dc4e5aee2e025e51e1392c72a2500577559fae9665c6d52bd6a35)
		key: 1de112f3326e683c6f3f6348c31554334288aac2d7c08460794567a96d874821, value: 8307e57f
		// keccak(d655dac6cd810cc6fa88e194418d5d68ee3c0d1524ca99102d7454b48a45fcc8)
		key: 25d01797e35f287ab7b68bfa28daff9bacd35d7a3a11bbd86d346df0c75fc8d4, value: 12
		// keccak(0000000000000000000000000000000000000000000000000000000000000000)
		key: 290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563, value: 9501ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95
		// keccak(75f96ab15d697e93042dc45b5c896c4b27e89bb6eaf39475c5c371cb2513f7d2)
		key: 297b7330606da1b3a511cb74d59067f686371c2dfcf08c40f28d4ccae4bbb8eb, value: 94cc74039c82c300ba9b7d348470df2972a34d2601
		// keccak(7ff1ccd6c3a4ffcca1b442665f88379b09ebea17412d175160ef108fe4d27708)
		key: 2f33a69a87216483b4520801f90de950df9b32cd7c5857c73cbcb6483944c139, value: 12
		// keccak(bfd358e93f18da3ed276c3afdbdba00b8f0b6008a03476a6a86bd6320ee6938d)
		key: 396165d6992c35a716a6bc9d98532b3f528646f1a3e24db50abaab1fdca4bbf6, value: 94ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95
		// keccak(697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f206511)
		key: 41b840011203114f159c752197e2f8f7da89be45d8a75b8bc1c151480a801665, value: 94ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95
		// keccak(75f96ab15d697e93042dc45b5c896c4b27e89bb6eaf39475c5c371cb2513f7d4)
		key: 5212dd3fe5e3427c96b9ec571f57bae61f5045df576715e6ad5c2e47454a4090, value: 94ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95
		// keccak(75f96ab15d697e93042dc45b5c896c4b27e89bb6eaf39475c5c371cb2513f7d3)
		key: 53960299ca52c12b1d83572f59016ab426eefe84c8aca873d5cb81d6166aef9e, value: 94ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95
		// keccak(697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f206510)
		key: 5632bc4de74c8f7366d160f9d99e3f33c45c7046b2ddb33c49c80bceccef7424, value: 94ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95
		// keccak(bfd358e93f18da3ed276c3afdbdba00b8f0b6008a03476a6a86bd6320ee6938c)
		key: 652fc59a8f2a19f7ee5cc6b2d4dd78e164ba7427a79f796a06232d0c74930eba, value: 94ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95
		// keccak(c5069e24aaadb2addc3e52e868fcf3f4f8acf5a87e24300992fd4540c2a87ef0)
		key: 7250b5ed9b2cc3ba67419e9f0f3fcf6df0c8740fb3ea407b800dff28fc7050d7, value: 843b9aca00
		// keccak(c5069e24aaadb2addc3e52e868fcf3f4f8acf5a87e24300992fd4540c2a87ef1)
		key: 73836cef606e2ad6102a1461183e38562bb425865f2bc53a67e615a52b4078cd, value: 8308b9d6
		// keccak(697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f20650f)
		key: 83010eb9820c88e824885fd8f7f32424ad835133ddc769cedc18104b33953abf, value: 94cc74039c82c300ba9b7d348470df2972a34d2601
		// keccak(75f96ab15d697e93042dc45b5c896c4b27e89bb6eaf39475c5c371cb2513f7d5)
		key: 8317c5425748c10e50f148c5ce1da7b8a582e560dd93bc2f5b7cf9bf5ff24a77, value: 843b9aca00
		// keccak(0000000000000000000000000000000000000000000000000000000000000004)
		key: 8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b, value: 94ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95
		// keccak(c5069e24aaadb2addc3e52e868fcf3f4f8acf5a87e24300992fd4540c2a87eed)
		key: a24bfc18fcc1e244ddb0876050d57bb7afc7d3015357149890d41dc0983789d7, value: 94cc74039c82c300ba9b7d348470df2972a34d2601
		// keccak(8819ef417987f8ae7a81f42cdfb18815282fe989326fbff903d13cf0e03ace2a)
		key: a92cdd2c356768eae1dec11953ac097554e9b37aff77f3e27e48327ae70b5d8e, value: 94ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95
		// keccak(3e5fec24aa4dc4e5aee2e025e51e1392c72a2500577559fae9665c6d52bd6a34)
		key: b9a1a659fa3de49828c24b8688647f39a98f15b762105bc7dcf32d9c459340ca, value: 880de0b6b3a7640000
		// keccak(3e5fec24aa4dc4e5aee2e025e51e1392c72a2500577559fae9665c6d52bd6a32)
		key: cf0c9f81324142c14384a63967ad4cf1d9cebe2d8870d44219174f98a2cae008, value: 94ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95
		// keccak(697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f206513)
		key: cf875a7874bb7bbe91aea7f1b7d40ebfc3472ec92f5f617a084432e4af3e7c79, value: 8308b9fd
		// keccak(bfd358e93f18da3ed276c3afdbdba00b8f0b6008a03476a6a86bd6320ee6938f)
		key: d14bd34b88c580425bfde9f3cda36813aaf1b78ba7d50fd94249991ecfc12969, value: 8308b9d9
		// keccak(8819ef417987f8ae7a81f42cdfb18815282fe989326fbff903d13cf0e03ace2c)
		key: d6aea97326ba2dea31ead03266fdf408ffe1cd658f3a1437b19f15b2a33790e7, value: 843b9aca00
		// keccak(8819ef417987f8ae7a81f42cdfb18815282fe989326fbff903d13cf0e03ace2d)
		key: ecebce584bb8d44beca09dcc6bac05c72b516102f58e9dffd18557b2f2df808d, value: 8307e5f1
		// keccak(c5069e24aaadb2addc3e52e868fcf3f4f8acf5a87e24300992fd4540c2a87eef)
		key: eece3f48c03ffd0d090e30e6fc0dfc7b45019d71a75fafafccc76577ce178f2d, value: 94ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95
		// keccak(8819ef417987f8ae7a81f42cdfb18815282fe989326fbff903d13cf0e03ace29)
		key: f6c9906f00400cd8011256368849abf5d045cb493cf4841c92ea0271eae73bbd, value: 94cc74039c82c300ba9b7d348470df2972a34d2601
		// keccak(3e5fec24aa4dc4e5aee2e025e51e1392c72a2500577559fae9665c6d52bd6a33)
		key: ff2898466379f431e1a96c0e04780b196f7d4528c6cc7050e97ef25b10b39d97, value: 94ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95
	*/
	/*
		From FlatTrie log
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba0000000000000000000000000000000000000000000000000000000000000000, v: 01ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95, step: 517464
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba0000000000000000000000000000000000000000000000000000000000000004, v: ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95, step: 517464
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba0000000000000000000000000000000000000000000000000000000000000005, v: 06, step: 571901
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba3e5fec24aa4dc4e5aee2e025e51e1392c72a2500577559fae9665c6d52bd6a32, v: ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95, step: 517503
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba3e5fec24aa4dc4e5aee2e025e51e1392c72a2500577559fae9665c6d52bd6a33, v: ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95, step: 517503
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba3e5fec24aa4dc4e5aee2e025e51e1392c72a2500577559fae9665c6d52bd6a34, v: 0de0b6b3a7640000, step: 517503
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba3e5fec24aa4dc4e5aee2e025e51e1392c72a2500577559fae9665c6d52bd6a35, v: 07e57f, step: 517503
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f20650f, v: cc74039c82c300ba9b7d348470df2972a34d2601, step: 571901
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f206510, v: ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95, step: 571901
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f206511, v: ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95, step: 571901
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f206512, v: 3b9aca00, step: 571901
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f206513, v: 08b9fd, step: 571901
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba75f96ab15d697e93042dc45b5c896c4b27e89bb6eaf39475c5c371cb2513f7d2, v: cc74039c82c300ba9b7d348470df2972a34d2601, step: 517670
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba75f96ab15d697e93042dc45b5c896c4b27e89bb6eaf39475c5c371cb2513f7d3, v: ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95, step: 517670
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba75f96ab15d697e93042dc45b5c896c4b27e89bb6eaf39475c5c371cb2513f7d4, v: ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95, step: 517670
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba75f96ab15d697e93042dc45b5c896c4b27e89bb6eaf39475c5c371cb2513f7d5, v: 3b9aca00, step: 517670
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba75f96ab15d697e93042dc45b5c896c4b27e89bb6eaf39475c5c371cb2513f7d6, v: 07e626, step: 517670
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba7ff1ccd6c3a4ffcca1b442665f88379b09ebea17412d175160ef108fe4d27708, v: 12, step: 517478
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba8819ef417987f8ae7a81f42cdfb18815282fe989326fbff903d13cf0e03ace29, v: cc74039c82c300ba9b7d348470df2972a34d2601, step: 517617
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba8819ef417987f8ae7a81f42cdfb18815282fe989326fbff903d13cf0e03ace2a, v: ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95, step: 517617
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba8819ef417987f8ae7a81f42cdfb18815282fe989326fbff903d13cf0e03ace2b, v: ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95, step: 517617
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba8819ef417987f8ae7a81f42cdfb18815282fe989326fbff903d13cf0e03ace2c, v: 3b9aca00, step: 517617
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0ba8819ef417987f8ae7a81f42cdfb18815282fe989326fbff903d13cf0e03ace2d, v: 07e5f1, step: 517617
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0baa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49, v: 12, step: 517464
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0babfd358e93f18da3ed276c3afdbdba00b8f0b6008a03476a6a86bd6320ee6938c, v: ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95, step: 571865
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0babfd358e93f18da3ed276c3afdbdba00b8f0b6008a03476a6a86bd6320ee6938d, v: ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95, step: 571865
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0babfd358e93f18da3ed276c3afdbdba00b8f0b6008a03476a6a86bd6320ee6938f, v: 08b9d9, step: 571865
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0bac5069e24aaadb2addc3e52e868fcf3f4f8acf5a87e24300992fd4540c2a87eed, v: cc74039c82c300ba9b7d348470df2972a34d2601, step: 571862
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0bac5069e24aaadb2addc3e52e868fcf3f4f8acf5a87e24300992fd4540c2a87eee, v: ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95, step: 571862
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0bac5069e24aaadb2addc3e52e868fcf3f4f8acf5a87e24300992fd4540c2a87eef, v: ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95, step: 571862
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0bac5069e24aaadb2addc3e52e868fcf3f4f8acf5a87e24300992fd4540c2a87ef0, v: 3b9aca00, step: 571862
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0bac5069e24aaadb2addc3e52e868fcf3f4f8acf5a87e24300992fd4540c2a87ef1, v: 08b9d6, step: 571862
			storage: addr: <nil>, k: fb390fe9eacaaf75d88bc8ce82038219da25a0bad655dac6cd810cc6fa88e194418d5d68ee3c0d1524ca99102d7454b48a45fcc8, v: 12, step: 517614
	*/
	storageUpdates := []struct {
		slot  []byte
		value []byte
	}{
		// 571905
		{common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"), common.Hex2Bytes("01ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95")},
		{common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000004"), common.Hex2Bytes("ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95")},
		{common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000005"), common.Hex2Bytes("06")},
		{common.Hex2Bytes("3e5fec24aa4dc4e5aee2e025e51e1392c72a2500577559fae9665c6d52bd6a32"), common.Hex2Bytes("ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95")},
		{common.Hex2Bytes("3e5fec24aa4dc4e5aee2e025e51e1392c72a2500577559fae9665c6d52bd6a33"), common.Hex2Bytes("ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95")},
		{common.Hex2Bytes("3e5fec24aa4dc4e5aee2e025e51e1392c72a2500577559fae9665c6d52bd6a34"), common.Hex2Bytes("0de0b6b3a7640000")},
		{common.Hex2Bytes("3e5fec24aa4dc4e5aee2e025e51e1392c72a2500577559fae9665c6d52bd6a35"), common.Hex2Bytes("07e57f")},
		{common.Hex2Bytes("697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f20650f"), common.Hex2Bytes("cc74039c82c300ba9b7d348470df2972a34d2601")},
		{common.Hex2Bytes("697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f206510"), common.Hex2Bytes("ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95")},
		{common.Hex2Bytes("697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f206511"), common.Hex2Bytes("ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95")},
		{common.Hex2Bytes("697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f206512"), common.Hex2Bytes("3b9aca00")},
		{common.Hex2Bytes("697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f206513"), common.Hex2Bytes("08b9fd")},
		{common.Hex2Bytes("75f96ab15d697e93042dc45b5c896c4b27e89bb6eaf39475c5c371cb2513f7d2"), common.Hex2Bytes("cc74039c82c300ba9b7d348470df2972a34d2601")},
		{common.Hex2Bytes("75f96ab15d697e93042dc45b5c896c4b27e89bb6eaf39475c5c371cb2513f7d3"), common.Hex2Bytes("ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95")},
		{common.Hex2Bytes("75f96ab15d697e93042dc45b5c896c4b27e89bb6eaf39475c5c371cb2513f7d4"), common.Hex2Bytes("ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95")},
		{common.Hex2Bytes("75f96ab15d697e93042dc45b5c896c4b27e89bb6eaf39475c5c371cb2513f7d5"), common.Hex2Bytes("3b9aca00")},
		{common.Hex2Bytes("75f96ab15d697e93042dc45b5c896c4b27e89bb6eaf39475c5c371cb2513f7d6"), common.Hex2Bytes("07e626")},
		{common.Hex2Bytes("7ff1ccd6c3a4ffcca1b442665f88379b09ebea17412d175160ef108fe4d27708"), common.Hex2Bytes("12")},
		{common.Hex2Bytes("8819ef417987f8ae7a81f42cdfb18815282fe989326fbff903d13cf0e03ace29"), common.Hex2Bytes("cc74039c82c300ba9b7d348470df2972a34d2601")},
		{common.Hex2Bytes("8819ef417987f8ae7a81f42cdfb18815282fe989326fbff903d13cf0e03ace2a"), common.Hex2Bytes("ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95")},
		{common.Hex2Bytes("8819ef417987f8ae7a81f42cdfb18815282fe989326fbff903d13cf0e03ace2b"), common.Hex2Bytes("ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95")},
		{common.Hex2Bytes("8819ef417987f8ae7a81f42cdfb18815282fe989326fbff903d13cf0e03ace2c"), common.Hex2Bytes("3b9aca00")},
		{common.Hex2Bytes("8819ef417987f8ae7a81f42cdfb18815282fe989326fbff903d13cf0e03ace2d"), common.Hex2Bytes("07e5f1")},
		{common.Hex2Bytes("a6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49"), common.Hex2Bytes("12")},
		{common.Hex2Bytes("bfd358e93f18da3ed276c3afdbdba00b8f0b6008a03476a6a86bd6320ee6938c"), common.Hex2Bytes("ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95")},
		{common.Hex2Bytes("bfd358e93f18da3ed276c3afdbdba00b8f0b6008a03476a6a86bd6320ee6938d"), common.Hex2Bytes("ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95")},
		{common.Hex2Bytes("bfd358e93f18da3ed276c3afdbdba00b8f0b6008a03476a6a86bd6320ee6938f"), common.Hex2Bytes("08b9d9")},
		{common.Hex2Bytes("c5069e24aaadb2addc3e52e868fcf3f4f8acf5a87e24300992fd4540c2a87eed"), common.Hex2Bytes("cc74039c82c300ba9b7d348470df2972a34d2601")},
		{common.Hex2Bytes("c5069e24aaadb2addc3e52e868fcf3f4f8acf5a87e24300992fd4540c2a87eee"), common.Hex2Bytes("ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95")},
		{common.Hex2Bytes("c5069e24aaadb2addc3e52e868fcf3f4f8acf5a87e24300992fd4540c2a87eef"), common.Hex2Bytes("ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95")},
		{common.Hex2Bytes("c5069e24aaadb2addc3e52e868fcf3f4f8acf5a87e24300992fd4540c2a87ef0"), common.Hex2Bytes("3b9aca00")},
		{common.Hex2Bytes("c5069e24aaadb2addc3e52e868fcf3f4f8acf5a87e24300992fd4540c2a87ef1"), common.Hex2Bytes("08b9d6")},
		{common.Hex2Bytes("d655dac6cd810cc6fa88e194418d5d68ee3c0d1524ca99102d7454b48a45fcc8"), common.Hex2Bytes("12")},
		// 571906
		{common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000005"), common.Hex2Bytes("07")},
		{common.Hex2Bytes("4ced6d0d36392b04cc5d8761b1327b3bbba6e1089c77f60a9a9ca18e05e4f00f"), common.Hex2Bytes("ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95")},
		{common.Hex2Bytes("4ced6d0d36392b04cc5d8761b1327b3bbba6e1089c77f60a9a9ca18e05e4f010"), common.Hex2Bytes("ec0e8ff20c7ec07d8f0970edbbfb745c4c32bc95")},
		{common.Hex2Bytes("4ced6d0d36392b04cc5d8761b1327b3bbba6e1089c77f60a9a9ca18e05e4f012"), common.Hex2Bytes("08ba02")},
	}

	stepSize := 33

	st, err := NewSecureTrie(common.Hash{}, NewDatabase(dbm), &TrieOpts{})
	if err != nil {
		t.Fatalf("Failed to create secure trie: %v", err)
	}

	for i, update := range storageUpdates {
		if i == stepSize {
			break
		}
		enc, err := rlp.EncodeToBytes(update.value)
		if err != nil {
			t.Fatalf("Failed to rlp encode: %v", err)
		}
		st.TryUpdate(update.slot, enc)
	}

	root := st.Hash()
	fmt.Printf("root: %x\n", root) // 0xf1ef081ee354c3d1ff6ec6188c3dd3c181553fb049b2807d3bf9a22d7dbd8487

	for i, update := range storageUpdates {
		if i < stepSize {
			continue
		}
		enc, err := rlp.EncodeToBytes(update.value)
		if err != nil {
			t.Fatalf("Failed to rlp encode: %v", err)
		}
		st.TryUpdate(update.slot, enc)
	}

	fmt.Printf("root: %x\n", st.Hash()) // 0xec806ef0e7737299d0eeb72658cfacc68952e91996eb03f2a8f32b6affa137ac

	f, err := NewFlatTrieWithDBManager(common.Hash{}, dbm, &addr, &TrieOpts{})
	if err != nil {
		t.Fatalf("Failed to create flat trie: %v", err)
	}

	for _, update := range storageUpdates {
		f.TryUpdate(update.slot, update.value)
	}

	root2 := f.Hash()

	fmt.Printf("root2: %x\n", root2)

	t.Fail()

}
