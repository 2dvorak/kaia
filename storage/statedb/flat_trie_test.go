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

	close()

	sd2, close2 := getSharedDomain(t)
	defer close2()

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
	close()

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

	close2()

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
	close3()

	t.Fail()
}

func TestSharedDomainOnlyStorageUpdates(t *testing.T) {
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
	sd.DomainPut(erigon_kv.AccountsDomain, addr.Bytes(), nil, buf, nil, 0)

	root, err := sd.ComputeCommitment(context.Background(), true, 0, "asdf")
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	_ = root
	root2, ok := sd.GetStorageRootHash(addr.Bytes())
	if !ok {
		t.Errorf("expected true got false")
	}
	fmt.Printf("root2: %x\n", root2)

	t.Fail()
}

func TestFlatTrieUpdateStorage(t *testing.T) {
	if commitment.CurrentAccountDeserialiseMode != commitment.AccountDeserialiseModeErigonV3 {
		mode := commitment.CurrentAccountDeserialiseMode
		commitment.CurrentAccountDeserialiseMode = commitment.AccountDeserialiseModeErigonV3
		defer func() {
			commitment.CurrentAccountDeserialiseMode = mode
		}()
	}
	dbm := newEmptyDBManager()
	defer dbm.Close()

	addr := common.HexToAddress("0x1")
	slot := common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000005")
	value := common.Hex2Bytes("95efef9fe22a5e1ae68baea7069dcb1ac607ed78cf12")

	f, err := NewFlatTrieWithDBManager(common.Hash{}, dbm, &addr, nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	/*if err := f.updateStorage(slot, value[1:]); err != nil {
		t.Errorf("expected nil got %v", err)
	}*/

	if err := f.TryUpdate(slot, value); err != nil {
		t.Errorf("expected nil got %v", err)
	}

	val, err := f.TryGet(slot)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	fmt.Printf("val: %x\n", val)

	root := f.Hash()
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	fmt.Printf("root: %x\n", root)

	root2, err := f.Commit(nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	fmt.Printf("root2: %x\n", root2)

	st, err := NewSecureTrie(common.Hash{}, NewDatabase(dbm), nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	if err := st.TryUpdate(slot, value); err != nil {
		t.Errorf("expected nil got %v", err)
	}
	root3 := st.Hash()
	fmt.Printf("root3: %x\n", root3)

	f2, err := NewFlatTrieWithDBManager(common.Hash{}, dbm, nil, nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}
	if err := f2.TryUpdate(addr.Bytes(), common.Hex2Bytes("00000000")); err != nil {
		t.Errorf("expected nil got %v", err)
	}

	_, err = f.Commit(nil)
	if err != nil {
		t.Errorf("expected nil got %v", err)
	}

	t.Fail()
}
