package bridge

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

var genesisKey *ecdsa.PrivateKey
var auth *bind.TransactOpts

type Platform struct {
	c   *Bridge
	sim *backends.SimulatedBackend
}

func keccak256(b ...[]byte) [32]byte {
	h := crypto.Keccak256(b...)
	r := [32]byte{}
	copy(r[:], h)
	return r
}

func init() {
	fmt.Println("Initializing...")
	genesisKey, _ = crypto.GenerateKey()
	auth = bind.NewKeyedTransactor(genesisKey)
}

func setup(beaconCommRoot, bridgeCommRoot [32]byte) (*Platform, error) {
	alloc := make(core.GenesisAlloc)
	balance := big.NewInt(123000000000000000)
	alloc[auth.From] = core.GenesisAccount{Balance: balance}
	sim := backends.NewSimulatedBackend(alloc, 6000000)

	addr, _, c, err := DeployBridge(auth, sim, beaconCommRoot, bridgeCommRoot)
	if err != nil {
		return nil, err
	}
	sim.Commit()

	fmt.Printf("deployed, addr: %x\n", addr)
	return &Platform{c, sim}, nil
}

func setupWithoutCommittee() (*Platform, error) {
	return setup([32]byte{}, [32]byte{})
}

type account struct {
	PrivateKey *ecdsa.PrivateKey
	Address    common.Address
}

func newAccount() *account {
	key, _ := crypto.GenerateKey()
	return &account{
		PrivateKey: key,
		Address:    crypto.PubkeyToAddress(key.PublicKey),
	}
}

func (p *Platform) printReceipt(tx *types.Transaction) {
	ctx, _ := context.WithTimeout(context.Background(), time.Minute)
	receipt, err := p.sim.TransactionReceipt(ctx, tx.Hash())
	if err != nil {
		fmt.Println("receipt err:", err)
	}
	fmt.Printf("tx gas used: %v\n", receipt.CumulativeGasUsed)

	if len(receipt.Logs) == 0 {
		fmt.Println("empty log")
		return
	}

	for i, log := range receipt.Logs {
		fmt.Printf("logs[%d]: %x %s\n", i, log.Data, string(log.Data))
	}
}

func TestSwapBeacon(t *testing.T) {
	// Genesis committee
	beaconOld := [][32]byte{[32]byte{1, 2, 3}, [32]byte{4, 5, 6}}
	beaconOldRoot := keccak256(beaconOld[0][:], beaconOld[1][:])
	fmt.Printf("beaconOldRoot: %x\n", beaconOldRoot)
	fmt.Printf("beaconOld[0]: %x\n", beaconOld[0])

	bridgeOld := [][32]byte{[32]byte{101, 102, 103}, [32]byte{104, 105, 106}}
	bridgeOldRoot := keccak256(bridgeOld[0][:], bridgeOld[1][:])
	fmt.Printf("bridgeOldRoot: %x\n", bridgeOldRoot)
	// fmt.Printf("bridgeOld[0]: %x\n", bridgeOld[0])

	p, err := setup(beaconOldRoot, bridgeOldRoot)
	if err != nil {
		t.Fatalf("Fail to deloy contract: %v\n", err)
	}

	// Test calling swapBeacon
	const comm_path_length = 1
	const comm_size = 1 << comm_path_length
	const pubkey_length = comm_size * comm_path_length
	const inst_path_length = 1
	const inst_size = 1 << inst_path_length
	const inst_length = 100
	const beacon_length = 512
	const bridge_length = 256
	_ = p

	beaconNew := [][32]byte{[32]byte{7, 8, 9}, [32]byte{10, 11, 12}}
	beaconNewRoot := keccak256(beaconNew[0][:], beaconNew[1][:])
	fmt.Printf("beaconNewRoot: %x\n", beaconNewRoot)
	fmt.Printf("beaconNew[0]: %x\n", beaconNew[0])

	insts := [][inst_length]byte{
		[inst_length]byte{'h', 'e', 'l', 'l', 'o'},
		[inst_length]byte{'w', 'o', 'r', 'l', 'd'},
	}
	inst := insts[0]
	instHashes := [][32]byte{
		keccak256(insts[0][:]),
		keccak256(insts[1][:]),
	}

	beaconInstRoot := keccak256(instHashes[0][:], instHashes[1][:])
	beaconInstPath := [inst_path_length][32]byte{instHashes[1]}
	beaconPathIsLeft := [inst_path_length]bool{false}
	fmt.Printf("beaconInstRoot: %x\n", beaconInstRoot)

	beaconBlkData := [32]byte{}
	beaconBlkHash := keccak256(beaconInstRoot[:], beaconBlkData[:])
	fmt.Printf("beaconBlkHash: %x\n", beaconBlkHash)

	beaconSignerPubkeys := [comm_size][32]byte{beaconOld[1], beaconOld[0]}
	beaconSignerSig := [32]byte{}
	beaconSignerPaths := [pubkey_length][32]byte{beaconOld[0], beaconOld[1]}
	beaconSignerPathIsLeft := [pubkey_length]bool{true, false}

	// For bridge
	bridgeInstRoot := keccak256(instHashes[0][:], instHashes[1][:])
	bridgeInstPath := [inst_path_length][32]byte{instHashes[1]}
	bridgePathIsLeft := [inst_path_length]bool{false}
	// fmt.Printf("bridgeInstRoot: %x\n", bridgeInstRoot)

	bridgeBlkData := [32]byte{}
	bridgeBlkHash := keccak256(bridgeInstRoot[:], bridgeBlkData[:])
	// fmt.Printf("bridgeBlkHash: %x\n", bridgeBlkHash)

	bridgeSignerPubkeys := [comm_size][32]byte{bridgeOld[1], bridgeOld[0]}
	bridgeSignerSig := [32]byte{}
	bridgeSignerPaths := [pubkey_length][32]byte{bridgeOld[0], bridgeOld[1]}
	bridgeSignerPathIsLeft := [pubkey_length]bool{true, false}

	auth.GasLimit = 6000000
	tx, err := p.c.SwapBeacon(
		auth,
		beaconNewRoot,
		inst[:],
		beaconInstPath,
		beaconPathIsLeft,
		beaconInstRoot,
		beaconBlkData,
		beaconBlkHash,
		beaconSignerPubkeys,
		beaconSignerSig,
		beaconSignerPaths,
		beaconSignerPathIsLeft,
		bridgeInstPath,
		bridgePathIsLeft,
		bridgeInstRoot,
		bridgeBlkData,
		bridgeBlkHash,
		bridgeSignerPubkeys,
		bridgeSignerSig,
		bridgeSignerPaths,
		bridgeSignerPathIsLeft,
	)
	if err != nil {
		fmt.Println("err:", err)
	}
	// fmt.Printf("%x\n", tx.To())
	// fmt.Printf("%x\n", tx.Hash())
	// fmt.Printf("%x\n", tx)
	// j, _ := tx.MarshalJSON()
	// fmt.Printf("%s\n", string(j))

	p.sim.Commit()

	p.printReceipt(tx)
}

func TestHash(t *testing.T) {
	p, err := setupWithoutCommittee()
	if err != nil {
		t.Fatalf("Fail to deloy contract: %v\n", err)
	}

	x, y := p.c.Get(nil)
	fmt.Println(x, y)

	inst := []byte{}
	x2, y2 := p.c.ParseSwapBeaconInst(nil, nil)
	fmt.Println(x2, y2)

	x3, _ := p.c.GetHash(nil, inst)
	fmt.Printf("%x\n", x3)

	x4 := crypto.Keccak256(inst[:])
	fmt.Printf("%x\n", x4)

	leaf := [32]byte{1, 2, 3}
	right := [32]byte{}
	comb := append(leaf[:], right[:]...)
	path := [1][32]byte{right}
	left := [1]bool{false}
	r := crypto.Keccak256(comb)
	root := [32]byte{}
	copy(root[:], r)
	leaf = [32]byte{1, 2, 3}
	x5, _ := p.c.InMerkleTree(nil, leaf, root, path, left)
	fmt.Println(x5)
}
