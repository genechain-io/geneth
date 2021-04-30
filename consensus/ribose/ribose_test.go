package ribose

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"math"
	"math/big"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/assert"
)

var (
	// Only this account is a validator for the 0th span
	Signer           = "8031ac1c4fcf7d4881d0bfb303b6f65cb8ddba22da4318b2f8909854760677eb"
	SignerPrivKey, _ = hex.DecodeString(Signer)
	SignerKey, _     = crypto.ToECDSA(SignerPrivKey)
	SignerAddr       = crypto.PubkeyToAddress(SignerKey.PublicKey) // 0x5bB5Fd822436DB4cbc749BdeDE853257Ef74f5D9

	DiffInTurn  = diffInTurn
	DiffNoTurn  = diffNoTurn
	ExtraSeal   = extraSeal
	ExtraVanity = extraVanity

	MaxValidators = maxValidators
	MaxCandidates = 50

	InitialBackOffTime = initialBackOffTime
	WiggleTime         = wiggleTime

	PickValidatorsAndSort = pickValidatorsAndSort
)

func SortValidators(validators []common.Address) {
	sort.Sort(validatorsAscending(validators))
}

// newTestRibose creates a small sized ribose DPoS scheme useful only for
// testing purposes.
func newTestRibose() *Ribose {
	ribose := New(params.GeneChainConfig, rawdb.NewMemoryDatabase())
	return ribose
}

// NewTestGenesisBlock creates a genesis block from ./testdata/genesis.json
func NewTestGenesisBlock(t *testing.T) *core.Genesis {
	genesisFile := "./testdata/genesis.json"
	genesisData, err := ioutil.ReadFile(genesisFile)
	assert.NoError(t, err, "fail reading", genesisFile)

	gen := &core.Genesis{}
	assert.NoError(t, json.Unmarshal(genesisData, gen))
	return gen
}

// newTestInstance creates a testing blockchain with testing genesis block and
// ribose engine.
func newTestInstance(t *testing.T) (*core.BlockChain, *Ribose) {
	chainDB := rawdb.NewMemoryDatabase()
	// Create genesis block
	genspec := NewTestGenesisBlock(t)
	genspec.MustCommit(chainDB)
	// Create consensus engine
	engine := New(genspec.Config, chainDB)
	// Create Ethereum backend
	bc, err := core.NewBlockChain(chainDB, nil, genspec.Config, engine, vm.Config{}, nil, nil)
	if !assert.NoError(t, err, "create new chain failed") {
		return nil, nil
	}
	engine.SetStateFn(bc.StateAt)
	return bc, engine
}

// Sign a block header with signer. The signature is placed in header.Extra.
func Sign(t *testing.T, header *types.Header, signer []byte) {
	sig, err := secp256k1.Sign(crypto.Keccak256(RiboseRLP(header)), signer)
	assert.NoError(t, err)
	copy(header.Extra[len(header.Extra)-extraSeal:], sig)
}

func BuildContractInput(engine *Ribose, method string, args ...interface{}) ([]byte, error) {
	return engine.riboseABI.Pack(method, args...)
}

// ExcuteContract excutes method with account addr on chain.
//  - `ret`: If ret is not nil, result is unpacked into ret and nil is returnd. Otherwise, unpacked []interface{} is returnd.
func ExecuteContract(chain *core.BlockChain, addr common.Address,
	ret interface{}, method string, args ...interface{}) ([]interface{}, error) {

	r := chain.Engine().(*Ribose)
	header := chain.CurrentHeader()
	statedb, err := r.stateFn(header.Root)
	if err != nil || statedb == nil {
		return nil, err
	}

	data, err := r.riboseABI.Pack(method, args...)
	if err != nil {
		return nil, err
	}

	msg := types.NewMessage(addr, &systemcontracts.RiboseContractAddr, 0, new(big.Int), math.MaxUint64, new(big.Int), data, nil, false)

	// use parent
	result, err := executeMsg(msg, statedb, header, newChainContext(chain, r), r.chainConfig)
	if err != nil {
		return nil, err
	}

	// unpack data
	if ret != nil {
		return nil, r.riboseABI.UnpackIntoInterface(ret, method, result)
	} else {
		// unpack data
		return r.riboseABI.Unpack(method, result)
	}
}

// CallContract uses chain and ethAPI to call method of ribose contract on
// blockNrOrHash.
//  - `ret`: If ret is not nil, result is unpacked into ret and nil is returnd. Otherwise, unpacked []interface{} is returnd.
func CallContract(t *testing.T, chain *core.BlockChain, ethAPI *ethapi.PublicBlockChainAPI,
	blockNrOrHash rpc.BlockNumberOrHash, ret interface{},
	method string, args ...interface{}) []interface{} {
	t.Logf("try call %s", method)

	r := chain.Engine().(*Ribose)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	data, err := r.riboseABI.Pack(method, args...)
	if !assert.NoError(t, err) {
		return nil
	}

	msgData := (hexutil.Bytes)(data)
	gas := (hexutil.Uint64)(uint64(math.MaxUint64 / 2))
	result, err := ethAPI.Call(ctx, ethapi.CallArgs{
		Gas:  &gas,
		To:   &systemcontracts.RiboseContractAddr,
		Data: &msgData,
	}, blockNrOrHash, nil)
	if !assert.NoError(t, err) {
		return nil
	}

	if ret != nil {
		assert.NoError(t, r.riboseABI.UnpackIntoInterface(ret, method, result))
		return nil
	} else {
		// unpack data
		ret, err := r.riboseABI.Unpack(method, result)
		assert.NoError(t, err)
		return ret
	}
}

func TestInitSystemContracts(t *testing.T) {
	chain, r := newTestInstance(t)
	state, err := chain.State()
	assert.NoError(t, err)
	assert.NoError(t, r.initializeSystemContracts(chain, chain.CurrentHeader(), state))
}

func newBlock(t *testing.T, chain *core.BlockChain) {
	block := chain.CurrentBlock()
	header := block.Header()
	state, err := chain.State()
	if !assert.NoError(t, err) {
		return
	}

	header.Number.Add(header.Number, big.NewInt(1))
	header.ParentHash = block.Hash()
	chain.Engine().(*Ribose).Authorize(SignerAddr, func(account accounts.Account, s string, data []byte) ([]byte, error) {
		return crypto.Sign(crypto.Keccak256(data), SignerKey)
	})
	assert.NoError(t, chain.Engine().Prepare(chain, header))
	_, err = chain.Engine().(*Ribose).FinalizeAndAssemble(chain, header, state, nil, nil, nil)
	assert.NoError(t, err)
	Sign(t, header, SignerPrivKey)

	block = types.NewBlockWithHeader(header)
	_, err = chain.InsertChain(types.Blocks{block})
	assert.NoError(t, err)
}

func TestGetSortedValidators(t *testing.T) {
	chain, r := newTestInstance(t)

	vals, err := r.getSortedValidators(chain, chain.CurrentHeader())
	assert.Error(t, err, "unknown ancestor")
	assert.Empty(t, vals, "initial validators not empty")

	newBlock(t, chain)

	vals, err = r.getSortedValidators(chain, chain.CurrentHeader())
	assert.NoError(t, err)
	assert.Empty(t, vals, "initial validators not empty")
}

func TestSendBlockReward(t *testing.T) {
	chain, r := newTestInstance(t)
	state, err := chain.State()
	assert.NoError(t, err)
	assert.EqualError(t,
		r.trySendBlockReward(chain, chain.CurrentHeader(), state),
		"execution reverted")
}

func TestPunish(t *testing.T) {
	chain, r := newTestInstance(t)
	state, err := chain.State()
	assert.NoError(t, err)

	newBlock(t, chain)

	assert.EqualError(t,
		r.tryPunishValidator(chain, chain.CurrentHeader(), state),
		"execution reverted")
}
