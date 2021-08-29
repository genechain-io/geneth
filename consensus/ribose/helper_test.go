package ribose_test

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/consensus/ribose"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/assert"
)

type Signer struct {
	addr    common.Address
	privKey []byte
	key     *ecdsa.PrivateKey
}

func NewSigner(str string) *Signer {
	pk, _ := hex.DecodeString(str)
	k, _ := crypto.ToECDSA(pk)
	return &Signer{
		privKey: pk,
		addr:    crypto.PubkeyToAddress(k.PublicKey),
		key:     k,
	}
}

func GenerateSigners(n int) (Signers, error) {
	signers := Signers{}
	for i := 0; i < n; i++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			return nil, err
		}
		signers = append(signers, &Signer{
			privKey: crypto.FromECDSA(key),
			addr:    crypto.PubkeyToAddress(key.PublicKey),
			key:     key})
	}
	return signers, nil
}

type Signers []*Signer

type signersAscending Signers

func (s signersAscending) Len() int           { return len(s) }
func (s signersAscending) Less(i, j int) bool { return bytes.Compare(s[i].addr[:], s[j].addr[:]) < 0 }
func (s signersAscending) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

var (
	defaultSigner = NewSigner(ribose.Signer)
	// Signers for signing tests, defaultSigner should be the first one because
	// registered at first during initialize
	defaultSigners = Signers{
		defaultSigner,
	}
	armContractAddr = common.HexToAddress("0x000000000000000000000000000000000000c000")
)

func init() {
	signers, err := GenerateSigners(6)
	if err != nil {
		panic(err)
	}
	defaultSigners = append(defaultSigners, signers...)
}

type riboseTester struct {
	ethereum  *eth.Ethereum
	workspace string
}

func (t *riboseTester) close() {
	t.ethereum.Stop()
	os.RemoveAll(t.workspace)
}

// Build an ethereum instance with genesis block from testdata/genesis.json for
// testing purpose.
func buildEthereumInstance(t *testing.T) *riboseTester {
	genesis := ribose.NewTestGenesisBlock(t)
	ethConf := &eth.Config{
		Genesis: genesis,
	}

	workspace, err := ioutil.TempDir("", "ribose-test-node-")
	assert.NoError(t, err, "Failed to create temporary keystore")

	// Create a networkless protocol stack and start an Ethereum service within
	stack, err := node.New(&node.Config{DataDir: workspace, UseLightweightKDF: true, Name: "ribose-test-node"})
	assert.NoError(t, err, "Failed to create node")
	ethereum, err := eth.New(stack, ethConf)
	assert.NoError(t, err, "Failed to register Ethereum protocol")

	// Start the node
	assert.NoError(t, stack.Start(), "Failed to start stack")

	ethConf.Genesis.MustCommit(ethereum.ChainDb())
	return &riboseTester{
		ethereum:  ethereum,
		workspace: workspace,
	}
}

func makeHeader(chain consensus.ChainReader, parent *types.Block, state *state.StateDB, engine consensus.Engine) *types.Header {
	var time uint64
	delay := chain.Config().Ribose.Period
	if parent.Time() == 0 {
		time = delay
	} else {
		time = parent.Time() + delay // block time is fixed
	}
	header := &types.Header{
		Root:       state.IntermediateRoot(chain.Config().IsEIP158(parent.Number())),
		ParentHash: parent.Hash(),
		Coinbase:   parent.Coinbase(),
		Difficulty: engine.CalcDifficulty(chain, time, &types.Header{
			Number:     parent.Number(),
			Time:       time - delay,
			Difficulty: parent.Difficulty(),
			UncleHash:  parent.UncleHash(),
		}),
		GasLimit: parent.GasLimit(),
		Number:   new(big.Int).Add(parent.Number(), common.Big1),
		Time:     time,
	}
	if chain.Config().IsLondon(header.Number) {
		header.BaseFee = misc.CalcBaseFee(chain.Config(), parent.Header())
		if !chain.Config().IsLondon(parent.Number()) {
			parentGasLimit := parent.GasLimit() * params.ElasticityMultiplier
			header.GasLimit = core.CalcGasLimit(parentGasLimit, parentGasLimit)
		}
	}
	return header
}

// BlockGen creates blocks for testing.
// See GenerateChain for a detailed explanation.
type BlockGen struct {
	i       int
	parent  *types.Block
	chain   []*types.Block
	header  *types.Header
	statedb *state.StateDB

	gasPool  *core.GasPool
	txs      []*types.Transaction
	receipts []*types.Receipt
	uncles   []*types.Header

	engine consensus.Engine
}

// SetCoinbase sets the coinbase of the generated block.
// It can be called at most once.
func (b *BlockGen) SetCoinbase(addr common.Address) {
	if b.gasPool != nil {
		if len(b.txs) > 0 {
			panic("coinbase must be set before adding transactions")
		}
		panic("coinbase can only be set once")
	}
	b.header.Coinbase = addr
	b.gasPool = new(core.GasPool).AddGas(b.header.GasLimit)
}

// AddTxWithChain adds a transaction to the generated block. If no coinbase has
// been set, the block's coinbase is set to the zero address.
//
// AddTxWithChain panics if the transaction cannot be executed. In addition to
// the protocol-imposed limitations (gas limit, etc.), there are some
// further limitations on the content of transactions that can be
// added. If contract code relies on the BLOCKHASH instruction,
// the block in chain will be returned.
func (b *BlockGen) AddTxWithChain(bc *core.BlockChain, tx *types.Transaction) {
	if b.gasPool == nil {
		b.SetCoinbase(common.Address{})
	}
	b.statedb.Prepare(tx.Hash(), len(b.txs))
	config := vm.Config{}
	// config = vm.Config{Debug: true, Tracer: vm.NewMarkdownLogger(nil, os.Stdout)}
	receipt, err := core.ApplyTransaction(bc.Config(), bc, &b.header.Coinbase, b.gasPool, b.statedb, b.header, tx, &b.header.GasUsed, config)
	if err != nil {
		panic(err)
	}
	b.txs = append(b.txs, tx)
	b.receipts = append(b.receipts, receipt)
}

// PrevBlock returns a previously generated block by number. It panics if
// num is greater or equal to the number of the block being generated.
// For index -1, PrevBlock returns the parent block given to GenerateChain.
func (b *BlockGen) PrevBlock(index int) *types.Block {
	if index >= b.i {
		panic(fmt.Errorf("block index %d out of range (%d,%d)", index, -1, b.i))
	}
	if index == -1 {
		return b.parent
	}
	return b.chain[index]
}

// TxNonce returns the next valid transaction nonce for the
// account at addr. It panics if the account does not exist.
func (b *BlockGen) TxNonce(addr common.Address) uint64 {
	if !b.statedb.Exist(addr) {
		panic("account does not exist")
	}
	return b.statedb.GetNonce(addr)
}

// generateChain from core.GenerateChain except using real chainreader
func generateChain(chainreader consensus.ChainReader, parent *types.Block, engine consensus.Engine, db ethdb.Database, n int, gen func(int, *BlockGen)) ([]*types.Block, []types.Receipts) {
	blocks, receipts := make(types.Blocks, n), make([]types.Receipts, n)
	genblock := func(i int, parent *types.Block, statedb *state.StateDB) (*types.Block, types.Receipts) {
		b := &BlockGen{i: i, chain: blocks, parent: parent, statedb: statedb, engine: engine}
		b.header = makeHeader(chainreader, parent, statedb, b.engine)

		// Handle upgrade build-in system contract code
		systemcontracts.UpgradeBuildInSystemContract(chainreader.Config(), b.header.Number, statedb)
		// Execute any user modifications to the block
		if gen != nil {
			gen(i, b)
		}
		if b.engine != nil {
			// Finalize and seal the block
			block, err := b.engine.FinalizeAndAssemble(chainreader, b.header, statedb, b.txs, b.uncles, b.receipts)
			if err != nil {
				panic(fmt.Sprintf("finalize error: %v", err))
			}

			// Write state changes to db
			root, err := statedb.Commit(true)
			if err != nil {
				panic(fmt.Sprintf("state write error: %v", err))
			}
			if err := statedb.Database().TrieDB().Commit(root, false, nil); err != nil {
				panic(fmt.Sprintf("trie write error: %v", err))
			}
			return block, b.receipts
		}
		return nil, nil
	}
	for i := 0; i < n; i++ {
		statedb, err := state.New(parent.Root(), state.NewDatabase(db), nil)
		if err != nil {
			panic(err)
		}
		block, receipt := genblock(i, parent, statedb)
		blocks[i] = block
		receipts[i] = receipt
		parent = block
	}
	return blocks, receipts
}

func buildBlocks(t *testing.T, tester *riboseTester, n int,
	genFn func(int, *core.BlockChain, *BlockGen),
	signer *Signer,
	signFn func(int, *types.Header, *types.Block, *Signer),
	insertFn func(int, *core.BlockChain, *types.Block) error) types.Blocks {
	if signer == nil {
		signer = defaultSigner
	}
	chain := tester.ethereum.BlockChain()
	engine := chain.Engine().(*ribose.Ribose)
	db := tester.ethereum.ChainDb()

	blocks := make(types.Blocks, 0, n)
	// ribose's snapshot can not find parent if block is not inserted. so
	// generate and inserte one by one
	for i := 0; i < n; i++ {
		// Generate block
		newBlocks, _ := generateChain(chain, chain.CurrentBlock(),
			engine, db, 1, func(_ int, blockGen *BlockGen) {
				// Prepare header for new block
				header := blockGen.PrevBlock(-1).Header()
				header.Number.Add(header.Number, big.NewInt(1))
				header.ParentHash = blockGen.PrevBlock(-1).Hash()
				engine.Authorize(signer.addr, func(account accounts.Account, s string, data []byte) ([]byte, error) {
					return crypto.Sign(crypto.Keccak256(data), signer.key)
				})
				if !assert.NoError(t, engine.Prepare(chain, header), i) {
					return
				}
				blockGen.header.Extra = header.Extra
				blockGen.header.Difficulty = header.Difficulty
				blockGen.SetCoinbase(signer.addr)

				if genFn != nil {
					genFn(i, chain, blockGen)
				}
			})
		if !assert.Len(t, newBlocks, 1) {
			break
		}

		// Sign block
		block := newBlocks[0]
		if !assert.NotNil(t, block) {
			break
		}
		header := block.Header() // Get the header and prepare it for signing
		if !assert.NotNil(t, header) {
			break
		}
		if i > 0 {
			header.ParentHash = blocks[i-1].Hash()
		}
		if signFn != nil {
			signFn(i, header, block, signer)
		} else {
			ribose.Sign(t, header, signer.privKey)
		}
		block = block.WithSeal(header)

		// Insert block
		if insertFn != nil {
			if !assert.NoError(t, insertFn(i, chain, block)) {
				break
			}
		} else {
			idx, err := chain.InsertChain(types.Blocks{block})
			if !assert.NoError(t, err, idx) {
				break
			}
		}
		blocks = append(blocks, block)
	}
	assert.Equal(t, n, len(blocks), "Not all blocks are generated")
	return blocks
}

func TestBuildBlocks(t *testing.T) {
	tester := buildEthereumInstance(t)
	defer tester.close()
	chain := tester.ethereum.BlockChain()

	blocks := buildBlocks(t, tester, 10,
		func(i int, bc *core.BlockChain, bg *BlockGen) {
			if i != 1 {
				tx, err := types.SignTx(
					types.NewTransaction(bg.TxNonce(ribose.SignerAddr),
						defaultSigners[i%len(defaultSigners)].addr, big.NewInt(1000), params.TxGas, common.Big1, nil),
					types.HomesteadSigner{}, ribose.SignerKey)
				if assert.NoError(t, err) {
					bg.AddTxWithChain(bc, tx)
				}
			}
		}, nil, nil, nil)
	assert.Len(t, blocks, 10)
	assert.Equal(t, blocks[len(blocks)-1], chain.CurrentBlock())
}

// callContract calls method of ribose contract with current block
//  - `ret`: If ret is not nil, result is unpacked into ret and nil is returnd. Otherwise, unpacked []interface{} is returnd.
func callContract(t *testing.T, instance *riboseTester, ret interface{},
	method string, args ...interface{}) []interface{} {
	chain := instance.ethereum.BlockChain()
	ethAPI := ethapi.NewPublicBlockChainAPI(instance.ethereum.APIBackend)
	return ribose.CallContract(t, chain, ethAPI, rpc.BlockNumberOrHashWithNumber(rpc.BlockNumber(chain.CurrentBlock().NumberU64())), ret, method, args...)
}
