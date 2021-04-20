package ribose_test

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"os"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/ribose"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/assert"
)

func TestInitialValidators(t *testing.T) {
	init := buildEthereumInstance(t)
	defer init.close()

	validators := []common.Address{}
	callContract(t, init, &validators, "getValidators")
	assert.Empty(t, validators, "validators should not be initialized")
	ret := callContract(t, init, nil, "getCandidateState", defaultSigner.addr)
	assert.Equal(t, common.HexToAddress("0x0"), ret[0])

	buildBlocks(t, init, 1, nil, nil, nil, nil)

	callContract(t, init, &validators, "getValidators")
	genesisValidators := []common.Address{defaultSigner.addr}
	assert.Equal(t, genesisValidators, validators, "validators not initialized")
	ret = callContract(t, init, nil, "getCandidateState", defaultSigner.addr)
	assert.Equal(t, defaultSigner.addr, ret[0])

	// more validators from extra in genesis
	signers, err := GenerateSigners(5)
	assert.NoError(t, err)
	genspec := ribose.NewTestGenesisBlock(t)
	var b bytes.Buffer
	b.WriteString("0x0000000000000000000000000000000000000000000000000000000000000000")
	for _, signer := range signers {
		t.Log(signer.addr.String(), signer.addr.String()[2:])
		b.WriteString(signer.addr.String()[2:])
	}
	b.WriteString("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	t.Log(b.String(), b.Len())
	genspec.ExtraData = hexutil.MustDecode(b.String())
	// genspec.Coinbase = signers[0].addr
	ethConf := &eth.Config{
		Genesis: genspec,
	}

	workspace, err := ioutil.TempDir("", "ribose-test-node-")
	assert.NoError(t, err, "Failed to create temporary keystore")
	defer os.RemoveAll(workspace)

	// Create a networkless protocol stack and start an Ethereum service within
	stack, err := node.New(&node.Config{DataDir: workspace, UseLightweightKDF: true, Name: "ribose-test-node"})
	assert.NoError(t, err, "Failed to create node")
	ethereum, err := eth.New(stack, ethConf)
	assert.NoError(t, err, "Failed to register Ethereum protocol")

	// Start the node and assemble the JavaScript console around it
	assert.NoError(t, stack.Start(), "Failed to start stack")
	_, err = stack.Attach()
	assert.NoError(t, err, "Failed to attach to node")

	ethConf.Genesis.MustCommit(ethereum.ChainDb())
	init = &riboseTester{ethereum: ethereum}
	chain := ethereum.BlockChain()
	sort.Sort(signersAscending(signers))
	// In turn signing
	for i, j := int(chain.CurrentBlock().NumberU64()), 1; j <= int(chain.Config().Ribose.Epoch); j++ {
		validator := signers[(i+j)%len(signers)]
		blocks := buildBlocks(t, init, 1, nil, validator, nil, nil)
		if !assert.Len(t, blocks, 1, "%d,%d,%v", i, j, validator.addr) ||
			!assert.Equal(t, blocks[0].Header().Difficulty, ribose.DiffInTurn, "%v,%v", blocks[0].NumberU64(), validator.addr) {
			break
		}
	}
}

func TestHeaderExtra(t *testing.T) {
	tester := buildEthereumInstance(t)
	defer tester.close()
	chain := tester.ethereum.BlockChain()

	buildBlocks(t, tester, int(chain.Config().Ribose.Epoch+1), nil, nil, nil, func(i int, c *core.BlockChain, b *types.Block) error {
		_, err := c.InsertChain(types.Blocks{b})
		if !assert.NoError(t, err) {
			return err
		}
		if b.NumberU64()%chain.Config().Ribose.Epoch == 0 {
			assert.Less(t, ribose.ExtraSeal+ribose.ExtraVanity, len(b.Header().Extra), b.Number())
		} else {
			assert.Equal(t, ribose.ExtraSeal+ribose.ExtraVanity, len(b.Header().Extra), b.Number())
		}
		return nil
	})
	if !assert.Greater(t, chain.CurrentBlock().NumberU64(), chain.Config().Ribose.Epoch) {
		return
	}
	header := chain.GetBlockByNumber(chain.Config().Ribose.Epoch).Header()
	headerJSON, _ := json.MarshalIndent(header, "", "  ")
	assert.Less(t, ribose.ExtraSeal+ribose.ExtraVanity, len(header.Extra), string(headerJSON))
}

func initSystemContract(t *testing.T, instance *riboseTester) types.Blocks {
	return buildBlocks(t, instance, 1, nil, nil, nil, nil)
}

func TestInitSystemContract(t *testing.T) {
	tester := buildEthereumInstance(t)
	defer tester.close()
	ret := callContract(t, tester, nil, "ARMAddr")
	assert.Equal(t, armContractAddr, ret[0])
	ret = callContract(t, tester, nil, "initialized")
	assert.False(t, ret[0].(bool))

	blocks := initSystemContract(t, tester)
	for _, block := range blocks {
		receipts := tester.ethereum.BlockChain().GetReceiptsByHash(block.Hash())
		assert.Equal(t, receipts.Len(), len(block.Transactions()))
		for _, receipt := range receipts {
			tx := block.Transaction(receipt.TxHash)
			txJSON, _ := json.MarshalIndent(tx, "", "  ")
			receiptJSON, _ := json.MarshalIndent(receipt, "", "  ")
			msg, err := tx.AsMessage(types.HomesteadSigner{})
			assert.NoError(t, err)
			assert.Equal(t, types.ReceiptStatusSuccessful, receipt.Status, "%v,%s,%s", msg.From(), txJSON, receiptJSON)
		}
	}
	ret = callContract(t, tester, nil, "ARMAddr")
	assert.Equal(t, armContractAddr, ret[0])
	ret = callContract(t, tester, nil, "initialized")
	assert.True(t, ret[0].(bool))
}

func fundSigners(t *testing.T, instance *riboseTester, signers Signers) {
	buildBlocks(t, instance, 1,
		func(i int, bc *core.BlockChain, bg *BlockGen) {
			for _, signer := range signers {
				tx, err := types.SignTx(
					types.NewTransaction(bg.TxNonce(defaultSigner.addr),
						signer.addr, new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1000)), params.TxGas, nil, nil),
					types.HomesteadSigner{}, defaultSigner.key)
				assert.NoError(t, err)
				bg.AddTxWithChain(bc, tx)
			}
		}, nil, nil, nil)
}

func TestFundSigners(t *testing.T) {
	tester := buildEthereumInstance(t)
	defer tester.close()
	fundSigners(t, tester, defaultSigners)
	db := tester.ethereum.ChainDb()
	statedb, err := state.New(tester.ethereum.BlockChain().CurrentBlock().Root(), state.NewDatabase(db), nil)
	if err != nil {
		panic(err)
	}
	for _, signer := range defaultSigners {
		if signer == defaultSigner {
			continue
		}
		assert.Equal(t, new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1000)), statedb.GetBalance(signer.addr))
	}
}

func registerSigners(t *testing.T, tester *riboseTester, signers Signers) types.Blocks {
	return buildBlocks(t, tester, 1, func(i int, bc *core.BlockChain, bg *BlockGen) {
		for _, signer := range signers {
			data, err := ribose.BuildContractInput(bc.Engine().(*ribose.Ribose), "register")
			assert.NoError(t, err)
			tx, err := types.SignTx(
				types.NewTransaction(bg.TxNonce(signer.addr),
					systemcontracts.RiboseContractAddr, common.Big0, params.TxGasContractCreation*100, common.Big1, data),
				types.HomesteadSigner{}, signer.key)
			if assert.NoError(t, err) {
				bg.AddTxWithChain(bc, tx)
			}
		}
	}, nil, nil, nil)
}

func stakeSigners(t *testing.T, tester *riboseTester, signers Signers) types.Blocks {
	return buildBlocks(t, tester, 1,
		func(i int, bc *core.BlockChain, bg *BlockGen) {
			for _, signer := range signers {
				data, err := ribose.BuildContractInput(bc.Engine().(*ribose.Ribose), "stake", signer.addr, big.NewInt(0))
				assert.NoError(t, err)
				tx, err := types.SignTx(
					types.NewTransaction(bg.TxNonce(signer.addr),
						systemcontracts.RiboseContractAddr, new(big.Int).Mul(big.NewInt(2e18), big.NewInt(5)), params.TxGasContractCreation*100, common.Big1, data),
					types.HomesteadSigner{}, signer.key)
				if assert.NoError(t, err) {
					bg.AddTxWithChain(bc, tx)
				}
			}
		}, nil, nil, nil)
}

func testRegisterSigners(t *testing.T, signers Signers) {
	init := buildEthereumInstance(t)
	defer init.close()
	chain := init.ethereum.BlockChain()

	// getTopCandidates and getValidators should be empty at first
	ret := callContract(t, init, nil, "getTopCandidates")
	assert.Empty(t, ret[0])
	assert.Empty(t, ret[1])
	validators := []common.Address{}
	callContract(t, init, &validators, "getValidators")
	assert.Empty(t, validators)

	initSystemContract(t, init)

	// getTopCandidates and getValidators should equal to genesis validators
	ret = callContract(t, init, nil, "getTopCandidates")
	assert.Equal(t, []common.Address{defaultSigner.addr}, ret[0])
	assert.Len(t, ret[1], 1)
	callContract(t, init, &validators, "getValidators")
	assert.Equal(t, []common.Address{defaultSigner.addr}, validators)

	fundSigners(t, init, signers)

	// Stake before register should fail
	blocks := stakeSigners(t, init, signers)
	for _, block := range blocks {
		receipts := chain.GetReceiptsByHash(block.Hash())
		assert.NotEmpty(t, receipts)
		for _, receipt := range receipts {
			tx := block.Transaction(receipt.TxHash)
			txJSON, _ := json.MarshalIndent(tx, "", "  ")
			receiptJSON, _ := json.MarshalIndent(receipt, "", "  ")
			msg, err := tx.AsMessage(types.HomesteadSigner{})
			assert.NoError(t, err)
			if msg.From() == defaultSigner.addr { // Only the default signer can stake successfully
				assert.Equal(t, types.ReceiptStatusSuccessful, receipt.Status, "%v,%s,%s", msg.From(), txJSON, receiptJSON)
			} else {
				assert.Equal(t, types.ReceiptStatusFailed, receipt.Status, "%v,%s,%s", msg.From(), txJSON, receiptJSON)
			}
		}
	}
	// getTopCandidates and getValidators now should be only one candidate
	expectValidators := []common.Address{defaultSigner.addr}
	ret = callContract(t, init, nil, "getTopCandidates")
	assert.Equal(t, expectValidators, ret[0])
	assert.Len(t, ret[1], 1)
	callContract(t, init, &validators, "getValidators")
	assert.Equal(t, expectValidators, validators)

	// Register
	blocks = registerSigners(t, init, signers)
	for _, block := range blocks {
		receipts := chain.GetReceiptsByHash(block.Hash())
		assert.NotEmpty(t, receipts)
		for _, receipt := range receipts {
			tx := block.Transaction(receipt.TxHash)
			txJSON, _ := json.MarshalIndent(tx, "", "  ")
			receiptJSON, _ := json.MarshalIndent(receipt, "", "  ")
			msg, err := tx.AsMessage(types.HomesteadSigner{})
			assert.NoError(t, err)
			if msg.From() == defaultSigner.addr { // The default signer is already registered
				assert.Equal(t, types.ReceiptStatusFailed, receipt.Status, "%v,%s,%s", msg.From(), txJSON, receiptJSON)
			} else {
				assert.Equal(t, types.ReceiptStatusSuccessful, receipt.Status, "%v,%s,%s", msg.From(), txJSON, receiptJSON)
			}
		}
	}
	// getTopCandidates and getValidators now should still be only one candidate
	ret = callContract(t, init, nil, "getTopCandidates")
	assert.Equal(t, expectValidators, ret[0])
	assert.Len(t, ret[1], 1)
	callContract(t, init, &validators, "getValidators")
	assert.Equal(t, expectValidators, validators)
	// Check getCandidateState
	for _, signer := range signers {
		/*
		   address,    // profitTaker
		   uint256,    // totalMined
		   uint256,    // totalFee
		   uint256,    // createTime
		   uint256,    // minerProfit
		   uint256,    // pendingProfit
		   uint256,    // pendingSettleBlock
		   bool        // jailed
		*/
		ret := callContract(t, init, nil, "getCandidateState", signer.addr)
		t.Log(ret)
		assert.Equal(t, 1, ret[3].(*big.Int).Cmp(common.Big0))
	}
	// Register again should fail
	blocks = registerSigners(t, init, signers)
	for _, block := range blocks {
		receipts := chain.GetReceiptsByHash(block.Hash())
		assert.Equal(t, types.ReceiptStatusFailed, receipts[0].Status)
	}
	// getTopCandidates and getValidators now should still be only one candidate
	ret = callContract(t, init, nil, "getTopCandidates")
	assert.Equal(t, expectValidators, ret[0])
	assert.Len(t, ret[1], 1)
	callContract(t, init, &validators, "getValidators")
	assert.Equal(t, expectValidators, validators)

	// Stake
	blocks = stakeSigners(t, init, signers)
	for _, block := range blocks {
		receipts := chain.GetReceiptsByHash(block.Hash())
		assert.NotEmpty(t, receipts)
		for _, receipt := range receipts {
			tx := block.Transaction(receipt.TxHash)
			txJSON, _ := json.MarshalIndent(tx, "", "  ")
			receiptJSON, _ := json.MarshalIndent(receipt, "", "  ")
			msg, err := tx.AsMessage(types.HomesteadSigner{})
			assert.NoError(t, err)
			assert.Equal(t, types.ReceiptStatusSuccessful, receipt.Status, "%v,%s,%s", msg.From(), txJSON, receiptJSON)
		}
	}

	// getValidators should be still only one
	callContract(t, init, &validators, "getValidators")
	assert.Equal(t, expectValidators, validators)
	// but getTopCandidates now should be full
	expectValidators = []common.Address{}
	for i, signer := range signers {
		if i >= 50 {
			break
		}
		expectValidators = append(expectValidators, signer.addr)
	}
	ret = callContract(t, init, nil, "getTopCandidates")
	assert.Equal(t, expectValidators, ret[0])
	assert.Len(t, ret[1], len(expectValidators))

	// Go to epoch
	buildBlocks(t, init, int(chain.Config().Ribose.Epoch-chain.CurrentBlock().NumberU64()%chain.Config().Ribose.Epoch), nil, nil, nil, nil)
	// getTopCandidates should still be full
	ret = callContract(t, init, nil, "getTopCandidates")
	assert.Equal(t, expectValidators, ret[0])
	assert.Len(t, ret[1], len(expectValidators))
	// getValidators now should be full
	expectValidators, err := ribose.PickValidatorsAndSort(ret[0].([]common.Address), ret[1].([]*big.Int))
	assert.NoError(t, err)
	if len(signers) > ribose.MaxCandidates {
		assert.Len(t, expectValidators, ribose.MaxValidators)
	} else {
		assert.Len(t, expectValidators, len(signers))
	}
	callContract(t, init, &validators, "getValidators")
	assert.Equal(t, expectValidators, validators)
}

func TestRegisterSigners(t *testing.T) {
	testRegisterSigners(t, defaultSigners)
	signers, err := GenerateSigners(60)
	assert.NoError(t, err)
	signers = append(defaultSigners, signers...)
	assert.Len(t, defaultSigners, 7)
	assert.Len(t, signers, 67)
	testRegisterSigners(t, signers)
}

func TestSignerNotFound(t *testing.T) {
	init := buildEthereumInstance(t)
	defer init.close()
	initSystemContract(t, init)

	// random signer account that is not a part of the validator set
	signer := "3714d99058cd64541433d59c6b391555b2fd9b54629c2b717a6c9c00d1127b6b"

	buildBlocks(t, init, 1,
		nil, NewSigner(signer), nil,
		func(i int, c *core.BlockChain, b *types.Block) error {
			_, err := c.InsertChain(types.Blocks{b})
			assert.EqualError(t, err, "unauthorized validator")
			return nil
		})
}

func TestInTurnSigning(t *testing.T) {
	tester := buildEthereumInstance(t)
	defer tester.close()
	initSystemContract(t, tester)
	buildBlocks(t, tester, int(tester.ethereum.BlockChain().Config().Ribose.Epoch+100), nil, nil, nil, nil)

	// avoid default signer because default signer might signed recently
	signers, err := GenerateSigners(ribose.MaxValidators)
	assert.NoError(t, err)
	fundSigners(t, tester, signers)
	registerSigners(t, tester, signers)
	stakeSigners(t, tester, signers)
	// Go to epoch
	chain := tester.ethereum.BlockChain()
	buildBlocks(t, tester, int(chain.Config().Ribose.Epoch*2-chain.CurrentBlock().NumberU64()), nil, nil, nil, nil)
	assert.Equal(t, chain.Config().Ribose.Epoch*2, chain.CurrentBlock().NumberU64())

	sort.Sort(signersAscending(signers))
	expectValidators := []common.Address{}
	for _, val := range signers {
		expectValidators = append(expectValidators, val.addr)
	}
	ret := callContract(t, tester, nil, "getValidators")
	assert.Equal(t, expectValidators, ret[0])
	ret = callContract(t, tester, nil, "getTopCandidates")
	t.Log(ret)

	// In turn signing
	for i, j := int(chain.CurrentBlock().NumberU64()), 1; j <= int(chain.Config().Ribose.Epoch); j++ {
		validator := signers[(i+j)%len(signers)]
		blocks := buildBlocks(t, tester, 1, nil, validator, nil, nil)
		if !assert.Len(t, blocks, 1, "%d,%d,%v", i, j, validator.addr) ||
			!assert.Equal(t, blocks[0].Header().Difficulty, ribose.DiffInTurn, "%v,%v", blocks[0].NumberU64(), validator.addr) {
			break
		}
	}
}

func TestOutOfTurnSigning(t *testing.T) {
	tester := buildEthereumInstance(t)
	defer tester.close()
	initSystemContract(t, tester)
	// avoid default signer because default signer might signed recently
	signers, err := GenerateSigners(ribose.MaxValidators)
	assert.NoError(t, err)
	fundSigners(t, tester, signers)
	registerSigners(t, tester, signers)
	stakeSigners(t, tester, signers)
	chain := tester.ethereum.BlockChain()
	buildBlocks(t, tester, int(chain.Config().Ribose.Epoch-chain.CurrentBlock().NumberU64()), nil, nil, nil, nil)

	// Only one signer can sign after one second delay
	sort.Sort(signersAscending(signers))
	engine := chain.Engine().(*ribose.Ribose)
	db := tester.ethereum.ChainDb()
	parent := chain.CurrentBlock()
	for i := len(signers) - 1; i >= 0; i-- {
		if int(chain.Config().Ribose.Epoch+1)%len(signers) == i {
			// Skip in-turn signer
			continue
		}
		signer := signers[i]
		newBlocks, _ := generateChain(chain, parent,
			engine, db, 1, func(_ int, blockGen *BlockGen) {
				header := parent.Header()
				header.Number.Add(header.Number, big.NewInt(1))
				header.ParentHash = parent.Hash()
				engine.Authorize(signer.addr, func(account accounts.Account, s string, data []byte) ([]byte, error) {
					return crypto.Sign(crypto.Keccak256(data), signer.key)
				})
				if !assert.NoError(t, chain.Engine().Prepare(chain, header), i) {
					return
				}
				blockGen.header.Extra = header.Extra
				blockGen.header.Difficulty = header.Difficulty
				blockGen.SetCoinbase(signer.addr)
				blockGen.header.Time = parent.Header().Time + chain.Config().Ribose.Period + ribose.InitialBackOffTime
			})
		if !assert.Len(t, newBlocks, 1) {
			break
		}
		block := newBlocks[0]
		header := block.Header()
		ribose.Sign(t, header, signer.privKey)
		block = block.WithSeal(header)
		assert.Equal(t, block.Header().Difficulty, ribose.DiffNoTurn, "%d,%d", i, block.NumberU64())
		// Only one signer can sign at this time
		idx, err := chain.InsertChain(types.Blocks{block})
		if err != nil {
			assert.EqualError(t, err, "invalid timestamp", i)
		} else {
			t.Log(idx, i, block.NumberU64())
		}
	}
	assert.Equal(t, chain.Config().Ribose.Epoch+1, chain.CurrentBlock().NumberU64())
}

func TestOutOfService(t *testing.T) {
	tester := buildEthereumInstance(t)
	defer tester.close()
	initSystemContract(t, tester)
	// avoid default signer because default signer might signed recently
	signers, err := GenerateSigners(ribose.MaxCandidates)
	assert.NoError(t, err)
	sort.Sort(signersAscending(signers))
	fundSigners(t, tester, signers)
	registerSigners(t, tester, signers)
	stakeSigners(t, tester, signers)
	// Go to epoch
	chain := tester.ethereum.BlockChain()
	buildBlocks(t, tester, int(chain.Config().Ribose.Epoch-chain.CurrentBlock().NumberU64()), nil, nil, nil, nil)
	// expect candidates should exclude default signer
	expectCandidates := []common.Address{defaultSigner.addr}
	for i, signer := range signers {
		if i == ribose.MaxCandidates-1 {
			expectCandidates[0] = signer.addr
			break
		}
		expectCandidates = append(expectCandidates, signer.addr)
	}
	ret := callContract(t, tester, nil, "getTopCandidates")
	assert.Equal(t, expectCandidates, ret[0])

	// Miss the first signer
	validators := make(Signers, len(signers))
	copy(validators, signers)
	if len(validators) > ribose.MaxValidators {
		validators = validators[:ribose.MaxValidators]
	}
	sort.Sort(signersAscending(validators))
	nSigners := len(validators)
	blocksToHitJail := nSigners*48 + nSigners
	for i, j := int(chain.CurrentBlock().NumberU64()), 1; j <= blocksToHitJail; j++ {
		idx := (i+j)%(nSigners-1) + 1
		diff := ribose.DiffNoTurn
		if idx == (i+j)%(nSigners) {
			diff = ribose.DiffInTurn
		}
		blocks := buildBlocks(t, tester, 1,
			func(i int, bc *core.BlockChain, bg *BlockGen) {
				bg.header.Time = bg.header.Time + ribose.InitialBackOffTime + uint64(len(signers))*ribose.WiggleTime
			}, validators[idx], nil, nil)
		if !assert.Len(t, blocks, 1, idx) ||
			!assert.Equal(t, blocks[0].Header().Difficulty, diff, "%d,%d,%d,%d", j, idx, nSigners, blocks[0].NumberU64()) {
			break
		}
	}
	t.Log(blocksToHitJail, nSigners, chain.CurrentBlock().NumberU64())
	// Check punished
	/*
	   address,    // profitTaker
	   uint256,    // totalMined
	   uint256,    // totalFee
	   uint256,    // createTime
	   uint256,    // minerProfit
	   uint256,    // pendingProfit
	   uint256,    // pendingSettleBlock
	   bool        // jailed
	*/
	ret = callContract(t, tester, nil, "getCandidateState", validators[0].addr)
	t.Log(ret)
	assert.True(t, ret[7].(bool))

	// getTopCandidates should exclude first signer
	for idx, c := range expectCandidates {
		if c == validators[0].addr {
			expectCandidates[idx] = expectCandidates[len(expectCandidates)-1]
			break
		}
	}
	expectCandidates = expectCandidates[:len(expectCandidates)-1]
	ret = callContract(t, tester, nil, "getTopCandidates")
	assert.Equal(t, expectCandidates, ret[0])
	// also do getValidators
	expectValidators := append([]common.Address{}, expectCandidates...)
	ribose.SortValidators(expectValidators)
	if len(expectValidators) > ribose.MaxValidators {
		expectValidators = expectValidators[:ribose.MaxValidators]
	}
	ret = callContract(t, tester, nil, "getValidators")
	assert.Equal(t, expectValidators, ret[0])

	// Can sign but can not get reward
	// @todo to be finished
	// buildBlocks(t, tester, 1,
	// 	func(i int, bc *core.BlockChain, bg *BlockGen) {
	// 		bg.header.Time = bg.header.Time + ribose.InitialBackOffTime + uint64(len(signers))*ribose.WiggleTime
	// 	}, validators[0], nil,
	// 	func(i int, c *core.BlockChain, b *types.Block) error {
	// 		_, err := c.InsertChain(types.Blocks{b})
	// 		assert.NoError(t, err)
	// 		return nil
	// 	})

	// Go to epoch
	blocksToHitJail = int(chain.Config().Ribose.Epoch - chain.CurrentBlock().NumberU64()%chain.Config().Ribose.Epoch)
	for i, j := int(chain.CurrentBlock().NumberU64()), 1; j <= blocksToHitJail; j++ {
		idx := (i+j)%(nSigners-1) + 1
		buildBlocks(t, tester, 1,
			func(i int, bc *core.BlockChain, bg *BlockGen) {
				bg.header.Time = bg.header.Time + ribose.InitialBackOffTime + uint64(len(signers))*ribose.WiggleTime
			}, validators[idx], nil, nil)
	}
	t.Log(blocksToHitJail, nSigners, chain.CurrentBlock().NumberU64())
	// getValidators should still exclude first signer
	ret = callContract(t, tester, nil, "getTopCandidates")
	assert.Equal(t, expectCandidates, ret[0])
	vals, err := ribose.PickValidatorsAndSort(ret[0].([]common.Address), ret[1].([]*big.Int))
	assert.NoError(t, err)
	assert.Equal(t, expectValidators, vals)
	// also do getValidators
	ret = callContract(t, tester, nil, "getValidators")
	assert.Equal(t, expectValidators, ret[0])
	// signing now should be unauthorized
	buildBlocks(t, tester, 1,
		func(i int, bc *core.BlockChain, bg *BlockGen) {
			bg.header.Time = bg.header.Time + ribose.InitialBackOffTime + uint64(len(signers))*ribose.WiggleTime
		}, nil, nil,
		func(i int, c *core.BlockChain, b *types.Block) error {
			// Should fail because last block is signed by default signer
			_, err := c.InsertChain(types.Blocks{b})
			assert.EqualError(t, err, "unauthorized validator", chain.CurrentBlock().NumberU64())
			return nil
		})
}

func TestSignTooFast(t *testing.T) {
	tester := buildEthereumInstance(t)
	defer tester.close()
	initSystemContract(t, tester)
	// Inturn signing too fast
	buildBlocks(t, tester, 1,
		func(i int, bc *core.BlockChain, bg *BlockGen) {
			header := bg.PrevBlock(-1).Header()
			bg.header.Time = header.Time + 1
		}, nil, nil,
		func(i int, c *core.BlockChain, b *types.Block) error {
			_, err := c.InsertChain(types.Blocks{b})
			assert.EqualError(t, err, "invalid timestamp")
			return nil
		})
	fundSigners(t, tester, defaultSigners)
	registerSigners(t, tester, defaultSigners)
	stakeSigners(t, tester, defaultSigners)
	// Go to epoch
	chain := tester.ethereum.BlockChain()
	buildBlocks(t, tester, int(chain.Config().Ribose.Epoch-chain.CurrentBlock().NumberU64()), nil, nil, nil, nil)
	// Out-of-turn signing too fast
	buildBlocks(t, tester, 1,
		func(i int, bc *core.BlockChain, bg *BlockGen) {
			header := bg.PrevBlock(-1).Header()
			bg.header.Time = header.Time + chain.Config().Ribose.Period
		}, nil, nil,
		func(i int, c *core.BlockChain, b *types.Block) error {
			_, err := c.InsertChain(types.Blocks{b})
			assert.EqualError(t, err, "invalid timestamp")
			return nil
		})
}
