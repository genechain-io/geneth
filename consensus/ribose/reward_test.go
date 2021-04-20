package ribose_test

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ribose"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/assert"
)

func TestBlockReward(t *testing.T) {
	tester := buildEthereumInstance(t)
	defer tester.close()

	reward := big.Int{}
	fee := big.Int{}
	buildBlocks(t, tester, 10,
		func(i int, bc *core.BlockChain, bg *BlockGen) {
			if i%2 == 0 {
				tx, err := types.SignTx(
					types.NewTransaction(bg.TxNonce(ribose.SignerAddr),
						defaultSigners[i%len(defaultSigners)].addr, big.NewInt(1000), params.TxGas, common.Big1, nil),
					types.HomesteadSigner{}, ribose.SignerKey)
				if assert.NoError(t, err) {
					bg.AddTxWithChain(bc, tx)
				}
			}
		}, nil, nil,
		func(i int, c *core.BlockChain, b *types.Block) error {
			_, err := c.InsertChain(types.Blocks{b})
			if !assert.NoError(t, err) {
				return err
			}
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
			ret := callContract(t, tester, nil, "getCandidateState", ribose.SignerAddr)
			t.Log(ret)
			assert.Equal(t, reward.Mul(big.NewInt(2e18), big.NewInt(int64(i+1))), ret[1], "reward mismatch")
			assert.Equal(t, fee.Mul(big.NewInt(21000), big.NewInt(int64(i)/2+1)), ret[2], "reward mismatch")
			return nil
		})
}

func TestFeeShare(t *testing.T) {
	// @todo to be finished
	return
	tester := buildEthereumInstance(t)
	signers := defaultSigners
	signer := signers[0]
	fundSigners(t, tester, signers)
	// register signers with different fee share
	buildBlocks(t, tester, 1, func(i int, bc *core.BlockChain, bg *BlockGen) {
		data, err := ribose.BuildContractInput(bc.Engine().(*ribose.Ribose), "register", uint32(8e8))
		assert.NoError(t, err)
		tx, err := types.SignTx(
			types.NewTransaction(bg.TxNonce(signer.addr),
				systemcontracts.RiboseContractAddr, common.Big0, params.TxGasContractCreation*100, common.Big1, data),
			types.HomesteadSigner{}, signer.key)
		if assert.NoError(t, err) {
			bg.AddTxWithChain(bc, tx)
		}
	}, nil, nil, nil)
	// Check feeShare of getCandidateState
	/*
	   uint256,    // stakerShare
	   uint256,    // stakePower
	   uint256,    // stakeRNA
	   uint256,    // stakeARM
	   uint256     // profitValue
	*/
	ret := callContract(t, tester, nil, "getCandidateStakeInfo", signer.addr)
	t.Log(ret)
	assert.Equal(t, big.NewInt(8*1e8), ret[0])

	stakers, err := GenerateSigners(len(signers))
	assert.NoError(t, err)
	fundSigners(t, tester, stakers)
	// stake signer
	blocks := buildBlocks(t, tester, 1,
		func(i int, bc *core.BlockChain, bg *BlockGen) {
			for k, staker := range stakers {
				data, err := ribose.BuildContractInput(bc.Engine().(*ribose.Ribose), "stake", signer.addr, big.NewInt(0))
				assert.NoError(t, err)
				tx, err := types.SignTx(
					types.NewTransaction(bg.TxNonce(staker.addr),
						systemcontracts.RiboseContractAddr, new(big.Int).Mul(big.NewInt(int64(k+1)), big.NewInt(1e18)), params.TxGasContractCreation*100, common.Big1, data),
					types.HomesteadSigner{}, staker.key)
				if assert.NoError(t, err) {
					bg.AddTxWithChain(bc, tx)
				}
			}
		}, nil, nil, nil)
	receipts := tester.ethereum.BlockChain().GetReceiptsByHash(blocks[0].Hash())
	for _, receipt := range receipts {
		headerJSON, _ := json.MarshalIndent(receipt, "", "  ")
		txJSON, _ := json.MarshalIndent(blocks[0].Transactions()[receipt.TransactionIndex], "", "  ")
		assert.Equal(t, types.ReceiptStatusSuccessful, receipt.Status, string(headerJSON)+string(txJSON))
	}

	// Check stakeRNA of getCandidateState
	/*
	   uint256,    // stakerShare
	   uint256,    // stakePower
	   uint256,    // stakeRNA
	   uint256,    // stakeARM
	   uint256     // profitValue
	*/
	ret = callContract(t, tester, nil, "getCandidateStakeInfo", signer.addr)
	t.Log(signer.addr, ret)
	assert.Equal(t, new(big.Int).Mul(big.NewInt(int64((len(signers)+1)*len(signers)/2)), big.NewInt(1e18)), ret[2])

	// build 100 blocks
	buildBlocks(t, tester, 100, nil, nil, nil, nil)

	// Check profitValue of getCandidateState
	/*
	   uint256,    // stakerShare
	   uint256,    // stakePower
	   uint256,    // stakeRNA
	   uint256,    // stakeARM
	   uint256     // profitValue
	*/
	ret = callContract(t, tester, nil, "getCandidateStakeInfo", signer.addr)
	t.Log(signer.addr, ret)
	assert.Equal(t, new(big.Int).Mul(big.NewInt(int64(len(signers))), big.NewInt(1e18)), ret[4])

	// settle reward
	blocks = buildBlocks(t, tester, 1,
		func(i int, bc *core.BlockChain, bg *BlockGen) {
			data, err := ribose.BuildContractInput(bc.Engine().(*ribose.Ribose), "settleStakerProfit", signer.addr)
			assert.NoError(t, err)
			tx, err := types.SignTx(
				types.NewTransaction(bg.TxNonce(ribose.SignerAddr),
					systemcontracts.RiboseContractAddr, common.Big0, params.TxGasContractCreation*100, common.Big1, data),
				types.HomesteadSigner{}, ribose.SignerKey)
			if assert.NoError(t, err) {
				bg.AddTxWithChain(bc, tx)
			}
		}, nil, nil, nil)
	receipts = tester.ethereum.BlockChain().GetReceiptsByHash(blocks[0].Hash())
	for _, receipt := range receipts {
		headerJSON, _ := json.MarshalIndent(receipt, "", "  ")
		txJSON, _ := json.MarshalIndent(blocks[0].Transactions()[receipt.TransactionIndex], "", "  ")
		assert.Equal(t, types.ReceiptStatusSuccessful, receipt.Status, string(headerJSON)+string(txJSON))
	}

	// withdraw reward
	blocks = buildBlocks(t, tester, 1,
		func(i int, bc *core.BlockChain, bg *BlockGen) {
			for _, staker := range stakers {
				data, err := ribose.BuildContractInput(bc.Engine().(*ribose.Ribose), "withdrawStakerProfits", staker.addr)
				assert.NoError(t, err)
				tx, err := types.SignTx(
					types.NewTransaction(bg.TxNonce(staker.addr),
						systemcontracts.RiboseContractAddr, common.Big0, params.TxGasContractCreation*100, common.Big1, data),
					types.HomesteadSigner{}, staker.key)
				if assert.NoError(t, err) {
					bg.AddTxWithChain(bc, tx)
				}
			}
		}, nil, nil, nil)
	receipts = tester.ethereum.BlockChain().GetReceiptsByHash(blocks[0].Hash())
	for _, receipt := range receipts {
		headerJSON, _ := json.MarshalIndent(receipt, "", "  ")
		txJSON, _ := json.MarshalIndent(blocks[0].Transactions()[receipt.TransactionIndex], "", "  ")
		assert.Equal(t, types.ReceiptStatusSuccessful, receipt.Status, string(headerJSON)+string(txJSON))
	}
	assert.Fail(t, "1")
}
