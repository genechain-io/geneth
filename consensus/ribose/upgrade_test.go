package ribose_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/consensus/ribose"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/stretchr/testify/assert"
)

func TestUpgrade(t *testing.T) {
	genspec := ribose.NewTestGenesisBlock(t)
	abiesBlock := genspec.Config.AbiesBlock.Int64()
	assert.NotZero(t, abiesBlock)
	systemcontracts.AbiesUpgrade.Networks[genspec.Config.ChainID.String()] = &systemcontracts.Upgrades{
		systemcontracts.RiboseContractAddr: {
			Code: "0000",
		},
		systemcontracts.ARMContractAddr: {
			Code: "1111",
		},
	}
	tester := buildEthereumInstance(t)
	defer tester.close()
	db := tester.ethereum.ChainDb()
	{
		statedb, err := state.New(tester.ethereum.BlockChain().CurrentBlock().Root(), state.NewDatabase(db), nil)
		assert.NoError(t, err)
		code := statedb.GetCode(systemcontracts.RiboseContractAddr)
		assert.Equal(t, genspec.Alloc[systemcontracts.RiboseContractAddr].Code, code)
		expectCode, _ := hex.DecodeString((*systemcontracts.AbiesUpgrade.Networks[genspec.Config.ChainID.String()])[systemcontracts.RiboseContractAddr].Code)
		assert.NotZero(t, bytes.Compare(expectCode, code))
	}

	buildBlocks(t, tester, int(abiesBlock), nil, nil, nil, nil)
	{
		statedb, err := state.New(tester.ethereum.BlockChain().CurrentBlock().Root(), state.NewDatabase(db), nil)
		assert.NoError(t, err)
		code := statedb.GetCode(systemcontracts.RiboseContractAddr)
		assert.NotZero(t, bytes.Compare(genspec.Alloc[systemcontracts.RiboseContractAddr].Code, code))
		expectCode, _ := hex.DecodeString((*systemcontracts.AbiesUpgrade.Networks[genspec.Config.ChainID.String()])[systemcontracts.RiboseContractAddr].Code)
		assert.Equal(t, expectCode, code)
	}
}
