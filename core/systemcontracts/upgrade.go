package systemcontracts

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

type Upgrade struct {
	CommitUrl string
	Code      string
}

type Upgrades = map[common.Address]Upgrade

type UpgradeConfig struct {
	Name     string
	Networks map[string]*Upgrades
}

func UpgradeBuildInSystemContract(config *params.ChainConfig, blockNumber *big.Int, statedb *state.StateDB) {
	if config == nil || blockNumber == nil || statedb == nil {
		return
	}

	logger := log.New("system-contract-upgrade", config.ChainID)

	if config.IsOnAbies(blockNumber) {
		applySystemContractUpgrade(AbiesUpgrade.Name, AbiesUpgrade.Networks[config.ChainID.String()], blockNumber, statedb, logger)
	}

	if config.IsOnBellis(blockNumber) {
		applySystemContractUpgrade(BellisUpgrade.Name, BellisUpgrade.Networks[config.ChainID.String()], blockNumber, statedb, logger)
	}
}

func applySystemContractUpgrade(name string, upgrade *Upgrades, blockNumber *big.Int, statedb *state.StateDB, logger log.Logger) {
	if upgrade == nil {
		logger.Info("Empty upgrade config", "height", blockNumber.String())
		return
	}

	logger.Info(fmt.Sprintf("Apply upgrade %s at height %d", name, blockNumber.Int64()))
	for addr, cfg := range *upgrade {
		logger.Info(fmt.Sprintf("Upgrade contract %s to commit %s", addr.String(), cfg.CommitUrl))
		newContractCode, err := hex.DecodeString(cfg.Code)
		if err != nil {
			panic(fmt.Errorf("failed to decode new contract code: %s", err.Error()))
		}
		statedb.SetCode(addr, newContractCode)
	}
}
