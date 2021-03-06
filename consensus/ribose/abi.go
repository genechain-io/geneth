package ribose

// riboseABI contains all methods to interactive with validator contracts.
const riboseABI = `
[
  {
    "type": "event",
    "name": "LogCandidateUpdate",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address",
        "indexed": true
      },
      {
        "type": "uint256",
        "name": "time",
        "internalType": "uint256",
        "indexed": false
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "LogDistributeBlockReward",
    "inputs": [
      {
        "type": "address",
        "name": "coinbase",
        "internalType": "address",
        "indexed": true
      },
      {
        "type": "uint256",
        "name": "blockReward",
        "internalType": "uint256",
        "indexed": true
      },
      {
        "type": "uint256",
        "name": "time",
        "internalType": "uint256",
        "indexed": false
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "LogJailValidator",
    "inputs": [
      {
        "type": "address",
        "name": "val",
        "internalType": "address",
        "indexed": true
      },
      {
        "type": "uint256",
        "name": "time",
        "internalType": "uint256",
        "indexed": false
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "LogMinerWithdraw",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address",
        "indexed": true
      },
      {
        "type": "address",
        "name": "withdrawer",
        "internalType": "address",
        "indexed": true
      },
      {
        "type": "uint256",
        "name": "amount",
        "internalType": "uint256",
        "indexed": true
      },
      {
        "type": "uint256",
        "name": "time",
        "internalType": "uint256",
        "indexed": false
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "LogPunishValidator",
    "inputs": [
      {
        "type": "address",
        "name": "val",
        "internalType": "address",
        "indexed": true
      },
      {
        "type": "uint256",
        "name": "time",
        "internalType": "uint256",
        "indexed": false
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "LogRegister",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address",
        "indexed": true
      },
      {
        "type": "uint256",
        "name": "time",
        "internalType": "uint256",
        "indexed": false
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "LogShareRateUpdate",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address",
        "indexed": true
      },
      {
        "type": "uint256",
        "name": "time",
        "internalType": "uint256",
        "indexed": false
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "LogStake",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address",
        "indexed": true
      },
      {
        "type": "address",
        "name": "staker",
        "internalType": "address",
        "indexed": true
      },
      {
        "type": "uint256",
        "name": "rna",
        "internalType": "uint256",
        "indexed": false
      },
      {
        "type": "uint256",
        "name": "arm",
        "internalType": "uint256",
        "indexed": false
      },
      {
        "type": "uint256",
        "name": "time",
        "internalType": "uint256",
        "indexed": false
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "LogStakerWithdraw",
    "inputs": [
      {
        "type": "address",
        "name": "staker",
        "internalType": "address",
        "indexed": true
      },
      {
        "type": "uint256",
        "name": "amount",
        "internalType": "uint256",
        "indexed": true
      },
      {
        "type": "uint256",
        "name": "time",
        "internalType": "uint256",
        "indexed": false
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "LogTopCandidatesAdd",
    "inputs": [
      {
        "type": "address",
        "name": "val",
        "internalType": "address",
        "indexed": true
      },
      {
        "type": "uint256",
        "name": "time",
        "internalType": "uint256",
        "indexed": false
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "LogTopCandidatesRemove",
    "inputs": [
      {
        "type": "address",
        "name": "val",
        "internalType": "address",
        "indexed": true
      },
      {
        "type": "uint256",
        "name": "time",
        "internalType": "uint256",
        "indexed": false
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "LogUnstake",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address",
        "indexed": true
      },
      {
        "type": "address",
        "name": "staker",
        "internalType": "address",
        "indexed": true
      },
      {
        "type": "uint256",
        "name": "rna",
        "internalType": "uint256",
        "indexed": false
      },
      {
        "type": "uint256",
        "name": "arm",
        "internalType": "uint256",
        "indexed": false
      },
      {
        "type": "uint256",
        "name": "time",
        "internalType": "uint256",
        "indexed": false
      }
    ],
    "anonymous": false
  },
  {
    "type": "event",
    "name": "LogUpdateValidator",
    "inputs": [
      {
        "type": "address[]",
        "name": "newSet",
        "internalType": "address[]",
        "indexed": false
      }
    ],
    "anonymous": false
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "address",
        "name": "",
        "internalType": "address"
      }
    ],
    "name": "ARMAddr",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      }
    ],
    "name": "BlockProfitCycle",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      }
    ],
    "name": "BlockProfits",
    "inputs": [
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint32",
        "name": "",
        "internalType": "uint32"
      }
    ],
    "name": "FullProfitShare",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      }
    ],
    "name": "JailReleaseThreshold",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      }
    ],
    "name": "JailThreshold",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint16",
        "name": "",
        "internalType": "uint16"
      }
    ],
    "name": "MaxStakeCount",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint16",
        "name": "",
        "internalType": "uint16"
      }
    ],
    "name": "MaxTopCandidates",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint16",
        "name": "",
        "internalType": "uint16"
      }
    ],
    "name": "MaxValidators",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      }
    ],
    "name": "MinimalStakingARM",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      }
    ],
    "name": "MinimalStakingRNA",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint64",
        "name": "",
        "internalType": "uint64"
      }
    ],
    "name": "PendingSettlePeriod",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      }
    ],
    "name": "ProfitValueScale",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      }
    ],
    "name": "PunishDecreaseInterval",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      }
    ],
    "name": "PunishThreshold",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint32",
        "name": "",
        "internalType": "uint32"
      }
    ],
    "name": "StakerProfitShare",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint64",
        "name": "",
        "internalType": "uint64"
      }
    ],
    "name": "StakingLockPeriod",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "payable",
    "outputs": [],
    "name": "distributeBlockReward",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      }
    ],
    "name": "getBookedProfit",
    "inputs": [
      {
        "type": "address",
        "name": "staker",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "string",
        "name": "",
        "internalType": "string"
      },
      {
        "type": "string",
        "name": "",
        "internalType": "string"
      },
      {
        "type": "string",
        "name": "",
        "internalType": "string"
      }
    ],
    "name": "getCandidateDescription",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      },
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      },
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      },
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      },
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      }
    ],
    "name": "getCandidateStakeInfo",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "address",
        "name": "",
        "internalType": "address"
      },
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      },
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      },
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      },
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      },
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      },
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      },
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "getCandidateState",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "address[]",
        "name": "",
        "internalType": "address[]"
      }
    ],
    "name": "getStakedCandidates",
    "inputs": [
      {
        "type": "address",
        "name": "staker",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      }
    ],
    "name": "getStakerUnsettledProfit",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      },
      {
        "type": "address",
        "name": "staker",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      },
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      },
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      },
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      },
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      }
    ],
    "name": "getStakingInfo",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      },
      {
        "type": "address",
        "name": "staker",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "address[]",
        "name": "",
        "internalType": "address[]"
      },
      {
        "type": "uint256[]",
        "name": "",
        "internalType": "uint256[]"
      }
    ],
    "name": "getTopCandidates",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "address[]",
        "name": "",
        "internalType": "address[]"
      }
    ],
    "name": "getValidators",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "nonpayable",
    "outputs": [],
    "name": "initialize",
    "inputs": [
      {
        "type": "address[]",
        "name": "vals",
        "internalType": "address[]"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "initialized",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "isJailed",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "isTopCandidate",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "isValidator",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "nonpayable",
    "outputs": [],
    "name": "punish",
    "inputs": [
      {
        "type": "address",
        "name": "val",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "nonpayable",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "register",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "nonpayable",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "setProfitTaker",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      },
      {
        "type": "address",
        "name": "taker",
        "internalType": "address payable"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "nonpayable",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "settleAllStakerProfit",
    "inputs": []
  },
  {
    "type": "function",
    "stateMutability": "nonpayable",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "settleStakerProfit",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "payable",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "stake",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      },
      {
        "type": "uint256",
        "name": "armAmount",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "nonpayable",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "stakeARM",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      },
      {
        "type": "uint256",
        "name": "armAmount",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "payable",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "stakeRNA",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "address",
        "name": "",
        "internalType": "address"
      }
    ],
    "name": "topCandidates",
    "inputs": [
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "nonpayable",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "unstake",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      },
      {
        "type": "uint256",
        "name": "rnaAmount",
        "internalType": "uint256"
      },
      {
        "type": "uint256",
        "name": "armAmount",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "nonpayable",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "unstakeARM",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      },
      {
        "type": "uint256",
        "name": "armAmount",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "nonpayable",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "unstakeRNA",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      },
      {
        "type": "uint256",
        "name": "rnaAmount",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "nonpayable",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "updateCandidateDescription",
    "inputs": [
      {
        "type": "string",
        "name": "website",
        "internalType": "string"
      },
      {
        "type": "string",
        "name": "email",
        "internalType": "string"
      },
      {
        "type": "string",
        "name": "details",
        "internalType": "string"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "nonpayable",
    "outputs": [],
    "name": "updateValidatorSet",
    "inputs": [
      {
        "type": "address[]",
        "name": "newSet",
        "internalType": "address[]"
      },
      {
        "type": "uint256",
        "name": "epoch",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "view",
    "outputs": [
      {
        "type": "address",
        "name": "",
        "internalType": "address"
      }
    ],
    "name": "validators",
    "inputs": [
      {
        "type": "uint256",
        "name": "",
        "internalType": "uint256"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "nonpayable",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "withdrawMinerProfits",
    "inputs": [
      {
        "type": "address",
        "name": "candidate",
        "internalType": "address"
      }
    ]
  },
  {
    "type": "function",
    "stateMutability": "nonpayable",
    "outputs": [
      {
        "type": "bool",
        "name": "",
        "internalType": "bool"
      }
    ],
    "name": "withdrawStakerProfits",
    "inputs": [
      {
        "type": "address",
        "name": "staker",
        "internalType": "address payable"
      }
    ]
  }
]
`
