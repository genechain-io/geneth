package systemcontracts

var (
	//upgrade config
	AbiesUpgrade = UpgradeConfig{
		Name:     "abies",
		Networks: map[string]*Upgrades{},
	}
	BellisUpgrade = UpgradeConfig{
		Name:     "bellis",
		Networks: map[string]*Upgrades{},
	}
)
