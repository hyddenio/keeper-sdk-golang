package enterprise

import (
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/auth"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/json_commands"
)

func GetEnterpriseIds(keeperAuth auth.IKeeperAuth, numberRequested int) (eids []int64, err error) {
	if numberRequested <= 0 || numberRequested > 1000 {
		err = api.NewKeeperError("number of requested IDs should be positive and cannot exceed 1000")
		return
	}
	var cmd = &json_commands.EnterpriseAllocateIdsCommand{
		NumberRequested: numberRequested,
	}
	var rs = new(json_commands.EnterpriseAllocateIdsResponse)
	if err = keeperAuth.ExecuteAuthCommand(cmd, rs, true); err == nil {
		for i := 0; i < rs.NumberAllocated; i++ {
			eids = append(eids, rs.BaseId+int64(i))
		}
	}
	return
}
