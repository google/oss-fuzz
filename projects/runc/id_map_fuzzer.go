package system

import (
	"strings"
	"github.com/opencontainers/runc/libcontainer/user"
)


func Fuzz(data []byte) int {
	uidmap, _ := user.ParseIDMap(strings.NewReader(string(data)))
	_ = UIDMapInUserNS(uidmap)
	return 1
}
