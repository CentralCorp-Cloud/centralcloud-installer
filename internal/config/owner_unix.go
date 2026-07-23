//go:build unix

package config

import (
	"os"
	"syscall"
)

func ownerUID(info os.FileInfo) uint32 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Uid
	}
	return ^uint32(0)
}
