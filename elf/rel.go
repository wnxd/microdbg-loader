package elf

import (
	"debug/elf"

	"github.com/wnxd/microdbg/debugger"
)

type relData struct {
	sym   *elf.Symbol
	addr  uint64
	size  uint64
	added uint64
	ctrl  debugger.ControlHandler
}
