package core

import (
	"errors"
	"sync"

	"github.com/bolaxy/common"

	"github.com/bolaxy/eth/types"
)

var (
	ErrNonceTooLow = errors.New("nonce too low")
)
type txLookup struct {
	all  map[common.Hash]*types.Transaction
	lock sync.RWMutex
}
