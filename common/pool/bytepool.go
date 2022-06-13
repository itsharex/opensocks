package pool

import (
	"log"

	"github.com/net-byte/opensocks/common/enum"
	"github.com/oxtoacart/bpool"
)

// BytePool is a byte pool
var BytePool *bpool.BytePool

func init() {
	BytePool = bpool.NewBytePool(128, enum.BufferSize)
	log.Println("BytePool initialized")
}
