package main

import (
	"context"
	"taiyi/core"
)

func main()  {
	ctx, cancel := context.WithCancel(context.Background())
	core.Start(ctx)
	cancel()
}
