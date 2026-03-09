package main

import (
	"cmit/paas/warp/internal/cmd"

	"google.golang.org/grpc"
)

func main() {
	grpc.EnableTracing = false
	cmd.NewRootCmd().Execute()
}
