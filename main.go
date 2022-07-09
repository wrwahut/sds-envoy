package main

import "context"

func main() {
	ctx := context.Background()
	server := NewServer(ctx)
	server.start(ctx)
}
