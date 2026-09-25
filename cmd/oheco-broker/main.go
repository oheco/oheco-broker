package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/oheco/oheco-broker/internal/discovery"
	"github.com/oheco/oheco-broker/internal/server"
)

const version = "0.1.0"

func main() {
	log.SetFlags(log.Ldate | log.Ltime)
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("oheco-broker " + version)
		return
	}
	if len(os.Args) > 1 {
		fmt.Fprintln(os.Stderr, "Usage: oheco-broker [--version]\nNo configuration. Trusted local development only; no authentication.")
		os.Exit(2)
	}
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	d, err := discovery.Open()
	if err != nil {
		return err
	}
	defer d.Close()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer l.Close()
	if err = d.Publish(l.Addr().String()); err != nil {
		return err
	}
	log.Printf("oheco-broker %s listening on %s; endpoint: %s", version, l.Addr(), d.Path())
	log.Print("WARNING: no authentication; any local client may execute commands as this user. Stop when not in use.")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.Serve(ctx, l)
}
