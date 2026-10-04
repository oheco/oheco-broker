package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/oheco/oheco-broker/internal/cli"
	"github.com/oheco/oheco-broker/internal/discovery"
	"github.com/oheco/oheco-broker/internal/server"
)

const version = "0.4.0"

func main() {
	log.SetFlags(log.Ldate | log.Ltime)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cli.Execute(ctx, os.Args[1:], version, run); err != nil {
		if errors.Is(err, discovery.ErrAlreadyRunning) {
			fmt.Println("oheco-broker is already running.")
			return
		}
		log.Print(err)
		os.Exit(1)
	}
}
func run(ctx context.Context) error {
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
	return server.Serve(ctx, l)
}
