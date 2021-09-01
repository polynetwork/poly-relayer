package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/beego/beego/v2/core/logs"
	"github.com/beego/beego/v2/server/web"
	"github.com/polynetwork/bridge-common/metrics"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/relayer"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:   "relayer",
		Usage:  "Poly cross chain transaction relayer",
		Action: start,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "config",
				Value: "config.json",
				Usage: "configuration file",
			},
		},
		Commands: []*cli.Command{},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func start(c *cli.Context) error {
	config, err := config.New(c.String("config"))
	if err != nil {
		panic(err)
	}
	err = config.Init()
	if err != nil {
		panic(err)
	}

	metrics.Init("relayer")
	go func() {
		// Insert web config
		web.BConfig.Listen.HTTPAddr = config.MetricHost
		web.BConfig.Listen.HTTPPort = config.MetricPort
		web.BConfig.RunMode = "prod"
		web.BConfig.AppName = "relayer"
		web.Run()
	}()

	wg := &sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())
	status := 0
	err = relayer.Start(ctx, wg, config)
	if err == nil {
		sc := make(chan os.Signal, 1)
		signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		sig := <-sc
		logs.Info("Validator is exiting with received signal:(%s).", sig.String())
	} else {
		logs.Error("Failed to start relayer service %v", err)
		status = 2
	}
	cancel()
	wg.Wait()
	os.Exit(status)
	return nil
}
