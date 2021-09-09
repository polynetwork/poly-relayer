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
		Commands: []*cli.Command{
			&cli.Command{
				Name:   relayer.SET_HEADER_HEIGHT,
				Usage:  "Set side chain header sync height",
				Action: command(relayer.SET_HEADER_HEIGHT),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:     "height",
						Usage:    "target block height",
						Required: true,
					},
					&cli.Int64Flag{
						Name:     "chain",
						Usage:    "target side chain",
						Required: true,
					},
				},
			},
			&cli.Command{
				Name:   relayer.SET_TX_HEIGHT,
				Usage:  "Set side chain header sync height",
				Action: command(relayer.SET_TX_HEIGHT),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:     "height",
						Usage:    "target block height",
						Required: true,
					},
					&cli.Int64Flag{
						Name:     "chain",
						Usage:    "target side chain",
						Required: true,
					},
				},
			},
			&cli.Command{
				Name:   relayer.STATUS,
				Usage:  "Check side chain header/tx sync height",
				Action: command(relayer.STATUS),
			},
			&cli.Command{
				Name:   relayer.RELAY_POLY_TX,
				Usage:  "Submit poly tx to dest chain",
				Action: command(relayer.RELAY_POLY_TX),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:  "height",
						Usage: "target block height",
					},
					&cli.StringFlag{
						Name:  "tx",
						Usage: "target tx hash",
					},
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func start(c *cli.Context) error {
	config, err := config.New(c.String("config"))
	if err != nil {
		logs.Error("Failed to parse config file %v", err)
		os.Exit(2)
	}
	err = config.Init()
	if err != nil {
		logs.Error("Failed to initialize configuration %v", err)
		os.Exit(2)
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
		logs.Info("Poly relayer is exiting with received signal:(%s).", sig.String())
	} else {
		logs.Error("Failed to start relayer service %v", err)
		status = 2
	}
	cancel()
	wg.Wait()
	os.Exit(status)
	return nil
}

func command(method string) func(*cli.Context) error {
	return func(c *cli.Context) error {
		config, err := config.New(c.String("config"))
		if err != nil {
			logs.Error("Failed to parse config file %v", err)
			os.Exit(2)
		}
		err = config.Init()
		if err != nil {
			logs.Error("Failed to initialize configuration %v", err)
			os.Exit(2)
		}
		err = relayer.HandleCommand(method, c)
		if err != nil {
			logs.Error("Command %s error %v", method, err)
		}
		return err
	}
}
