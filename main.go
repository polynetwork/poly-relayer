package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/polynetwork/bridge-common/log"
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
			&cli.StringFlag{
				Name:  "roles",
				Value: "roles.json",
				Usage: "roles configuration file",
			},
			&cli.StringFlag{
				Name:  "wallet",
				Value: "",
				Usage: "wallet path",
			},
		},
		Before: Init,
		Commands: []*cli.Command{
			&cli.Command{
				Name:   relayer.CHECK_WALLET,
				Usage:  "Check wallet status",
				Action: command(relayer.CHECK_WALLET),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:     "chain",
						Usage:    "target side chain",
						Required: true,
					},
				},
			},
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
				Usage:  "Set side chain tx sync height",
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
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:     "chain",
						Usage:    "target side chain",
						Required: true,
					},
				},
			},
			&cli.Command{
				Name:   relayer.RELAY_TX,
				Usage:  "Submit cross chain tx",
				Action: command(relayer.RELAY_TX),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:  "height",
						Usage: "target block height",
					},
					&cli.Int64Flag{
						Name:  "chain",
						Usage: "target tx chain",
					},
					&cli.StringFlag{
						Name:  "hash",
						Usage: "target tx hash",
					},
					&cli.Int64Flag{
						Name:  "limit",
						Usage: "tx gas limit",
					},
					&cli.StringFlag{
						Name:  "price",
						Usage: "tx gas price",
					},
					&cli.StringFlag{
						Name:  "pricex",
						Usage: "tx gas priceX",
					},
					&cli.BoolFlag{
						Name:  "free",
						Usage: "skip check fee",
					},
					&cli.StringFlag{
						Name:  "sender",
						Usage: "tx sender address",
					},
					&cli.BoolFlag{
						Name:  "auto",
						Usage: "submit will try to find the proper bin",
						Value: false,
					},
				},
			},
			&cli.Command{
				Name:   relayer.PATCH,
				Usage:  "Patch cross chain tx, will do auto patching if auto is set",
				Action: command(relayer.PATCH),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:  "height",
						Usage: "target block height",
					},
					&cli.Int64Flag{
						Name:  "chain",
						Usage: "tx chain id",
					},
					&cli.Int64Flag{
						Name:  "limit",
						Usage: "tx gas limit",
					},
					&cli.StringFlag{
						Name:  "price",
						Usage: "tx gas price",
					},
					&cli.StringFlag{
						Name:  "pricex",
						Usage: "tx gas priceX",
					},
					&cli.StringFlag{
						Name:  "hash",
						Usage: "target tx hash",
					},
					&cli.BoolFlag{
						Name:  "free",
						Usage: "skip check fee",
					},
					&cli.BoolFlag{
						Name:  "auto",
						Usage: "auto patch",
						Value: false,
					},
				},
			},
			&cli.Command{
				Name:   relayer.HTTP,
				Usage:  "Run http server",
				Action: command(relayer.HTTP),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:  "port",
						Usage: "http endpoint port",
					},
					&cli.StringFlag{
						Name:  "host",
						Usage: "http endpoint host",
					},
				},
			},
			&cli.Command{
				Name:   relayer.SKIP,
				Usage:  "Mark tx hash to skip before sumbit to target chain",
				Action: command(relayer.SKIP),
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "hash",
						Usage:    "tx hash",
						Required: true,
					},
				},
			},
			&cli.Command{
				Name:   relayer.CHECK_SKIP,
				Usage:  "Check tx skip status",
				Action: command(relayer.CHECK_SKIP),
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "hash",
						Usage:    "tx hash",
						Required: true,
					},
				},
			},
			&cli.Command{
				Name:   relayer.CREATE_ACCOUNT,
				Usage:  "Create a new eth keystore account",
				Action: command(relayer.CREATE_ACCOUNT),
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "path",
						Usage:    "wallet path",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "pass",
						Usage: "wallet password",
					},
				},
			},
			&cli.Command{
				Name:   relayer.APPROVE_SIDECHAIN,
				Usage:  "Approve side chain",
				Action: command(relayer.APPROVE_SIDECHAIN),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:  "chain",
						Usage: "chain id",
					},
				},
			},
			&cli.Command{
				Name:   relayer.SYNC_GENESIS,
				Usage:  "Sync side chain genesis to poly",
				Action: command(relayer.SYNC_GENESIS),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:  "height",
						Usage: "target block height",
					},
					&cli.Int64Flag{
						Name:  "chain",
						Usage: "chain id",
					},
				},
			},
			&cli.Command{
				Name:   relayer.SYNC_HEADER,
				Usage:  "Sync side chain header to poly",
				Action: command(relayer.SYNC_HEADER),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:  "height",
						Usage: "target block height",
					},
					&cli.Int64Flag{
						Name:  "chain",
						Usage: "chain id",
					},
				},
			},
			&cli.Command{
				Name:   relayer.ADD_SIDECHAIN,
				Usage:  "Register side chain to poly",
				Action: command(relayer.ADD_SIDECHAIN),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:  "router",
						Usage: "target chain router",
					},
					&cli.Int64Flag{
						Name:  "chain",
						Usage: "chain id",
					},
					&cli.StringFlag{
						Name:  "ccm",
						Usage: "ccm data address",
					},
				},
			},
			&cli.Command{
				Name:   relayer.INIT_GENESIS,
				Usage:  "Init genesis for contract",
				Action: command(relayer.INIT_GENESIS),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:  "height",
						Usage: "target poly height",
					},
					&cli.Int64Flag{
						Name:  "chain",
						Usage: "chain id",
					},
					&cli.StringFlag{
						Name:  "ccm",
						Usage: "ccm address",
					},
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal("Start error", "err", err)
	}
}

func start(c *cli.Context) error {
	config, err := config.New(c.String("config"))
	if err != nil {
		log.Error("Failed to parse config file", "err", err)
		os.Exit(2)
	}
	err = config.ReadRoles(c.String("roles"))
	if err != nil {
		log.Error("Failed to read roles configuration", "err", err)
		os.Exit(2)
	}
	err = config.Init()
	if err != nil {
		log.Error("Failed to initialize configuration", "err", err)
		os.Exit(2)
	}

	wg := &sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())
	status := 0
	err = relayer.Start(ctx, wg, config)
	if err == nil {
		sc := make(chan os.Signal, 10)
		signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGSTOP, syscall.SIGQUIT)
		sig := <-sc
		log.Info("Poly relayer is exiting with received signal", "signal", sig.String())
	} else {
		log.Error("Failed to start relayer service", "err", err)
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
			log.Error("Failed to parse config file", "err", err)
			os.Exit(2)
		}
		err = config.Init()
		if err != nil {
			log.Error("Failed to initialize configuration", "err", err)
			os.Exit(2)
		}
		err = relayer.HandleCommand(method, c)
		if err != nil {
			log.Error("Failure", "command", method, "err", err)
		} else {
			log.Info("Command was executed successful!")
		}
		return nil
	}
}

func Init(ctx *cli.Context) (err error) {
	// Set wallet path
	config.WALLET_PATH = ctx.String("wallet")
	config.CONFIG_PATH = ctx.String("config")

	log.Init()
	return
}
