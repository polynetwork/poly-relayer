package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/urfave/cli/v2"

	"github.com/polynetwork/bridge-common/log"
	"github.com/polynetwork/bridge-common/util"
	"github.com/polynetwork/bridge-common/wallet"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/relayer"
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
			&cli.BoolFlag{
				Name: "encrypted",
			},
			&cli.BoolFlag{
				Name: "plain",
			},
			&cli.StringFlag{
				Name:  "log",
				Value: "",
				Usage: "log file path, use stdout when unspecified",
			},
			&cli.UintFlag{
				Name:  "logmaxsize",
				Usage: "max log file size in MB, wont split log file when unspecified",
			},
			&cli.UintFlag{
				Name:  "logmaxfiles",
				Usage: "max log files to keep, wont remove old logs when unspecified",
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
			&cli.StringFlag{
				Name:  "wallets",
				Value: "",
				Usage: "poly wallets path",
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
				Name:   relayer.SET_EPOCH_HEIGHT,
				Usage:  "Set poly epoch sync height",
				Action: command(relayer.SET_EPOCH_HEIGHT),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:     "height",
						Usage:    "target block height",
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
				Name:   relayer.VALIDATE,
				Usage:  "Validate txs",
				Action: command(relayer.VALIDATE),
			},
			&cli.Command{
				Name:   relayer.VALIDATE_BLOCK,
				Usage:  "Validate txs in block",
				Action: command(relayer.VALIDATE_BLOCK),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:  "height",
						Usage: "target poly height",
					},
					&cli.Int64Flag{
						Name:  "chain",
						Usage: "chain id",
					},
				},
			},
			&cli.Command{
				Name:   relayer.SET_VALIDATOR_HEIGHT,
				Usage:  "Set chain tx validator height",
				Action: command(relayer.SET_VALIDATOR_HEIGHT),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:     "height",
						Usage:    "target block height",
						Required: true,
					},
					&cli.Int64Flag{
						Name:     "chain",
						Usage:    "target chain",
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
				Name:   relayer.TEST,
				Usage:  "Test",
				Action: command(relayer.TEST),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:  "id",
						Usage: "epoch id",
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
					&cli.StringFlag{
						Name:  "url",
						Usage: "submit to local http service",
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
					&cli.BoolFlag{
						Name:  "submit",
						Usage: "enable http submit tx",
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
				Name:   relayer.SCAN_POLY_TX,
				Usage:  "Scan poly txs in range",
				Action: command(relayer.SCAN_POLY_TX),
				Flags: []cli.Flag{
					&cli.Uint64Flag{
						Name:     "chain",
						Usage:    "src_chain",
						Required: true,
					},
					&cli.Uint64Flag{
						Name:     "height",
						Usage:    "scan start height",
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
				},
			},
			&cli.Command{
				Name:   relayer.UPDATE_ACCOUNT,
				Usage:  "Update keystore accounts with new passphrase",
				Action: command(relayer.UPDATE_ACCOUNT),
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "path",
						Usage:    "wallet path",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "account",
						Usage: "wallet account to update",
					},
				},
			},
			&cli.Command{
				Name:   relayer.ENCRYPT_FILE,
				Usage:  "Encrypt a single file with passphrase",
				Action: command(relayer.ENCRYPT_FILE),
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "file",
						Usage:    "file path",
						Required: true,
					},
				},
			},
			&cli.Command{
				Name:   relayer.DECRYPT_FILE,
				Usage:  "Decrypt a single file with passphrase",
				Action: command(relayer.DECRYPT_FILE),
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "file",
						Usage:    "file path",
						Required: true,
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
					&cli.BoolFlag{
						Name:  "update",
						Usage: "updating side chain or not",
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
					&cli.Int64Flag{
						Name:  "blocks",
						Usage: "blocks to wait",
					},
					&cli.StringFlag{
						Name:  "ccm",
						Usage: "ccm data address",
					},
					&cli.StringFlag{
						Name:  "name",
						Usage: "chain name",
					},
					&cli.BoolFlag{
						Name:  "vote",
						Usage: "whether using votes",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "update",
						Usage: "updating side chain or not",
					},
				},
			},
			&cli.Command{
				Name:   relayer.GET_SIDE_CHAIN,
				Usage:  "Get side chain instance",
				Action: command(relayer.GET_SIDE_CHAIN),
				Flags: []cli.Flag{
					&cli.Int64Flag{
						Name:  "chain",
						Usage: "chain id",
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
					&cli.BoolFlag{
						Name: "sync:",
						Usage: "Sync zion epochs to chain",
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
		readConf := true
		switch method {
		case relayer.RELAY_TX:
			if c.String("url") != "" {
				readConf = false
			}
		case relayer.ENCRYPT_FILE, relayer.DECRYPT_FILE, relayer.CREATE_ACCOUNT, relayer.UPDATE_ACCOUNT:
			readConf = false
		}
		if readConf {
			conf, err := config.New(c.String("config"))
			if err != nil {
				log.Error("Failed to parse config file", "err", err)
				os.Exit(2)
			}
			err = conf.Init()
			if err != nil {
				log.Error("Failed to initialize configuration", "err", err)
				os.Exit(2)
			}
			// poly wallets
			walletsPath := c.String("wallets")
			if walletsPath != "" {
				if conf.Poly.Signer == nil {
					conf.Poly.Signer = new(wallet.Config)
				}
				conf.Poly.Signer.Path = config.GetConfigPath(config.WALLET_PATH, walletsPath)
				password, err := util.ReadPassword("passphrase")
				if err != nil {
					return err
				}
				conf.Poly.Signer.Password = string(password)
			}
		}
		err := relayer.HandleCommand(method, c)
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
	config.ENCRYPTED = ctx.Bool("encrypted")
	config.PLAIN = ctx.Bool("plain")

	log.Init(&log.LogConfig{
		Path:     ctx.String("log"),
		MaxFiles: ctx.Uint("logmaxfiles"),
		MaxSize:  ctx.Uint("logmaxsize")})

	return
}
