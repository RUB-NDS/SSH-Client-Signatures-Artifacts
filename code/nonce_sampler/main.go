package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/urfave/cli/v2"
)

func testNonceBias(cCtx *cli.Context) error {
	if _, err := os.Stat(cCtx.String("private-key-file")); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unable to find private key file: %s", cCtx.String("private-key-file"))
	}
	if err := RunBiasAnalysis(cCtx.Int("minimum-signatures"),
		cCtx.Int("workers"),
		cCtx.String("client-command"),
		cCtx.Int("timeout"),
		cCtx.String("private-key-file"),
		cCtx.Bool("agent"),
		cCtx.Bool("no-partial-success")); err != nil {
		return fmt.Errorf("error running bias analysis: %w", err)
	}
	return nil
}

func testNonceDeterminism(cCtx *cli.Context) error {
	if _, err := os.Stat(cCtx.String("private-key-file")); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unable to find private key file: %s", cCtx.String("private-key-file"))
	}
	if err := RunDeterminismAnalysis(cCtx.Int("timeout"),
		cCtx.String("private-key-file"),
		cCtx.Bool("agent"),
		cCtx.Bool("no-partial-success")); err != nil {
		return fmt.Errorf("error running determinism analysis: %w", err)
	}
	return nil
}

func main() {
	log.SetOutput(os.Stdout)
	app := &cli.App{
		Name:        "ssh-client-nonce-sampler",
		Usage:       "Test your SSH client's signature",
		Description: "A tool to measure DSA / ECDSA / Ed25519 nonce determinism in SSH client signature generation and test for potential bias",
		Commands: []*cli.Command{
			{
				Name:  "bias",
				Usage: "sample nonces and test for bias",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:    "workers",
						Aliases: []string{"j"},
						Usage:   "number of workers",
						Value:   runtime.NumCPU(),
					},
					&cli.IntFlag{
						Name:    "minimum-signatures",
						Aliases: []string{"n"},
						Usage:   "minimum number of signatures to collect",
						Value:   20000,
					},
					&cli.PathFlag{
						Name:     "private-key-file",
						Aliases:  []string{"k"},
						Usage:    "path to the private key file containing the client's private key",
						Required: true,
					},
					&cli.StringFlag{
						Name:    "client-command",
						Aliases: []string{"c"},
						Usage:   "client command to use for connecting to the server using ECDSA user authentication (placeholders: %host% and %port%)",
						Value:   "",
					},
					&cli.IntFlag{
						Name:    "timeout",
						Aliases: []string{"t"},
						Usage:   "listen timeout in milliseconds",
						Value:   1000,
					},
					&cli.BoolFlag{
						Name:    "agent",
						Aliases: []string{"a"},
						Usage:   "connect to the local SSH agent identified via SSH_AUTH_SOCK instead to generate signatures",
						Value:   false,
					},
					&cli.BoolFlag{
						Name:  "no-partial-success",
						Usage: "do not indicate a partial success during authentication. use with deterministic nonces to avoid false positives.",
						Value: false,
					},
				},
				Action: testNonceBias,
			},
			{
				Name:  "determinism",
				Usage: "sample two nonces from the same connection and test for determinism",
				Flags: []cli.Flag{
					&cli.PathFlag{
						Name:     "private-key-file",
						Aliases:  []string{"k"},
						Usage:    "path to the private key file containing the client's private key",
						Required: true,
					},
					&cli.IntFlag{
						Name:    "timeout",
						Aliases: []string{"t"},
						Usage:   "listen timeout in milliseconds",
						Value:   1000,
					},
					&cli.BoolFlag{
						Name:    "agent",
						Aliases: []string{"a"},
						Usage:   "connect to the local SSH agent identified via SSH_AUTH_SOCK instead to generate signatures",
						Value:   false,
					},
					&cli.BoolFlag{
						Name:  "no-partial-success",
						Usage: "do not indicate a partial success during authentication. this may hinder detection of random nonces and is generally not recommended.",
						Value: false,
					},
				},
				Action: testNonceDeterminism,
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
