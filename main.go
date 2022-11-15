package main

import (
	"fmt"
	"github.com/ghodss/yaml"
	"math/rand"
	"os"
	"runtime"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/spf13/pflag"
)

func main() {
	logger.SetFlags(logger.Lshortfile)

	configFlagSet := pflag.NewFlagSet("oauth2-proxy", pflag.ContinueOnError)

	// Because we parse early to determine alpha vs legacy config, we have to
	// ignore any unknown flags for now
	configFlagSet.ParseErrorsWhitelist.UnknownFlags = true

	config := configFlagSet.String("config", "", "path to alpha config file (use at your own risk - the structure in this config file may change between minor releases)")
	convertConfig := configFlagSet.String("convert-old-config", "", "path to the old config which should be converted to the new yaml format")
	showVersion := configFlagSet.Bool("version", false, "print version string")
	configFlagSet.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("oauth2-proxy %s (built with %s)\n", VERSION, runtime.Version())
		return
	}

	if *convertConfig != "" && *config != "" {
		logger.Fatal("cannot use config and convert-old-config together")
	}

	if *convertConfig != "" {
		//logger.Printf("%v is old config", convertConfig)
		//
		//oldOptions, err := loadLegacyOptions(*convertConfig, configFlagSet, os.Args[1:])
		//if err != nil {
		//	logger.Fatalf("ERROR: %v", err)
		//}
		//
		//if err := printConvertedConfig(oldOptions); err != nil {
		//	logger.Fatalf("ERROR: could not convert config: %v", err)
		//}
		//return
	}

	opts, err := loadConfiguration(*config)
	if err != nil {
		logger.Fatalf("ERROR: %v", err)
	}

	if err = validation.Validate(opts); err != nil {
		logger.Fatalf("%s", err)
	}

	validator := NewValidator(opts.Server.EmailDomains, opts.Server.AuthenticatedEmailsFile)
	oauthproxy, err := NewOAuthProxy(opts, validator)
	if err != nil {
		logger.Fatalf("ERROR: Failed to initialise OAuth2 Proxy: %v", err)
	}

	rand.Seed(time.Now().UnixNano())

	if err := oauthproxy.Start(); err != nil {
		logger.Fatalf("ERROR: Failed to start OAuth2 Proxy: %v", err)
	}
}

// loadConfiguration will load in the user's configuration.
func loadConfiguration(config string) (*options.AlphaOptions, error) {
	opts := options.NewAlphaOptions()
	if err := options.LoadYAML(config, opts); err != nil {
		return nil, fmt.Errorf("failed to load alpha options: %v", err)
	}

	return opts, nil
}

// loadLegacyOptions loads the old toml options using the legacy flagset
// and legacy options struct.
func loadLegacyOptions(config string, extraFlags *pflag.FlagSet, args []string) (*options.AlphaOptions, error) {
	optionsFlagSet := options.NewLegacyFlagSet()
	optionsFlagSet.AddFlagSet(extraFlags)
	if err := optionsFlagSet.Parse(args); err != nil {
		return nil, fmt.Errorf("failed to parse flags: %v", err)
	}

	legacyOpts := options.NewLegacyOptions()
	if err := options.Load(config, optionsFlagSet, legacyOpts); err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	opts, err := legacyOpts.ToOptions()
	if err != nil {
		return nil, fmt.Errorf("failed to convert config: %v", err)
	}

	return opts, nil
}

// printConvertedConfig extracts alpha options from the loaded configuration
// and renders these to stdout in YAML format.
func printConvertedConfig(opts *options.Options) error {
	alphaConfig := &options.AlphaOptions{}
	alphaConfig.ExtractFrom(opts)

	data, err := yaml.Marshal(alphaConfig)
	if err != nil {
		return fmt.Errorf("unable to marshal config: %v", err)
	}

	if _, err := os.Stdout.Write(data); err != nil {
		return fmt.Errorf("unable to write output: %v", err)
	}

	return nil
}
