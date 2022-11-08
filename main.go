package main

import (
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"time"

	"github.com/ghodss/yaml"
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

	oldConfig := configFlagSet.String("old-config", "", "path to config file")
	config := configFlagSet.String("config", "", "path to alpha config file (use at your own risk - the structure in this config file may change between minor releases)")
	convertConfig := configFlagSet.Bool("convert-old-config", false, "if true, the proxy will load configuration as normal and convert the old configuration to the new config structure, and print it to stdout")
	showVersion := configFlagSet.Bool("version", false, "print version string")
	configFlagSet.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("oauth2-proxy %s (built with %s)\n", VERSION, runtime.Version())
		return
	}

	if *convertConfig && *config != "" {
		logger.Fatal("cannot use alpha-config and convert-config-to-alpha together")
	}

	opts, err := loadConfiguration(*config, configFlagSet, os.Args[1:])
	if err != nil {
		logger.Fatalf("ERROR: %v", err)
	}

	if *convertConfig {
		logger.Printf("%v is old config", oldConfig)
		//if err := printConvertedConfig(opts); err != nil {
		//	logger.Fatalf("ERROR: could not convert config: %v", err)
		//}
		return
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
func loadConfiguration(config string, extraFlags *pflag.FlagSet, args []string) (*options.AlphaOptions, error) {
	//opts, err := loadOptions(config, extraFlags, args)
	//if err != nil {
	//	return nil, fmt.Errorf("failed to load core options: %v", err)
	//}

	opts := options.NewAlphaOptions()
	opts.Server = options.ServerDefaults()
	if err := options.LoadYAML(config, opts); err != nil {
		return nil, fmt.Errorf("failed to load alpha options: %v", err)
	}

	return opts, nil
}

// loadOptions loads the configuration using the old style format into the
// core options.AlphaOptions struct.
// This means that none of the options that have been converted to alpha config
// will be loaded using this method.
func loadOptions(config string, extraFlags *pflag.FlagSet, args []string) (*options.Options, error) {

	optionsFlagSet := options.NewFlagSet()
	optionsFlagSet.AddFlagSet(extraFlags)
	if err := optionsFlagSet.Parse(args); err != nil {
		return nil, fmt.Errorf("failed to parse flags: %v", err)
	}

	opts := options.NewOptions()
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
