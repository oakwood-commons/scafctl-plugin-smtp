// Package main is the entry point for the scafctl-plugin-smtp plugin.
package main

import (
	"github.com/oakwood-commons/scafctl-plugin-smtp/internal/smtp"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
)

func main() {
	sdkplugin.Serve(&smtp.Plugin{})
}
