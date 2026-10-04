// Package migrations embeds the SQL schema used by the standalone migration command.
package migrations

import "embed"

//go:embed *.sql
var Files embed.FS
