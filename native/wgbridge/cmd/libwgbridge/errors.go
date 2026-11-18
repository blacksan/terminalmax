// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) TerminalMax contributors

package main

import "errors"

const errBadHandleMsg = "wgbridge: unknown or closed handle"

var (
	errNullConf   = errors.New("wgbridge: NULL config")
	errNullTarget = errors.New("wgbridge: NULL target")
	errNullToken  = errors.New("wgbridge: NULL token buffer")
)
