// Copyright 2025 The Kaia Authors
// This file is part of the Kaia library.
//
// The Kaia library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Kaia library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Kaia library. If not, see <http://www.gnu.org/licenses/>.

package impl

import (
	"github.com/erigontech/erigon-lib/kv"
	mdbx2 "github.com/erigontech/erigon-lib/kv/mdbx"
	log3 "github.com/erigontech/erigon-lib/log/v3"
	flatkv "github.com/kaiachain/kaia/kaiax/flatkv"
	"github.com/kaiachain/kaia/log"
)

var _ flatkv.FlatKVModule = &FlatKVModule{}

type InitOpts struct {
	DataDir string
}

type FlatKVModule struct {
	InitOpts
	chaindb kv.RwDB
}

var logger = log.NewModuleLogger(log.KaiaxFlatKV)

// LoggerAdapter adapts Kaia logger to Erigon logger interface
type LoggerAdapter struct {
	log.Logger
}

func (l LoggerAdapter) GetHandler() log3.Handler {
	return LogHandlerAdapter{l.Logger.GetHandler()}
}

func (l LoggerAdapter) Log(level log3.Lvl, msg string, ctx ...interface{}) {
	switch level {
	case log3.LvlDebug:
		l.Logger.Debug(msg, ctx...)
	case log3.LvlInfo:
		l.Logger.Info(msg, ctx...)
	case log3.LvlWarn:
		l.Logger.Warn(msg, ctx...)
	case log3.LvlError:
		l.Logger.Error(msg, ctx...)
	case log3.LvlCrit:
		l.Logger.Crit(msg, ctx...)
	}
}

func (l LoggerAdapter) New(ctx ...interface{}) log3.Logger {
	return LoggerAdapter{l.Logger.NewWith(ctx...)}
}

func (l LoggerAdapter) SetHandler(h log3.Handler) {
	l.Logger.SetHandler(ErigonHandlerAdapter{h})
}

type LogHandlerAdapter struct {
	log.Handler
}

func (l LogHandlerAdapter) Log(r *log3.Record) error {
	return l.Handler.Log(&log.Record{
		Time: r.Time,
		Lvl:  log.Lvl(r.Lvl),
		Msg:  r.Msg,
		Ctx:  r.Ctx,
		Call: r.Call,
		KeyNames: log.RecordKeyNames{
			Time: r.KeyNames.Time,
			Msg:  r.KeyNames.Msg,
			Lvl:  r.KeyNames.Lvl,
		},
	})
}

type ErigonHandlerAdapter struct {
	log3.Handler
}

func (h ErigonHandlerAdapter) Log(r *log.Record) error {
	return h.Handler.Log(&log3.Record{
		Time: r.Time,
		Lvl:  log3.Lvl(r.Lvl),
		Msg:  r.Msg,
		Ctx:  r.Ctx,
		Call: r.Call,
		KeyNames: log3.RecordKeyNames{
			Time: r.KeyNames.Time,
			Msg:  r.KeyNames.Msg,
			Lvl:  r.KeyNames.Lvl,
		},
	})
}

func NewFlatKVModule() *FlatKVModule {
	return &FlatKVModule{}
}

func createDb(dataDir string) (kv.RwDB, error) {
	return mdbx2.MustOpen(dataDir), nil
}

func (k *FlatKVModule) Init(opts *InitOpts) error {
	if opts == nil {
		return ErrInitUnexpectedNil
	}
	k.InitOpts = *opts
	if k.chaindb == nil {
		var err error
		k.chaindb, err = createDb(k.InitOpts.DataDir)
		if err != nil {
			return err
		}
	}
	return nil
}

func (k *FlatKVModule) Start() error {
	logger.Info("FlatKVModule Started")
	return nil
}

func (k *FlatKVModule) Stop() {
	logger.Info("FlatKVModule Stopped")
	if k.chaindb != nil {
		k.chaindb.Close()
	}
}
