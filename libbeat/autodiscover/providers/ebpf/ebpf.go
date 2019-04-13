// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
package ebpf

import (
	"fmt"

	"github.com/andrewkroh/go-ebpf/socket"
	"github.com/gofrs/uuid"

	"github.com/elastic/beats/libbeat/autodiscover"
	"github.com/elastic/beats/libbeat/autodiscover/template"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/common/bus"
	"github.com/elastic/beats/libbeat/logp"
)

func init() {
	autodiscover.Registry.AddProvider("ebpf", EbpfProvider)
}

type Provider struct {
	bus     bus.Bus
	channel chan []byte
	config  *Config

	monitor   *socket.Monitor
	uuid      uuid.UUID
	templates template.Mapper
	builders  autodiscover.Builders
	appenders autodiscover.Appenders
	done      chan struct{}
	logger    *logp.Logger
}

func EbpfProvider(bus bus.Bus, uuid uuid.UUID, c *common.Config) (autodiscover.Provider, error) {
	config := defaultConfig()
	err := c.Unpack(&config)
	if err != nil {
		return nil, err
	}

	mapper, err := template.NewConfigMapper(config.Templates)
	if err != nil {
		return nil, err
	}

	builders, err := autodiscover.NewBuilders(config.Builders, config.HintsEnabled)
	if err != nil {
		return nil, err
	}

	appenders, err := autodiscover.NewAppenders(config.Appenders)
	if err != nil {
		return nil, err
	}

	m, err := socket.NewMonitor()
	if err != nil {
		return nil, err
	}

	done := make(chan struct{}, 1)
	return &Provider{
		appenders: appenders,
		builders:  builders,
		templates: mapper,
		uuid:      uuid,
		bus:       bus,
		monitor:   m,
		done:      done,
		logger:    logp.NewLogger("ebpf"),
	}, nil
}

func (p *Provider) String() string {
	return "ebpf"
}

func (p *Provider) Start() {
	out, err := p.monitor.Start(p.done)
	if err != nil {
		p.logger.Fatalf("unable to start socket monitor due to error: +%v", err)
	}

	go p.watch(out)
}

func (p *Provider) Stop() {
	close(p.done)
}

func (p *Provider) watch(out <-chan interface{}) {
	for e := range out {
		if state, ok := e.(*socket.IPState); ok {
			if state.OldState == socket.TCP_CLOSE && state.NewState == socket.TCP_LISTEN {
				p.publishEvent(bus.Event{
					"provider":   p.uuid,
					"id": fmt.Sprintf("%d:%d", state.PID, state.SrcPort),
					"host": state.SrcAddr,
					"port": state.SrcPort,
					"comm": state.Comm,
					"pid": state.PID,
					"start": true,

				})
			} else if state.OldState == socket.TCP_LISTEN && state.NewState == socket.TCP_CLOSE {
				p.publishEvent(bus.Event{
					"provider":   p.uuid,
					"id": fmt.Sprintf("%d:%d", state.PID, state.SrcPort),
					"host": state.SrcAddr,
					"port": state.SrcPort,
					"comm": state.Comm,
					"pid": state.PID,
					"stop": true,

				})
			}
		}
	}
}

func (p *Provider) publishEvent(e bus.Event) {
	if config := p.builders.GetConfig(e); config != nil {
		e["config"] = config
	}

	p.bus.Publish(e)

}
