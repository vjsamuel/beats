package ebpf

import (
	"fmt"
	"strings"

	"github.com/elastic/beats/libbeat/autodiscover"
	"github.com/elastic/beats/libbeat/autodiscover/template"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/common/bus"
	"github.com/elastic/beats/libbeat/common/cfgwarn"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/metricbeat/mb"
)

func init() {
	autodiscover.Registry.AddBuilder("ebpf", NewEbpfBuilder)
}

type ebpf struct {
	Registry *mb.Register
	logger   *logp.Logger
}

func NewEbpfBuilder(_ *common.Config) (autodiscover.Builder, error) {
	cfgwarn.Beta("The ebpf builder is beta")

	return &ebpf{
		Registry: mb.Registry,
		logger: logp.NewLogger("ebpf"),
	}, nil
}


func (e *ebpf) CreateConfig(event bus.Event) []*common.Config {
	var cfgs []*common.Config

	modRaw, _ := event["comm"]
	if modRaw == nil {
		return cfgs
	}

	mod, _ := modRaw.(string)
	if mod == "docker-proxy" {
		return cfgs
	}

	msets, err := e.Registry.DefaultMetricSets(mod)
	if err != nil || len(msets) == 0 {
		msets = e.Registry.MetricSets(mod)
	}

	hostRaw, _ := event["host"]
	if hostRaw == nil {
		return cfgs
	}

	portRaw := event["port"]
	if portRaw == nil {
		return cfgs
	}

	fmt.Println(e.Registry.MetricSets("elasticsearch"))

	for _, m := range e.Registry.Modules() {
		fmt.Println(m, mod)
		if strings.Contains(mod, m) == true {
			mod = m
			break
		}
	}

	moduleConfig := common.MapStr{
		"module":     mod,
		"metricsets": msets,
		"hosts":      []string{fmt.Sprintf("%s:%d", hostRaw, portRaw)},
		"enabled":    true,
		"fields": common.MapStr{
			"process": common.MapStr{
				"pid": event["pid"],
			},
		},
		"fields_under_root": true,

	}

	e.logger.Debugf("generated config: %+v", moduleConfig)

	cfg, err := common.NewConfigFrom(moduleConfig)
	if err != nil {
		e.logger.Debug( "config merge failed with error: %v", err)
	}
	e.logger.Debug("generated config: +%v", *cfg)
	cfgs = append(cfgs, cfg)

	return template.ApplyConfigTemplate(event, cfgs)
}
