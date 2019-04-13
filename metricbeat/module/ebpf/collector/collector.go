package collector

import (
	"sync"
	"time"

	"github.com/andrewkroh/go-ebpf/socket"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/common/cfgwarn"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/metricbeat/mb"
)

// init registers the MetricSet with the central registry as soon as the program
// starts. The New function will be called later to instantiate an instance of
// the MetricSet for each host defined in the module's configuration. After the
// MetricSet has been created then Fetch will begin to be called periodically.
func init() {
	mb.Registry.MustAddMetricSet("ebpf", "collector", New)
}

// MetricSet holds any configuration or state information. It must implement
// the mb.MetricSet interface. And this is best achieved by embedding
// mb.BaseMetricSet because it implements all of the required mb.MetricSet
// interface methods except for Fetch.
type MetricSet struct {
	mb.BaseMetricSet
	monitor   *socket.Monitor
	logger    *logp.Logger
	lock      sync.Mutex
}

// New creates a new instance of the MetricSet. New is responsible for unpacking
// any MetricSet specific configuration options if there are any.
func New(base mb.BaseMetricSet) (mb.MetricSet, error) {
	cfgwarn.Beta("The ebpf collector metricset is beta.")

	config := struct{
		Interval time.Duration `config:"interval"`
	}{
		Interval: time.Minute,
	}
	if err := base.Module().UnpackConfig(&config); err != nil {
		return nil, err
	}

	m, err := socket.NewMonitor()
	if err != nil {
		return nil, err
	}

	return &MetricSet{
		BaseMetricSet: base,
		monitor: m,
		logger: logp.NewLogger("ebpf"),
	}, nil
}

// Fetch methods implements the data gathering and data conversion to the right
// format. It publishes the event which is then forwarded to the output. In case
// of an error set the Error field of mb.Event or simply call report.Error().
func (m *MetricSet) Run(reporter mb.PushReporterV2) {
	out, err := m.monitor.Start(reporter.Done())
	if err != nil {
		m.logger.Fatalf("unable to start socket monitor due to error: +%v", err)
	}

	for e := range out {
		if state, ok := e.(*socket.IPState); ok {
			reporter.Event(mb.Event{
				MetricSetFields: common.MapStr{
					"comm": state.Comm,
					"protocol": state.Protocol,
					"source_addr": state.SrcAddr,
					"source_port": state.SrcPort,
					"destination_addr": state.DstAddr,
					"destination_port": state.DstPort,
					"new_state": state.NewState,
					"old_state": state.OldState,
				},
			})
		}
	}
}
