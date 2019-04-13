package nginx

import "github.com/elastic/beats/metricbeat/mb"

func init() {
	// Register the ModuleFactory function for the "mysql" module.
	if err := mb.Registry.AddModule("nginx", NewModule); err != nil {
		panic(err)
	}
}

func NewModule(base mb.BaseModule) (mb.Module, error) {
	// Validate that at least one host has been specified.
	config := struct {
		Hosts []string `config:"hosts"    validate:"nonzero,required"`
	}{}
	if err := base.UnpackConfig(&config); err != nil {
		return nil, err
	}

	return &base, nil
}
