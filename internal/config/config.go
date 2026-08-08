package config

  import (
        "fmt"
        "os"

        "gopkg.in/yaml.v3"
  )

  type Transport string

  const (
		TransportStdio Transport = "stdio"
		TransportHTTP Transport ="http"  
)

type ServerConfig struct {
	Name string `yaml:"name"`
	Transport Transport `yaml:"transport"`
	Command string `yaml:"command,omitempty"`
	Args []string `yaml:"args,omitempty"`
	URL string `yaml:"url,omitempty"`
}

type Config struct {
	Servers []ServerConfig `yaml:"servers"`
}

func Load(path string) (*Config, error) {
	data, err:= os.ReadFile(path)
	if err !=nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err:= yaml.Unmarshal(data, &cfg); err!=nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err:= cfg.validate(); err!=nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	for _, s:= range c.Servers {
		if s.Name =="" {
			return fmt.Errorf("server missing name")
		}

		switch s.Transport {

		case TransportStdio:
			if s.Command == "" {
				return fmt.Errorf("server %q: stdio transport requires command", s.Name)
			}
		case TransportHTTP:
			if s.URL == "" {
				return fmt.Errorf("server %q: http transport requires url", s.Name)
			}
		default:
			return fmt.Errorf("server %q: unknown transport method %q", s.Name, s.Transport)
		}
	}
	return nil
}