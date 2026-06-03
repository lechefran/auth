package auth

// Service coordinates authentication workflows.
//
// The service is deliberately database-independent. Future steps will add
// storage interfaces to Config and implement workflows against those
// interfaces.
type Service struct {
	cfg Config
}

// New creates a Service with secure defaults for omitted optional settings.
func New(cfg Config) (*Service, error) {
	cfg = normalizeConfig(cfg)
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	return &Service{cfg: cfg}, nil
}

// Config returns the normalized service configuration.
func (s *Service) Config() Config {
	return s.cfg
}
