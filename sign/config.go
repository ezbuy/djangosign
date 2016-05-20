package sign

type Config struct {
	SECRET_KEY string
}

var _config *Config

func Setup(config *Config) {
	_config = config
}
