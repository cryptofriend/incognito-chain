package server

type PingArgs struct {
	RawAddress string
	PublicKey  string
	SignData   string
}

func (ping *PingArgs) Init(RawAddress string, PublicKey string, SignData string) {
	ping.PublicKey = PublicKey
	ping.SignData = SignData
	ping.RawAddress = RawAddress
}
