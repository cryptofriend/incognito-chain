package jsonresult

import (
	"github.com/incognitochain/incognito-chain/blockchain"
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/transaction"
)

type CustomToken struct {
	ID        string   `json:"ID"`
	Name      string   `json:"Name"`
	Symbol    string   `json:"Symbol"`
	Image     string   `json:"Image"`
	Amount    uint64   `json:"Amount"`
	IsPrivacy bool     `json:"IsPrivacy"`
	ListTxs   []string `json:"ListTxs"`
}

func (customToken *CustomToken) Init(obj transaction.TxCustomToken) {
	customToken.ID = obj.TxTokenData.PropertyID.String()
	customToken.Symbol = obj.TxTokenData.PropertySymbol
	customToken.Name = obj.TxTokenData.PropertyName
	customToken.Amount = obj.TxTokenData.Amount
	customToken.Image = common.Render(obj.TxTokenData.PropertyID[:])
}

func (customToken *CustomToken) InitPrivacy(obj transaction.TxCustomTokenPrivacy) {
	customToken.ID = obj.TxTokenPrivacyData.PropertyID.String()
	customToken.Symbol = obj.TxTokenPrivacyData.PropertySymbol
	customToken.Name = obj.TxTokenPrivacyData.PropertyName
	customToken.Amount = obj.TxTokenPrivacyData.Amount
	customToken.Image = common.Render(obj.TxTokenPrivacyData.PropertyID[:])
	customToken.IsPrivacy = true
}

func (customToken *CustomToken) InitPrivacyForCrossShard(obj blockchain.CrossShardTokenPrivacyMetaData) {
	customToken.ID = obj.TokenID.String()
	customToken.Symbol = obj.PropertySymbol
	customToken.Name = obj.PropertyName
	customToken.Amount = obj.Amount
	customToken.Image = common.Render(obj.TokenID[:])
	customToken.IsPrivacy = true
}

type ListCustomToken struct {
	ListCustomToken []CustomToken `json:"ListCustomToken"`
}
