package metadata

import (
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/database"
)

type ResponseBase struct {
	MetadataBase
	RequestedTxID common.Hash
}

func (bbRes *ResponseBase) CheckTransactionFee(tr Transaction, minFee uint64) bool {
	// no need to have fee for this tx
	return true
}

func (bbRes *ResponseBase) ValidateTxWithBlockChain(txr Transaction, bcr BlockchainRetriever, shardID byte, db database.DatabaseInterface) (bool, error) {
	// no need to validate tx with blockchain, just need to validate with requeste tx (via RequestedTxID) in current block
	return false, nil
}

func (bbRes *ResponseBase) ValidateSanityData(bcr BlockchainRetriever, txr Transaction) (bool, bool, error) {
	return false, true, nil
}

func (bbRes *ResponseBase) ValidateMetadataByItself() bool {
	// The validation just need to check at tx level, so returning true here
	return true
}

func (bbRes *ResponseBase) Hash() *common.Hash {
	record := bbRes.RequestedTxID.String()
	// final hash
	record += bbRes.MetadataBase.Hash().String()
	hash := common.HashH([]byte(record))
	return &hash
}

func (bbRes *ResponseBase) CalculateSize() uint64 {
	return calculateSize(bbRes)
}
