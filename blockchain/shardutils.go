package blockchain

import (
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/common/base58"
	"github.com/incognitochain/incognito-chain/database"
	"github.com/incognitochain/incognito-chain/metadata"
	"github.com/incognitochain/incognito-chain/privacy"
	"github.com/incognitochain/incognito-chain/transaction"
)

//=======================================BEGIN SHARD BLOCK UTIL
func GetAssignInstructionFromBeaconBlock(beaconBlocks []*BeaconBlock, shardID byte) [][]string {
	assignInstruction := [][]string{}
	for _, beaconBlock := range beaconBlocks {
		for _, l := range beaconBlock.Body.Instructions {
			if l[0] == "assign" && l[2] == "shard" {
				if strings.Compare(l[3], strconv.Itoa(int(shardID))) == 0 {
					assignInstruction = append(assignInstruction, l)
				}
			}
		}
	}
	return assignInstruction
}

func FetchBeaconBlockFromHeight(db database.DatabaseInterface, from uint64, to uint64) ([]*BeaconBlock, error) {
	beaconBlocks := []*BeaconBlock{}
	for i := from; i <= to; i++ {
		hash, err := db.GetBeaconBlockHashByIndex(i)
		if err != nil {
			return beaconBlocks, err
		}
		beaconBlockByte, err := db.FetchBeaconBlock(hash)
		if err != nil {
			return beaconBlocks, err
		}
		beaconBlock := BeaconBlock{}
		err = json.Unmarshal(beaconBlockByte, &beaconBlock)
		if err != nil {
			return beaconBlocks, NewBlockChainError(UnmashallJsonShardBlockError, err)
		}
		beaconBlocks = append(beaconBlocks, &beaconBlock)
	}
	return beaconBlocks, nil
}

func CreateCrossShardByteArray(txList []metadata.Transaction, fromShardID byte) []byte {
	crossIDs := []byte{}
	byteMap := make([]byte, common.MAX_SHARD_NUMBER)
	for _, tx := range txList {
		if tx.GetProof() != nil {
			for _, outCoin := range tx.GetProof().GetOutputCoins() {
				lastByte := outCoin.CoinDetails.GetPubKeyLastByte()
				shardID := common.GetShardIDFromLastByte(lastByte)
				byteMap[common.GetShardIDFromLastByte(shardID)] = 1
				//fmt.Println("CS: header has output coin to shard", shardID)
			}
		}

		switch tx.GetType() {
		case common.TxCustomTokenType:
			{
				customTokenTx := tx.(*transaction.TxCustomToken)
				for _, out := range customTokenTx.TxTokenData.Vouts {
					lastByte := out.PaymentAddress.Pk[len(out.PaymentAddress.Pk)-1]
					shardID := common.GetShardIDFromLastByte(lastByte)
					byteMap[common.GetShardIDFromLastByte(shardID)] = 1
				}
			}
		case common.TxCustomTokenPrivacyType:
			{
				customTokenTx := tx.(*transaction.TxCustomTokenPrivacy)
				if customTokenTx.TxTokenPrivacyData.TxNormal.GetProof() != nil {
					for _, outCoin := range customTokenTx.TxTokenPrivacyData.TxNormal.GetProof().GetOutputCoins() {
						lastByte := outCoin.CoinDetails.GetPubKeyLastByte()
						shardID := common.GetShardIDFromLastByte(lastByte)
						byteMap[common.GetShardIDFromLastByte(shardID)] = 1
					}
				}
			}
		}
	}

	for k := range byteMap {
		if byteMap[k] == 1 && k != int(fromShardID) {
			crossIDs = append(crossIDs, byte(k))
		}
	}

	return crossIDs
}

/*
	Create Swap Action
	Return param:
	#1: swap instruction
	#2: new pending validator list after swapped
	#3: new committees after swapped
	#4: error
*/
func CreateSwapAction(pendingValidator []string, commitees []string, committeeSize int, shardID byte) ([]string, []string, []string, error) {
	newPendingValidator, newShardCommittees, shardSwapedCommittees, shardNewCommittees, err := SwapValidator(pendingValidator, commitees, committeeSize, common.OFFSET)
	if err != nil {
		return nil, nil, nil, err
	}
	swapInstruction := []string{"swap", strings.Join(shardNewCommittees, ","), strings.Join(shardSwapedCommittees, ","), "shard", strconv.Itoa(int(shardID))}
	return swapInstruction, newPendingValidator, newShardCommittees, nil
}

/*
	Action Generate From Transaction:
	- Stake
	- Stable param: set, del,...
*/
func CreateShardInstructionsFromTransactionAndInstruction(
	transactions []metadata.Transaction,
	bc *BlockChain,
	shardID byte,
) (instructions [][]string, err error) {
	// Generate stake action
	stakeShardPubKey := []string{}
	stakeBeaconPubKey := []string{}
	stakeShardTxID := []string{}
	stakeBeaconTxID := []string{}
	instructions, err = buildActionsFromMetadata(transactions, bc, shardID)
	if err != nil {
		return nil, err
	}
	for _, tx := range transactions {
		switch tx.GetMetadataType() {
		case metadata.ShardStakingMeta:
			pk := tx.GetProof().GetInputCoins()[0].CoinDetails.GetPublicKey().Compress()
			pkb58 := base58.Base58Check{}.Encode(pk, common.ZeroByte)
			stakeShardPubKey = append(stakeShardPubKey, pkb58)
			stakeShardTxID = append(stakeShardTxID, tx.Hash().String())
		case metadata.BeaconStakingMeta:
			pk := tx.GetProof().GetInputCoins()[0].CoinDetails.GetPublicKey().Compress()
			pkb58 := base58.Base58Check{}.Encode(pk, common.ZeroByte)
			stakeBeaconPubKey = append(stakeBeaconPubKey, pkb58)
			stakeBeaconTxID = append(stakeBeaconTxID, tx.Hash().String())
		}
	}
	if !reflect.DeepEqual(stakeShardPubKey, []string{}) {
		instruction := []string{StakeAction, strings.Join(stakeShardPubKey, ","), "shard", strings.Join(stakeShardTxID, ",")}
		instructions = append(instructions, instruction)
	}
	if !reflect.DeepEqual(stakeBeaconPubKey, []string{}) {
		instruction := []string{StakeAction, strings.Join(stakeBeaconPubKey, ","), "beacon", strings.Join(stakeBeaconTxID, ",")}
		instructions = append(instructions, instruction)
	}
	return instructions, nil
}

// build actions from txs and ins at shard
func buildActionsFromMetadata(
	txs []metadata.Transaction,
	bc *BlockChain,
	shardID byte,
) ([][]string, error) {
	actions := [][]string{}
	for _, tx := range txs {
		meta := tx.GetMetadata()
		if meta != nil {
			actionPairs, err := meta.BuildReqActions(tx, bc, shardID)
			if err != nil {
				continue
			}
			actions = append(actions, actionPairs...)
		}
	}
	return actions, nil
}

//=======================================END SHARD BLOCK UTIL
//====================New Merkle Tree================
func CreateShardTxRoot2(txList []metadata.Transaction) ([]common.Hash, []common.Hash) {
	//calculate output coin hash for each shard
	crossShardDataHash := getCrossShardDataHash(txList)
	// calculate merkel path for a shardID
	// step 1: calculate merkle data : [1, 2, 3, 4, 12, 34, 1234]
	/*
			   	1234=hash(12,34)
			   /			  \
		  12=hash(1,2)	 34=hash(3,4)
			 / \	 		 / \
			1	2			3	4
	*/
	merkleTree := Merkle{}
	merkleData := merkleTree.BuildMerkleTreeOfHashes2(crossShardDataHash, common.MAX_SHARD_NUMBER)
	return crossShardDataHash, merkleData
}
func GetMerklePathCrossShard2(txList []metadata.Transaction, shardID byte) (merklePathShard []common.Hash, merkleShardRoot common.Hash) {
	_, merkleTree := CreateShardTxRoot2(txList)
	merklePathShard, merkleShardRoot = Merkle{}.GetMerklePathForCrossShard(common.MAX_SHARD_NUMBER, merkleTree, shardID)
	return merklePathShard, merkleShardRoot
}

/*
	Calculate Final Hash as Hash of:
		1. CrossTransactionFinalHash
		2. TxTokenDataVoutFinalHash
		3. CrossTxTokenPrivacyData
	These hashes will be calculated as comment in getCrossShardDataHash function
*/
func VerifyCrossShardBlockUTXO(block *CrossShardBlock, merklePathShard []common.Hash) bool {
	var outputCoinHash common.Hash
	var txTokenDataHash common.Hash
	var txTokenPrivacyDataHash common.Hash
	outCoins := block.CrossOutputCoin
	outputCoinHash = calHashOutCoinCrossShard(outCoins)
	txTokenDataList := block.CrossTxTokenData
	txTokenDataHash = calHashTxTokenDataHashList(txTokenDataList)
	txTokenPrivacyDataList := block.CrossTxTokenPrivacyData
	txTokenPrivacyDataHash = calHashTxTokenPrivacyDataHashList(txTokenPrivacyDataList)
	tmpByte := append(append(outputCoinHash.GetBytes(), txTokenDataHash.GetBytes()...), txTokenPrivacyDataHash.GetBytes()...)
	finalHash := common.HashH(tmpByte)
	return Merkle{}.VerifyMerkleRootFromMerklePath(finalHash, merklePathShard, block.Header.ShardTxRoot, block.ToShardID)
}

//====================End New Merkle Tree================
/*
	Helper function: group OutputCoin into shard and get the hash of each group
	Return value
		- Array of hash created from 256 group cross shard data hash
		- Length array is 256
		- Value is sorted as shardID from low to high
		- ShardID which have no outputcoin received hash of emptystring value

	Hash Procedure:
		- For each shard:
			CROSS OUTPUT COIN
			+ Get outputcoin and append to a list of that shard
			+ Calculate value for Hash:
				* if receiver shard has no outcoin then received hash value of empty string
				* if receiver shard has >= 1 outcoin then concatenate all outcoin bytes value then hash
				* At last, we compress all cross out put coin into a CrossOutputCoinFinalHash
			TXTOKENDATA
			+ Do the same as above

			=> Then Final Hash of each shard is Hash of value in this order:
				1. CrossOutputCoinFinalHash
				2. TxTokenDataVoutFinalHash
	TxTokenOut DataStructure
		- Use Only One TxTokenData for one TokenID
		- Vouts of one tokenID from many transaction will be compress into One Vouts List
		- Using Key-Value structure for accessing one token ID data:
			key: token ID
			value: TokenData of that token
*/
func getCrossShardDataHash(txList []metadata.Transaction) []common.Hash {
	// group transaction by shardID
	outCoinEachShard := make([][]privacy.OutputCoin, common.MAX_SHARD_NUMBER)
	txTokenDataEachShard := make([]map[common.Hash]*transaction.TxTokenData, common.MAX_SHARD_NUMBER)
	txTokenPrivacyDataMap := make([]map[common.Hash]*ContentCrossShardTokenPrivacyData, common.MAX_SHARD_NUMBER)
	for _, tx := range txList {
		switch tx.GetType() {
		//==================For PRV Transfer Only
		//TxReturnStakingType cannot be crossshard tx
		case common.TxNormalType, common.TxRewardType:
			{
				//==================Proof Process
				if tx.GetProof() != nil {
					for _, outCoin := range tx.GetProof().GetOutputCoins() {
						lastByte := outCoin.CoinDetails.GetPubKeyLastByte()
						shardID := common.GetShardIDFromLastByte(lastByte)
						outCoinEachShard[shardID] = append(outCoinEachShard[shardID], *outCoin)
					}
				}
			}
		//==================For PRV & TxCustomToken Transfer
		case common.TxCustomTokenType:
			{
				customTokenTx := tx.(*transaction.TxCustomToken)
				//==================Proof Process
				if customTokenTx.GetProof() != nil {
					for _, outCoin := range customTokenTx.GetProof().GetOutputCoins() {
						lastByte := outCoin.CoinDetails.GetPubKeyLastByte()
						shardID := common.GetShardIDFromLastByte(lastByte)
						outCoinEachShard[shardID] = append(outCoinEachShard[shardID], *outCoin)
					}
				}
				//==================Tx Token Data Process
				for _, vout := range customTokenTx.TxTokenData.Vouts {
					lastByte := vout.PaymentAddress.Pk[len(vout.PaymentAddress.Pk)-1]
					shardID := common.GetShardIDFromLastByte(lastByte)
					if txTokenDataEachShard[shardID] == nil {
						txTokenDataEachShard[shardID] = make(map[common.Hash]*transaction.TxTokenData)
					}
					if _, ok := txTokenDataEachShard[shardID][customTokenTx.TxTokenData.PropertyID]; !ok {
						newTxTokenData := cloneTxTokenDataForCrossShard(customTokenTx.TxTokenData)
						txTokenDataEachShard[shardID][customTokenTx.TxTokenData.PropertyID] = &newTxTokenData
					}
					vouts := txTokenDataEachShard[shardID][customTokenTx.TxTokenData.PropertyID].Vouts
					vouts = append(vouts, vout)
					txTokenDataEachShard[shardID][customTokenTx.TxTokenData.PropertyID].Vouts = vouts
				}
			}
		case common.TxCustomTokenPrivacyType:
			{
				customTokenPrivacyTx := tx.(*transaction.TxCustomTokenPrivacy)
				//==================Proof Process
				if customTokenPrivacyTx.GetProof() != nil {
					for _, outCoin := range customTokenPrivacyTx.GetProof().GetOutputCoins() {
						lastByte := outCoin.CoinDetails.GetPubKeyLastByte()
						shardID := common.GetShardIDFromLastByte(lastByte)
						outCoinEachShard[shardID] = append(outCoinEachShard[shardID], *outCoin)
					}
				}
				//==================Tx Token Privacy Data Process
				if customTokenPrivacyTx.TxTokenPrivacyData.TxNormal.GetProof() != nil {
					for _, outCoin := range customTokenPrivacyTx.TxTokenPrivacyData.TxNormal.GetProof().GetOutputCoins() {
						lastByte := outCoin.CoinDetails.GetPubKeyLastByte()
						shardID := common.GetShardIDFromLastByte(lastByte)
						if txTokenPrivacyDataMap[shardID] == nil {
							txTokenPrivacyDataMap[shardID] = make(map[common.Hash]*ContentCrossShardTokenPrivacyData)
						}
						if _, ok := txTokenPrivacyDataMap[shardID][customTokenPrivacyTx.TxTokenPrivacyData.PropertyID]; !ok {
							contentCrossTokenPrivacyData := cloneTxTokenPrivacyDataForCrossShard(customTokenPrivacyTx.TxTokenPrivacyData)
							txTokenPrivacyDataMap[shardID][customTokenPrivacyTx.TxTokenPrivacyData.PropertyID] = &contentCrossTokenPrivacyData
						}
						txTokenPrivacyDataMap[shardID][customTokenPrivacyTx.TxTokenPrivacyData.PropertyID].OutputCoin = append(txTokenPrivacyDataMap[shardID][customTokenPrivacyTx.TxTokenPrivacyData.PropertyID].OutputCoin, *outCoin)
					}
				}
			}
		}
	}
	//calcualte hash for each shard
	outputCoinHash := make([]common.Hash, common.MAX_SHARD_NUMBER)
	txTokenOutHash := make([]common.Hash, common.MAX_SHARD_NUMBER)
	txTokenPrivacyOutHash := make([]common.Hash, common.MAX_SHARD_NUMBER)
	combinedHash := make([]common.Hash, common.MAX_SHARD_NUMBER)
	for i := 0; i < common.MAX_SHARD_NUMBER; i++ {
		outputCoinHash[i] = calHashOutCoinCrossShard(outCoinEachShard[i])
		txTokenOutHash[i] = calHashTxTokenDataHashFromMap(txTokenDataEachShard[i])
		txTokenPrivacyOutHash[i] = calHashTxTokenPrivacyDataHashFromMap(txTokenPrivacyDataMap[i])

		tmpByte := append(append(outputCoinHash[i].GetBytes(), txTokenOutHash[i].GetBytes()...), txTokenPrivacyOutHash[i].GetBytes()...)
		combinedHash[i] = common.HashH(tmpByte)
	}
	return combinedHash
}

// helper function to get cross data (send to a shard) from list of transaction:
// 1. (Privacy) PRV: Output coin
// 2. Tx Custom Token: Tx Token Data
// 3. Privacy Custom Token: Token Data + Output coin
func getCrossShardData(txList []metadata.Transaction, shardID byte) ([]privacy.OutputCoin,
	[]transaction.TxTokenData,
	[]ContentCrossShardTokenPrivacyData,
) {
	coinList := []privacy.OutputCoin{}
	txTokenDataMap := make(map[common.Hash]*transaction.TxTokenData)
	txTokenPrivacyDataMap := make(map[common.Hash]*ContentCrossShardTokenPrivacyData)
	var txTokenDataList []transaction.TxTokenData
	var txTokenPrivacyDataList []ContentCrossShardTokenPrivacyData
	for _, tx := range txList {
		if tx.GetProof() != nil {
			for _, outCoin := range tx.GetProof().GetOutputCoins() {
				lastByte := common.GetShardIDFromLastByte(outCoin.CoinDetails.GetPubKeyLastByte())
				if lastByte == shardID {
					//fmt.Println("CS: outputcoin has output coin to shard", lastByte)
					coinList = append(coinList, *outCoin)
				}
			}
		}
		if tx.GetType() == common.TxCustomTokenType {
			customTokenTx := tx.(*transaction.TxCustomToken)
			for _, vout := range customTokenTx.TxTokenData.Vouts {
				lastByte := common.GetShardIDFromLastByte(vout.PaymentAddress.Pk[len(vout.PaymentAddress.Pk)-1])
				if lastByte == shardID {
					if _, ok := txTokenDataMap[customTokenTx.TxTokenData.PropertyID]; !ok {
						newTxTokenData := cloneTxTokenDataForCrossShard(customTokenTx.TxTokenData)
						txTokenDataMap[customTokenTx.TxTokenData.PropertyID] = &newTxTokenData
					}
					vouts := txTokenDataMap[customTokenTx.TxTokenData.PropertyID].Vouts
					vouts = append(vouts, vout)
					txTokenDataMap[customTokenTx.TxTokenData.PropertyID].Vouts = vouts
				}
			}
		}
		if tx.GetType() == common.TxCustomTokenPrivacyType {
			customTokenPrivacyTx := tx.(*transaction.TxCustomTokenPrivacy)
			if customTokenPrivacyTx.TxTokenPrivacyData.TxNormal.GetProof() != nil {
				for _, outCoin := range customTokenPrivacyTx.TxTokenPrivacyData.TxNormal.GetProof().GetOutputCoins() {
					lastByte := common.GetShardIDFromLastByte(outCoin.CoinDetails.GetPubKeyLastByte())
					if lastByte == shardID {
						if _, ok := txTokenPrivacyDataMap[customTokenPrivacyTx.TxTokenPrivacyData.PropertyID]; !ok {
							contentCrossTokenPrivacyData := cloneTxTokenPrivacyDataForCrossShard(customTokenPrivacyTx.TxTokenPrivacyData)
							txTokenPrivacyDataMap[customTokenPrivacyTx.TxTokenPrivacyData.PropertyID] = &contentCrossTokenPrivacyData
						}
						txTokenPrivacyDataMap[customTokenPrivacyTx.TxTokenPrivacyData.PropertyID].OutputCoin = append(txTokenPrivacyDataMap[customTokenPrivacyTx.TxTokenPrivacyData.PropertyID].OutputCoin, *outCoin)
					}
				}
			}
		}
	}
	if len(txTokenDataMap) != 0 {
		for _, value := range txTokenDataMap {
			txTokenDataList = append(txTokenDataList, *value)
		}
		sort.SliceStable(txTokenDataList[:], func(i, j int) bool {
			return txTokenDataList[i].PropertyID.String() < txTokenDataList[j].PropertyID.String()
		})
	}
	if len(txTokenPrivacyDataMap) != 0 {
		for _, value := range txTokenPrivacyDataMap {
			txTokenPrivacyDataList = append(txTokenPrivacyDataList, *value)
		}
		sort.SliceStable(txTokenPrivacyDataList[:], func(i, j int) bool {
			return txTokenPrivacyDataList[i].PropertyID.String() < txTokenPrivacyDataList[j].PropertyID.String()
		})
	}
	return coinList, txTokenDataList, txTokenPrivacyDataList
}

func calHashOutCoinCrossShard(outCoins []privacy.OutputCoin) common.Hash {
	tmpByte := []byte{}
	var outputCoinHash common.Hash
	if len(outCoins) != 0 {
		for _, outCoin := range outCoins {
			coin := &outCoin

			tmpByte = append(tmpByte, coin.Bytes()...)
		}
		outputCoinHash = common.HashH(tmpByte)
	} else {
		outputCoinHash = common.HashH([]byte(""))
	}
	return outputCoinHash
}

func calHashTxTokenDataHashFromMap(txTokenDataMap map[common.Hash]*transaction.TxTokenData) common.Hash {
	if len(txTokenDataMap) == 0 {
		return common.HashH([]byte(""))
	}
	var txTokenDataList []transaction.TxTokenData
	for _, value := range txTokenDataMap {
		txTokenDataList = append(txTokenDataList, *value)
	}
	sort.SliceStable(txTokenDataList[:], func(i, j int) bool {
		return txTokenDataList[i].PropertyID.String() < txTokenDataList[j].PropertyID.String()
	})
	return calHashTxTokenDataHashList(txTokenDataList)
}

func calHashTxTokenDataHashList(txTokenDataList []transaction.TxTokenData) common.Hash {
	tmpByte := []byte{}
	if len(txTokenDataList) != 0 {
		for _, txTokenData := range txTokenDataList {
			tempHash, _ := txTokenData.Hash()
			tmpByte = append(tmpByte, tempHash.GetBytes()...)
		}
	} else {
		return common.HashH([]byte(""))
	}

	return common.HashH(tmpByte)
}

func calHashTxTokenPrivacyDataHashFromMap(txTokenPrivacyDataMap map[common.Hash]*ContentCrossShardTokenPrivacyData) common.Hash {
	if len(txTokenPrivacyDataMap) == 0 {
		return common.HashH([]byte(""))
	}
	var txTokenPrivacyDataList []ContentCrossShardTokenPrivacyData
	for _, value := range txTokenPrivacyDataMap {
		txTokenPrivacyDataList = append(txTokenPrivacyDataList, *value)
	}
	sort.SliceStable(txTokenPrivacyDataList[:], func(i, j int) bool {
		return txTokenPrivacyDataList[i].PropertyID.String() < txTokenPrivacyDataList[j].PropertyID.String()
	})
	return calHashTxTokenPrivacyDataHashList(txTokenPrivacyDataList)
}

func calHashTxTokenPrivacyDataHashList(txTokenPrivacyDataList []ContentCrossShardTokenPrivacyData) common.Hash {
	tmpByte := []byte{}
	if len(txTokenPrivacyDataList) != 0 {
		for _, txTokenPrivacyData := range txTokenPrivacyDataList {
			tempHash := txTokenPrivacyData.Hash()
			tmpByte = append(tmpByte, tempHash.GetBytes()...)

		}
	} else {
		return common.HashH([]byte(""))
	}
	return common.HashH(tmpByte)
}

func cloneTxTokenDataForCrossShard(txTokenData transaction.TxTokenData) transaction.TxTokenData {
	newTxTokenData := transaction.TxTokenData{
		PropertyID:     txTokenData.PropertyID,
		PropertyName:   txTokenData.PropertyName,
		PropertySymbol: txTokenData.PropertySymbol,
		Mintable:       txTokenData.Mintable,
		Amount:         txTokenData.Amount,
		Type:           transaction.CustomTokenCrossShard,
	}
	newTxTokenData.Vins = []transaction.TxTokenVin{}
	newTxTokenData.Vouts = []transaction.TxTokenVout{}
	return newTxTokenData
}
func cloneTxTokenPrivacyDataForCrossShard(txTokenPrivacyData transaction.TxTokenPrivacyData) ContentCrossShardTokenPrivacyData {
	newContentCrossTokenPrivacyData := ContentCrossShardTokenPrivacyData{
		PropertyID:     txTokenPrivacyData.PropertyID,
		PropertyName:   txTokenPrivacyData.PropertyName,
		PropertySymbol: txTokenPrivacyData.PropertySymbol,
		Mintable:       txTokenPrivacyData.Mintable,
		Amount:         txTokenPrivacyData.Amount,
		Type:           transaction.CustomTokenCrossShard,
	}
	newContentCrossTokenPrivacyData.OutputCoin = []privacy.OutputCoin{}
	return newContentCrossTokenPrivacyData
}
func CreateMerkleCrossOutputCoin(crossOutputCoins map[byte][]CrossOutputCoin) (*common.Hash, error) {
	if len(crossOutputCoins) == 0 {
		res, err := generateZeroValueHash()

		return &res, err
	}
	keys := []int{}
	crossOutputCoinHashes := []*common.Hash{}
	for k := range crossOutputCoins {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	for _, shardID := range keys {
		for _, value := range crossOutputCoins[byte(shardID)] {
			hash := value.Hash()
			hashByte := hash.GetBytes()
			newHash, err := common.Hash{}.NewHash(hashByte)
			if err != nil {
				return &common.Hash{}, NewBlockChainError(HashError, err)
			}
			crossOutputCoinHashes = append(crossOutputCoinHashes, newHash)
		}
	}
	merkle := Merkle{}
	merkleTree := merkle.BuildMerkleTreeOfHashes(crossOutputCoinHashes, len(crossOutputCoinHashes))
	return merkleTree[len(merkleTree)-1], nil
}

func VerifyMerkleCrossOutputCoin(crossOutputCoins map[byte][]CrossOutputCoin, rootHash common.Hash) bool {
	res, err := CreateMerkleCrossOutputCoin(crossOutputCoins)
	if err != nil {
		return false
	}
	hashByte := rootHash.GetBytes()
	newHash, err := common.Hash{}.NewHash(hashByte)
	if err != nil {
		return false
	}
	return newHash.IsEqual(res)
}
func CreateMerkleCrossTransaction(crossTransactions map[byte][]CrossTransaction) (*common.Hash, error) {
	if len(crossTransactions) == 0 {
		res, err := generateZeroValueHash()
		return &res, err
	}
	keys := []int{}
	crossTransactionHashes := []*common.Hash{}
	for k := range crossTransactions {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	for _, shardID := range keys {
		for _, value := range crossTransactions[byte(shardID)] {
			hash := value.Hash()
			crossTransactionHashes = append(crossTransactionHashes, &hash)
		}
	}
	merkle := Merkle{}
	merkleTree := merkle.BuildMerkleTreeOfHashes(crossTransactionHashes, len(crossTransactionHashes))
	return merkleTree[len(merkleTree)-1], nil
}

func VerifyMerkleCrossTransaction(crossTransactions map[byte][]CrossTransaction, rootHash common.Hash) bool {
	res, err := CreateMerkleCrossTransaction(crossTransactions)
	if err != nil {
		return false
	}
	hashByte := rootHash.GetBytes()
	newHash, err := common.Hash{}.NewHash(hashByte)
	if err != nil {
		return false
	}
	return newHash.IsEqual(res)
}

//=======================================END CROSS SHARD UTIL
