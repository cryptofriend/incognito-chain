package blockchain

import (
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/common/base58"
	"github.com/incognitochain/incognito-chain/metadata"
	"github.com/incognitochain/incognito-chain/transaction"
	"github.com/incognitochain/incognito-chain/wallet"
)

func (blockchain *BlockChain) ValidateBlockWithPrevShardBestState(block *ShardBlock) error {
	prevBST, err := blockchain.config.DataBase.FetchPrevBestState(false, block.Header.ShardID)
	if err != nil {
		return err
	}
	shardBestState := ShardBestState{}
	if err := json.Unmarshal(prevBST, &shardBestState); err != nil {
		return err
	}

	// blkHash := block.Header.Hash()
	// producerPk := base58.Base58Check{}.Encode(block.Header.ProducerAddress.Pk, common.ZeroByte)
	// err = incognitokey.ValidateDataB58(producerPk, block.ProducerSig, blkHash.GetBytes())
	// if err != nil {
	// 	return NewBlockChainError(ProducerError, errors.New("Producer's sig not match"))
	// }
	//verify producer
	// block.GetValidationField()
	producerPk := block.Header.Producer
	producerPosition := (shardBestState.ShardProposerIdx + block.Header.Round) % len(shardBestState.ShardCommittee)
	tempProducer := shardBestState.ShardCommittee[producerPosition]
	if strings.Compare(tempProducer, producerPk) != 0 {
		return NewBlockChainError(ProducerError, errors.New("Producer should be should be :"+tempProducer))
	}
	// if block.Header.Version != SHARD_BLOCK_VERSION {
	// 	return NewBlockChainError(, errors.New("Version should be :"+strconv.Itoa(VERSION)))
	// }
	// Verify parent hash exist or not
	prevBlockHash := block.Header.PreviousBlockHash
	parentBlockData, err := blockchain.config.DataBase.FetchBlock(prevBlockHash)
	if err != nil {
		return NewBlockChainError(DatabaseError, err)
	}
	parentBlock := ShardBlock{}
	json.Unmarshal(parentBlockData, &parentBlock)
	// Verify block height with parent block
	if parentBlock.Header.Height+1 != block.Header.Height {
		return NewBlockChainError(ShardStateError, errors.New("block height of new block should be :"+strconv.Itoa(int(block.Header.Height+1))))
	}
	return nil
}

//This only happen if user is a shard committee member.
func (blockchain *BlockChain) RevertShardState(shardID byte) error {
	//Steps:
	// 1. Restore current beststate to previous beststate
	// 2. Set pool shardstate
	// 3. Delete newly inserted block
	// 4. Remove incoming crossShardBlks
	// 5. Delete txs and its related stuff (ex: txview) belong to block

	blockchain.chainLock.Lock()
	defer blockchain.chainLock.Unlock()
	currentBestState := blockchain.BestState.Shard[shardID]
	currentBestStateBlk := currentBestState.BestBlock

	prevBST, err := blockchain.config.DataBase.FetchPrevBestState(false, shardID)
	if err != nil {
		return err
	}
	shardBestState := ShardBestState{}
	if err := json.Unmarshal(prevBST, &shardBestState); err != nil {
		return err
	}

	err = blockchain.DeleteIncomingCrossShard(currentBestStateBlk)
	if err != nil {
		return NewBlockChainError(UnExpectedError, err)
	}

	for _, tx := range currentBestState.BestBlock.Body.Transactions {
		if err := blockchain.config.DataBase.DeleteTransactionIndex(*tx.Hash()); err != nil {
			return err
		}
	}

	if err := blockchain.restoreFromTxViewPoint(currentBestStateBlk); err != nil {
		return err
	}

	if err := blockchain.restoreFromCrossTxViewPoint(currentBestStateBlk); err != nil {
		return err
	}

	prevBeaconHeight := shardBestState.BeaconHeight
	beaconBlocks, err := FetchBeaconBlockFromHeight(blockchain.config.DataBase, prevBeaconHeight+1, currentBestStateBlk.Header.BeaconHeight)
	if err != nil {
		return err
	}

	if err := blockchain.restoreDatabaseFromBeaconInstruction(beaconBlocks, currentBestStateBlk.Header.ShardID); err != nil {
		return err
	}

	// DeleteIncomingCrossShard
	blockchain.config.DataBase.DeleteBlock(currentBestStateBlk.Header.Hash(), currentBestStateBlk.Header.Height, shardID)
	blockchain.BestState.Shard[shardID] = &shardBestState
	if err := blockchain.StoreShardBestState(shardID); err != nil {
		return err
	}
	return nil
}

func (blockchain *BlockChain) BackupCurrentShardState(block *ShardBlock, beaconblks []*BeaconBlock) error {

	//Steps:
	// 1. Backup beststate
	// 2.	Backup data that will be modify by new block data

	tempMarshal, err := json.Marshal(blockchain.BestState.Shard[block.Header.ShardID])
	if err != nil {
		return NewBlockChainError(UnmashallJsonShardBlockError, err)
	}

	if err := blockchain.config.DataBase.StorePrevBestState(tempMarshal, false, block.Header.ShardID); err != nil {
		return NewBlockChainError(UnExpectedError, err)
	}

	if err := blockchain.createBackupFromTxViewPoint(block); err != nil {
		return err
	}

	if err := blockchain.createBackupFromCrossTxViewPoint(block); err != nil {
		return err
	}

	if err := blockchain.backupDatabaseFromBeaconInstruction(beaconblks, block.Header.ShardID); err != nil {
		return err
	}

	return nil
}

func (blockchain *BlockChain) backupDatabaseFromBeaconInstruction(beaconBlocks []*BeaconBlock,
	shardID byte) error {

	shardCommittee := make(map[byte][]string)
	isInit := false
	epoch := uint64(0)
	db := blockchain.config.DataBase
	// listShardCommittee := blockchain.config.DataBase.FetchCommitteeByEpoch
	for _, beaconBlock := range beaconBlocks {
		for _, l := range beaconBlock.Body.Instructions {
			if l[0] == StakeAction || l[0] == RandomAction {
				continue
			}
			if len(l) <= 2 {
				continue
			}
			shardToProcess, err := strconv.Atoi(l[1])
			if err != nil {
				continue
			}
			if shardToProcess == int(shardID) {
				metaType, err := strconv.Atoi(l[0])
				if err != nil {
					return err
				}
				switch metaType {
				case metadata.BeaconRewardRequestMeta:
					beaconBlkRewardInfo, err := metadata.NewBeaconBlockRewardInfoFromStr(l[3])
					if err != nil {
						return err
					}
					publicKeyCommittee, _, err := base58.Base58Check{}.Decode(beaconBlkRewardInfo.PayToPublicKey)
					if err != nil {
						return err
					}
					for key := range beaconBlkRewardInfo.BeaconReward {
						err = db.BackupCommitteeReward(publicKeyCommittee, key)
						if err != nil {
							return err
						}
					}
					continue

				case metadata.DevRewardRequestMeta:
					devRewardInfo, err := metadata.NewDevRewardInfoFromStr(l[3])
					if err != nil {
						return err
					}
					keyWalletDevAccount, err := wallet.Base58CheckDeserialize(common.DevAddress)
					if err != nil {
						return err
					}
					for key := range devRewardInfo.DevReward {
						err = db.BackupCommitteeReward(keyWalletDevAccount.KeySet.PaymentAddress.Pk, key)
						if err != nil {
							return err
						}
					}
					continue

				case metadata.ShardBlockRewardRequestMeta:
					shardRewardInfo, err := metadata.NewShardBlockRewardInfoFromString(l[3])
					if err != nil {
						return err
					}
					if (!isInit) || (epoch != shardRewardInfo.Epoch) {
						isInit = true
						epoch = shardRewardInfo.Epoch
						temp, err := blockchain.config.DataBase.FetchCommitteeByHeight(epoch * common.EPOCH)
						if err != nil {
							return err
						}
						json.Unmarshal(temp, &shardCommittee)
					}
					err = blockchain.backupShareRewardForShardCommittee(shardRewardInfo.Epoch, shardRewardInfo.ShardReward, shardCommittee[shardID])
					if err != nil {
						return err
					}
					continue
				}
			}
		}
	}
	return nil
}

func (blockchain *BlockChain) backupShareRewardForShardCommittee(epoch uint64, totalReward map[common.Hash]uint64, listCommitee []string) error {
	// reward := totalReward / uint64(len(listCommitee))
	reward := map[common.Hash]uint64{}
	for key, value := range totalReward {
		reward[key] = value / uint64(len(listCommitee))
	}
	for key := range totalReward {
		for _, committee := range listCommitee {
			committeeBytes, _, err := base58.Base58Check{}.Decode(committee)
			if err != nil {
				return err
			}
			err = blockchain.config.DataBase.BackupCommitteeReward(committeeBytes, key)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (blockchain *BlockChain) createBackupFromTxViewPoint(block *ShardBlock) error {
	// Fetch data from block into tx View point
	view := NewTxViewPoint(block.Header.ShardID)
	err := view.fetchTxViewPointFromBlock(blockchain.config.DataBase, block)
	if err != nil {
		return err
	}

	// check privacy custom token
	backupedView := make(map[string]bool)
	for _, privacyCustomTokenSubView := range view.privacyCustomTokenViewPoint {
		if ok := backupedView[privacyCustomTokenSubView.tokenID.String()]; !ok {
			err = blockchain.backupSerialNumbersFromTxViewPoint(*privacyCustomTokenSubView)
			if err != nil {
				return err
			}

			err = blockchain.backupCommitmentsFromTxViewPoint(*privacyCustomTokenSubView)
			if err != nil {
				return err
			}
			backupedView[privacyCustomTokenSubView.tokenID.String()] = true
		}

	}
	err = blockchain.backupSerialNumbersFromTxViewPoint(*view)
	if err != nil {
		return err
	}

	err = blockchain.backupCommitmentsFromTxViewPoint(*view)
	if err != nil {
		return err
	}

	return nil
}

func (blockchain *BlockChain) createBackupFromCrossTxViewPoint(block *ShardBlock) error {
	view := NewTxViewPoint(block.Header.ShardID)
	err := view.fetchCrossTransactionViewPointFromBlock(blockchain.config.DataBase, block)

	for _, privacyCustomTokenSubView := range view.privacyCustomTokenViewPoint {
		err = blockchain.backupCommitmentsFromTxViewPoint(*privacyCustomTokenSubView)
		if err != nil {
			return err
		}
	}
	err = blockchain.backupCommitmentsFromTxViewPoint(*view)
	if err != nil {
		return err
	}

	return nil
}

func (blockchain *BlockChain) backupSerialNumbersFromTxViewPoint(view TxViewPoint) error {
	err := blockchain.config.DataBase.BackupSerialNumbersLen(*view.tokenID, view.shardID)
	if err != nil {
		return err
	}
	return nil
}

func (blockchain *BlockChain) backupCommitmentsFromTxViewPoint(view TxViewPoint) error {

	// commitment
	keys := make([]string, 0, len(view.mapCommitments))
	for k := range view.mapCommitments {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		pubkey := k
		pubkeyBytes, _, err := base58.Base58Check{}.Decode(pubkey)
		if err != nil {
			return err
		}
		lastByte := pubkeyBytes[len(pubkeyBytes)-1]
		pubkeyShardID := common.GetShardIDFromLastByte(lastByte)
		if pubkeyShardID == view.shardID {
			err = blockchain.config.DataBase.BackupCommitmentsOfPubkey(*view.tokenID, view.shardID, pubkeyBytes)
			if err != nil {
				return err
			}
		}
	}

	// outputs
	keys = make([]string, 0, len(view.mapOutputCoins))
	for k := range view.mapOutputCoins {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// for _, k := range keys {
	// 	pubkey := k

	// 	pubkeyBytes, _, err := base58.Base58Check{}.Decode(pubkey)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	lastByte := pubkeyBytes[len(pubkeyBytes)-1]
	// 	pubkeyShardID := common.GetShardIDFromLastByte(lastByte)
	// 	if pubkeyShardID == view.shardID {
	// 		err = blockchain.config.DataBase.BackupOutputCoin(*view.tokenID, pubkeyBytes, pubkeyShardID)
	// 		if err != nil {
	// 			return err
	// 		}
	// 	}
	// }
	return nil
}

func (blockchain *BlockChain) restoreDatabaseFromBeaconInstruction(beaconBlocks []*BeaconBlock,
	shardID byte) error {

	shardCommittee := make(map[byte][]string)
	isInit := false
	epoch := uint64(0)
	db := blockchain.config.DataBase
	// listShardCommittee := blockchain.config.DataBase.FetchCommitteeByEpoch
	for _, beaconBlock := range beaconBlocks {
		for _, l := range beaconBlock.Body.Instructions {
			if l[0] == StakeAction || l[0] == RandomAction {
				continue
			}
			if len(l) <= 2 {
				continue
			}
			shardToProcess, err := strconv.Atoi(l[1])
			if err != nil {
				continue
			}
			if shardToProcess == int(shardID) {
				metaType, err := strconv.Atoi(l[0])
				if err != nil {
					return err
				}
				switch metaType {
				case metadata.BeaconRewardRequestMeta:
					beaconBlkRewardInfo, err := metadata.NewBeaconBlockRewardInfoFromStr(l[3])
					if err != nil {
						return err
					}
					publicKeyCommittee, _, err := base58.Base58Check{}.Decode(beaconBlkRewardInfo.PayToPublicKey)
					if err != nil {
						return err
					}
					for key := range beaconBlkRewardInfo.BeaconReward {
						err = db.RestoreCommitteeReward(publicKeyCommittee, key)
						if err != nil {
							return err
						}
					}
					continue

				case metadata.DevRewardRequestMeta:
					devRewardInfo, err := metadata.NewDevRewardInfoFromStr(l[3])
					if err != nil {
						return err
					}
					keyWalletDevAccount, err := wallet.Base58CheckDeserialize(common.DevAddress)
					if err != nil {
						return err
					}
					for key := range devRewardInfo.DevReward {
						err = db.RestoreCommitteeReward(keyWalletDevAccount.KeySet.PaymentAddress.Pk, key)
						if err != nil {
							return err
						}
					}
					continue

				case metadata.ShardBlockRewardRequestMeta:
					shardRewardInfo, err := metadata.NewShardBlockRewardInfoFromString(l[3])
					if err != nil {
						return err
					}
					if (!isInit) || (epoch != shardRewardInfo.Epoch) {
						isInit = true
						epoch = shardRewardInfo.Epoch
						temp, err := blockchain.config.DataBase.FetchCommitteeByHeight(epoch * common.EPOCH)
						if err != nil {
							return err
						}
						json.Unmarshal(temp, &shardCommittee)
					}
					err = blockchain.restoreShareRewardForShardCommittee(shardRewardInfo.Epoch, shardRewardInfo.ShardReward, shardCommittee[shardID])
					if err != nil {
						return err
					}
					continue
				}
			}
		}
	}
	return nil
}

func (blockchain *BlockChain) restoreShareRewardForShardCommittee(epoch uint64, totalReward map[common.Hash]uint64, listCommitee []string) error {
	// reward := totalReward / uint64(len(listCommitee))
	reward := map[common.Hash]uint64{}
	for key, value := range totalReward {
		reward[key] = value / uint64(len(listCommitee))
	}
	for key := range totalReward {
		for _, committee := range listCommitee {
			committeeBytes, _, err := base58.Base58Check{}.Decode(committee)
			if err != nil {
				return err
			}
			err = blockchain.config.DataBase.RestoreCommitteeReward(committeeBytes, key)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (blockchain *BlockChain) restoreFromTxViewPoint(block *ShardBlock) error {
	// Fetch data from block into tx View point
	view := NewTxViewPoint(block.Header.ShardID)
	err := view.fetchTxViewPointFromBlock(blockchain.config.DataBase, block)
	if err != nil {
		return err
	}

	// check normal custom token
	for indexTx, customTokenTx := range view.customTokenTxs {
		switch customTokenTx.TxTokenData.Type {
		case transaction.CustomTokenInit:
			{
				err = blockchain.config.DataBase.DeleteCustomToken(customTokenTx.TxTokenData.PropertyID)
				if err != nil {
					return err
				}
			}
		case transaction.CustomTokenCrossShard:
			{
				err = blockchain.config.DataBase.DeleteCustomToken(customTokenTx.TxTokenData.PropertyID)
				if err != nil {
					return err
				}
			}
		}
		err = blockchain.config.DataBase.DeleteCustomTokenTx(customTokenTx.TxTokenData.PropertyID, indexTx, block.Header.ShardID, block.Header.Height)
		if err != nil {
			return err
		}

	}

	// check privacy custom token
	for indexTx, privacyCustomTokenSubView := range view.privacyCustomTokenViewPoint {
		privacyCustomTokenTx := view.privacyCustomTokenTxs[indexTx]
		switch privacyCustomTokenTx.TxTokenPrivacyData.Type {
		case transaction.CustomTokenInit:
			{
				err = blockchain.config.DataBase.DeletePrivacyCustomToken(privacyCustomTokenTx.TxTokenPrivacyData.PropertyID)
				if err != nil {
					return err
				}
			}
		}
		err = blockchain.config.DataBase.DeletePrivacyCustomTokenTx(privacyCustomTokenTx.TxTokenPrivacyData.PropertyID, indexTx, block.Header.ShardID, block.Header.Height)
		if err != nil {
			return err
		}

		err = blockchain.restoreSerialNumbersFromTxViewPoint(*privacyCustomTokenSubView)
		if err != nil {
			return err
		}

		err = blockchain.restoreCommitmentsFromTxViewPoint(*privacyCustomTokenSubView, block.Header.ShardID)
		if err != nil {
			return err
		}
	}

	err = blockchain.restoreSerialNumbersFromTxViewPoint(*view)
	if err != nil {
		return err
	}

	err = blockchain.restoreCommitmentsFromTxViewPoint(*view, block.Header.ShardID)
	if err != nil {
		return err
	}

	return nil
}

func (blockchain *BlockChain) restoreFromCrossTxViewPoint(block *ShardBlock) error {
	view := NewTxViewPoint(block.Header.ShardID)
	err := view.fetchCrossTransactionViewPointFromBlock(blockchain.config.DataBase, block)

	for _, privacyCustomTokenSubView := range view.privacyCustomTokenViewPoint {
		tokenID := privacyCustomTokenSubView.tokenID
		if err := blockchain.config.DataBase.DeletePrivacyCustomTokenCrossShard(*tokenID); err != nil {
			return err
		}
		err = blockchain.restoreCommitmentsFromTxViewPoint(*privacyCustomTokenSubView, block.Header.ShardID)
		if err != nil {
			return err
		}
	}

	err = blockchain.restoreCommitmentsFromTxViewPoint(*view, block.Header.ShardID)
	if err != nil {
		return err
	}
	return nil
}

func (blockchain *BlockChain) restoreSerialNumbersFromTxViewPoint(view TxViewPoint) error {
	err := blockchain.config.DataBase.RestoreSerialNumber(*view.tokenID, view.shardID, view.listSerialNumbers)
	if err != nil {
		return err
	}
	return nil
}

func (blockchain *BlockChain) restoreCommitmentsFromTxViewPoint(view TxViewPoint, shardID byte) error {

	// commitment
	keys := make([]string, 0, len(view.mapCommitments))
	for k := range view.mapCommitments {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		pubkey := k
		item1 := view.mapCommitments[k]
		pubkeyBytes, _, err := base58.Base58Check{}.Decode(pubkey)
		if err != nil {
			return err
		}
		lastByte := pubkeyBytes[len(pubkeyBytes)-1]
		pubkeyShardID := common.GetShardIDFromLastByte(lastByte)
		if pubkeyShardID == view.shardID {
			err = blockchain.config.DataBase.RestoreCommitmentsOfPubkey(*view.tokenID, view.shardID, pubkeyBytes, item1)
			if err != nil {
				return err
			}
		}
	}

	// outputs
	for _, k := range keys {
		publicKey := k
		publicKeyBytes, _, err := base58.Base58Check{}.Decode(publicKey)
		if err != nil {
			return err
		}
		lastByte := publicKeyBytes[len(publicKeyBytes)-1]
		publicKeyShardID := common.GetShardIDFromLastByte(lastByte)
		if publicKeyShardID == shardID {
			outputCoinArray := view.mapOutputCoins[k]
			outputCoinBytesArray := make([][]byte, 0)
			for _, outputCoin := range outputCoinArray {
				outputCoinBytesArray = append(outputCoinBytesArray, outputCoin.Bytes())
			}
			err = blockchain.config.DataBase.DeleteOutputCoin(*view.tokenID, publicKeyBytes, outputCoinBytesArray, publicKeyShardID)
			if err != nil {
				return err
			}
		}
	}
	return nil
}