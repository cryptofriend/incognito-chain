package lvdb

import (
	"bytes"
	"encoding/binary"
	"math/big"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/database"
	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb/util"
)

func getPrevPrefix(isBeacon bool, shardID byte) []byte {
	key := []byte{}
	if isBeacon {
		key = append(key, prevBeaconPrefix...)
	} else {
		key = append(key, append(prevShardPrefix, append([]byte{shardID}, byte('-'))...)...)
	}
	return key
}

func (db *db) StorePrevBestState(val []byte, isBeacon bool, shardID byte) error {
	key := getPrevPrefix(isBeacon, shardID)
	if err := db.Put(key, val); err != nil {
		return database.NewDatabaseError(database.UnexpectedError, errors.Wrap(err, "db.put"))
	}
	return nil
}

func (db *db) FetchPrevBestState(isBeacon bool, shardID byte) ([]byte, error) {
	key := getPrevPrefix(isBeacon, shardID)
	beststate, err := db.lvdb.Get(key, nil)
	if err != nil {
		return nil, database.NewDatabaseError(database.UnexpectedError, errors.Wrap(err, "db.get"))
	}
	return beststate, nil
}

func (db *db) CleanBackup(isBeacon bool, shardID byte) error {
	iter := db.lvdb.NewIterator(util.BytesPrefix(getPrevPrefix(isBeacon, shardID)), nil)
	for iter.Next() {
		err := db.Delete(iter.Key())
		if err != nil {
			return database.NewDatabaseError(database.UnexpectedError, errors.Wrap(err, "db.lvdb.Delete"))
		}
	}
	iter.Release()
	return nil
}

func (db *db) BackupCommitmentsOfPubkey(tokenID common.Hash, shardID byte, pubkey []byte) error {
	//backup keySpec3 & keySpec4
	prevkey := getPrevPrefix(false, shardID)
	key := db.GetKey(string(commitmentsPrefix), tokenID)
	key = append(key, shardID)

	keySpec3 := append(key, []byte("len")...)
	backupKeySpec3 := append(prevkey, keySpec3...)
	res, err := db.Get(keySpec3)
	if err != nil {
		if err.(*database.DatabaseError).GetErrorCode() != database.ErrCodeMessage[database.LvDbNotFound].Code {
			return database.NewDatabaseError(database.UnexpectedError, errors.Wrap(err, "db.lvdb.Get"))
		}
		return nil
	}

	if err := db.Put(backupKeySpec3, res); err != nil {
		return err
	}

	return nil
}

func (db *db) RestoreCommitmentsOfPubkey(tokenID common.Hash, shardID byte, pubkey []byte, commitments [][]byte) error {
	// restore keySpec3 & keySpec4
	// delete keySpec1 & keySpec2
	prevkey := getPrevPrefix(false, shardID)
	key := db.GetKey(string(commitmentsPrefix), tokenID)
	key = append(key, shardID)

	var lenData uint64
	len, err := db.GetCommitmentLength(tokenID, shardID)
	if err != nil && len == nil {
		return err
	}
	if len == nil {
		lenData = 0
	} else {
		lenData = len.Uint64()
	}
	for _, c := range commitments {
		newIndex := new(big.Int).SetUint64(lenData).Bytes()
		if lenData == 0 {
			newIndex = []byte{0}
		}
		keySpec1 := append(key, newIndex...)
		db.Delete(keySpec1)

		keySpec2 := append(key, c...)
		db.Delete(keySpec2)
		lenData++
	}

	// keySpec3 store last index of array commitment
	keySpec3 := append(key, []byte("len")...)
	backupKeySpec3 := append(prevkey, keySpec3...)
	res, err := db.Get(backupKeySpec3)
	if err != nil {
		if err.(*database.DatabaseError).GetErrorCode() != database.ErrCodeMessage[database.LvDbNotFound].Code {
			return database.NewDatabaseError(database.UnexpectedError, errors.Wrap(err, "db.lvdb.Get"))
		}
		if err := db.Delete(keySpec3); err != nil {
			return err
		}
	}

	if err := db.Put(keySpec3, res); err != nil {
		return err
	}

	return nil
}

func (db *db) DeleteOutputCoin(tokenID common.Hash, publicKey []byte, outputCoinArr [][]byte, shardID byte) error {
	key := db.GetKey(string(outcoinsPrefix), tokenID)
	key = append(key, shardID)

	key = append(key, publicKey...)
	for _, outputCoin := range outputCoinArr {
		keyTemp := append(key, common.HashB(outputCoin)...)
		if err := db.Delete(keyTemp); err != nil {
			return err
		}
	}

	return nil
}

func (db *db) BackupSerialNumbersLen(tokenID common.Hash, shardID byte) error {
	current := db.GetKey(string(serialNumbersPrefix), tokenID)
	current = append(current, shardID)
	current = append(current, []byte("len")...)
	res, err := db.Get(current)
	if err != nil {
		if err.(*database.DatabaseError).GetErrorCode() != database.ErrCodeMessage[database.LvDbNotFound].Code {
			return database.NewDatabaseError(database.LvDbNotFound, errors.Wrap(err, "db.lvdb.Get"))
		}
		return nil
	}
	key := getPrevPrefix(false, shardID)
	key = append(key, current...)
	if err := db.Put(key, res); err != nil {
		return err
	}
	return nil
}

func (db *db) RestoreSerialNumber(tokenID common.Hash, shardID byte, serialNumbers [][]byte) error {
	key := db.GetKey(string(serialNumbersPrefix), tokenID)
	key = append(key, shardID)
	currentLenKey := append(key, []byte("len")...)
	prevLenKey := getPrevPrefix(false, shardID)
	prevLenKey = append(prevLenKey, currentLenKey...)

	prevLen, err := db.Get(prevLenKey)
	if err != nil && err.(*database.DatabaseError).GetErrorCode() != database.ErrCodeMessage[database.LvDbNotFound].Code {
		return database.NewDatabaseError(database.UnexpectedError, errors.Wrap(err, "db.lvdb.Get"))
	}
	if err := db.Put(currentLenKey, prevLen); err != nil {
		return err
	}

	for _, s := range serialNumbers {
		keySpec1 := append(key, s...)
		err = db.Delete(keySpec1)
		if err != nil {
			return err
		}
	}

	return nil
}

func (db *db) DeleteTransactionIndex(txId common.Hash) error {
	key := string(transactionKeyPrefix) + txId.String()
	err := db.Delete([]byte(key))
	if err != nil {
		return database.NewDatabaseError(database.UnexpectedError, err)
	}
	return nil

}

func (db *db) DeleteCustomToken(tokenID common.Hash) error {
	key := db.GetKey(string(tokenInitPrefix), tokenID)
	err := db.Delete(key)
	if err != nil {
		return err
	}
	return nil
}

func (db *db) DeleteCustomTokenTx(tokenID common.Hash, txIndex int32, shardID byte, blockHeight uint64) error {
	key := db.GetKey(string(TokenPrefix), tokenID)
	key = append(key, shardID)
	bs := make([]byte, 8)
	binary.LittleEndian.PutUint64(bs, bigNumber-blockHeight)
	key = append(key, bs...)
	bs = make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(bigNumber-txIndex))
	key = append(key, bs...)
	err := db.Delete(key)
	if err != nil {
		return err
	}
	return nil
}

func (db *db) DeletePrivacyCustomToken(tokenID common.Hash) error {
	key := db.GetKey(string(privacyTokenInitPrefix), tokenID)
	err := db.Delete(key)
	if err != nil {
		return err
	}
	return nil
}

func (db *db) DeletePrivacyCustomTokenTx(tokenID common.Hash, txIndex int32, shardID byte, blockHeight uint64) error {
	key := db.GetKey(string(PrivacyTokenPrefix), tokenID)
	key = append(key, shardID)
	bs := make([]byte, 8)
	binary.LittleEndian.PutUint64(bs, bigNumber-blockHeight)
	key = append(key, bs...)
	bs = make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(bigNumber-txIndex))
	key = append(key, bs...)
	err := db.Delete(key)
	if err != nil {
		return err
	}
	return nil
}

func (db *db) DeletePrivacyCustomTokenCrossShard(tokenID common.Hash) error {
	key := db.GetKey(string(PrivacyTokenCrossShardPrefix), tokenID)
	err := db.Delete(key)
	if err != nil {
		return err
	}
	return nil
}

func (db *db) RestoreCrossShardNextHeights(fromShard byte, toShard byte, curHeight uint64) error {
	key := append(nextCrossShardKeyPrefix, fromShard)
	key = append(key, []byte("-")...)
	key = append(key, toShard)
	key = append(key, []byte("-")...)
	curHeightBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(curHeightBytes, curHeight)
	heightKey := append(key, curHeightBytes...)
	for {
		nextHeightBytes, err := db.Get(heightKey)
		if err != nil && err.(*database.DatabaseError).GetErrorCode() != database.ErrCodeMessage[database.LvDbNotFound].Code {
			return database.NewDatabaseError(database.UnexpectedError, errors.Wrap(err, "db.lvdb.Get"))
		}
		err = db.Delete(heightKey)
		if err != nil {
			return err
		}

		var nextHeight uint64
		binary.Read(bytes.NewReader(nextHeightBytes[:8]), binary.LittleEndian, &nextHeight)

		if nextHeight == 0 {
			break
		}
		heightKey = append(key, nextHeightBytes...)
	}
	nextHeightBytes := make([]byte, 8)
	heightKey = append(key, curHeightBytes...)
	if err := db.Put(heightKey, nextHeightBytes); err != nil {
		return err
	}
	return nil
}

func (db *db) DeleteCommitteeByHeight(blkEpoch uint64) error {
	key := append(beaconPrefix, shardIDPrefix...)
	key = append(key, committeePrefix...)
	key = append(key, heightPrefix...)
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, blkEpoch)
	key = append(key, buf[:]...)
	err := db.Delete(key)
	if err != nil {
		return err
	}
	return nil
}

func (db *db) DeleteAcceptedShardToBeacon(shardID byte, shardBlkHash common.Hash) error {
	prefix := append([]byte{shardID}, shardBlkHash[:]...)
	key := append(shardToBeaconKeyPrefix, prefix...)
	if err := db.Delete(key); err != nil {
		return nil
	}
	return nil
}

func (db *db) DeleteIncomingCrossShard(shardID byte, crossShardID byte, crossBlkHash common.Hash) error {
	prefix := append([]byte{shardID}, append([]byte{crossShardID}, crossBlkHash[:]...)...)
	// csh-ShardID-CrossShardID-CrossShardBlockHash : ShardBlockHeight
	key := append(crossShardKeyPrefix, prefix...)
	if err := db.Delete(key); err != nil {
		return err
	}
	return nil
}

func (db *db) BackupBridgedTokenByTokenID(tokenID common.Hash) error {
	key := append(centralizedBridgePrefix, tokenID[:]...)
	backupKey := getPrevPrefix(true, 0)
	backupKey = append(backupKey, key...)
	tokenWithAmtBytes, dbErr := db.lvdb.Get(key, nil)
	if dbErr != nil {
		if err := db.Put(backupKey, []byte{}); err != nil {
			return err
		}
	} else {
		if err := db.Put(backupKey, tokenWithAmtBytes); err != nil {
			return err
		}
	}
	return nil
}

func (db *db) RestoreBridgedTokenByTokenID(tokenID common.Hash) error {
	key := append(centralizedBridgePrefix, tokenID[:]...)
	backupKey := getPrevPrefix(true, 0)
	backupKey = append(backupKey, key...)

	tokenWithAmtBytes, dbErr := db.Get(backupKey)
	if dbErr != nil && dbErr.(*database.DatabaseError).GetErrorCode() != database.ErrCodeMessage[database.LvDbNotFound].Code {
		return database.NewDatabaseError(database.UnexpectedError, errors.Wrap(dbErr, "db.lvdb.Get"))
	}

	if err := db.Put(key, tokenWithAmtBytes); err != nil {
		return err
	}
	return nil
}

// REWARD

func (db *db) BackupShardRewardRequest(epoch uint64, shardID byte, tokenID common.Hash) error {
	backupKey := getPrevPrefix(true, 0)
	key, err := NewKeyAddShardRewardRequest(epoch, shardID, tokenID)
	if err != nil {
		return err
	}
	backupKey = append(backupKey, key...)
	curValue, err := db.lvdb.Get(key, nil)
	if err != nil {
		err := db.Put(backupKey, common.Uint64ToBytes(0))
		if err != nil {
			return err
		}
	} else {
		err := db.Put(backupKey, curValue)
		if err != nil {
			return err
		}
	}

	return nil
}
func (db *db) BackupCommitteeReward(committeeAddress []byte, tokenID common.Hash) error {
	backupKey := getPrevPrefix(true, 0)
	key, err := NewKeyAddCommitteeReward(committeeAddress, tokenID)
	if err != nil {
		return err
	}
	backupKey = append(backupKey, key...)
	curValue, err := db.lvdb.Get(key, nil)
	if err != nil {
		err := db.Put(backupKey, common.Uint64ToBytes(0))
		if err != nil {
			return err
		}
	} else {
		err := db.Put(backupKey, curValue)
		if err != nil {
			return err
		}
	}

	return nil
}
func (db *db) RestoreShardRewardRequest(epoch uint64, shardID byte, tokenID common.Hash) error {
	backupKey := getPrevPrefix(true, 0)
	key, err := NewKeyAddShardRewardRequest(epoch, shardID, tokenID)
	if err != nil {
		return err
	}
	backupKey = append(backupKey, key...)
	bakValue, err := db.lvdb.Get(backupKey, nil)
	if err != nil {
		return err
	}
	err = db.Put(key, bakValue)
	if err != nil {
		return err
	}

	return nil
}
func (db *db) RestoreCommitteeReward(committeeAddress []byte, tokenID common.Hash) error {
	backupKey := getPrevPrefix(true, 0)
	key, err := NewKeyAddCommitteeReward(committeeAddress, tokenID)
	if err != nil {
		return err
	}
	backupKey = append(backupKey, key...)
	bakValue, err := db.lvdb.Get(backupKey, nil)
	if err != nil {
		return err
	}
	err = db.Put(key, bakValue)
	if err != nil {
		return err
	}

	return nil
}
