package rpcserver

import (
	"errors"
	"github.com/incognitochain/incognito-chain/blockchain"
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/pubsub"
	"github.com/incognitochain/incognito-chain/rpcserver/jsonresult"
	"reflect"
)

func (wsServer *WsServer) handleSubscribePendingTransaction(params interface{}, subcription string, cResult chan RpcSubResult, closeChan <-chan struct{}) {
	Logger.log.Info("Handle Subcribe Pending Transaction", params, subcription)
	arrayParams := common.InterfaceSlice(params)
	if len(arrayParams) != 1 {
		err := NewRPCError(ErrRPCInvalidParams, errors.New("Methods should only contain 1 params"))
		cResult <- RpcSubResult{Error: err}
		return
	}
	txHashTemp, ok := arrayParams[0].(string)
	if !ok {
		err := NewRPCError(ErrRPCInvalidParams, errors.New("Invalid Tx Hash"))
		cResult <- RpcSubResult{Error: err}
	}
	txHash, _ := common.Hash{}.NewHashFromStr(txHashTemp)
	// try to get transaction in database
	_, blockHash, index, tx, err := wsServer.config.BlockChain.GetTransactionByHash(*txHash)
	if err == nil {
		shardBlock, _, err := wsServer.config.BlockChain.GetShardBlockByHash(blockHash)
		if err == nil {
			res, err := (&HttpServer{}).revertTxToResponseObject(tx, shardBlock.Hash(), shardBlock.Header.Height, index, shardBlock.Header.ShardID)
			cResult <- RpcSubResult{Result: res, Error: err}
			return
		}
	}
	// transaction not in database yet then subscribe new shard event block and watch
	subId, subChan, err := wsServer.config.PubSubManager.RegisterNewSubscriber(pubsub.NewShardblockTopic)
	if err != nil {
		err := NewRPCError(ErrSubcribe, err)
		cResult <- RpcSubResult{Error: err}
		return
	}
	defer func() {
		Logger.log.Info("Finish Subscribe New Pending Transaction ", txHashTemp)
		wsServer.config.PubSubManager.Unsubscribe(pubsub.NewShardblockTopic, subId)
		close(cResult)
	}()
	for {
		select {
		case msg := <-subChan:
			{
				shardBlock, ok := msg.Value.(*blockchain.ShardBlock)
				if !ok {
					Logger.log.Errorf("Wrong Message Type from Pubsub Manager, wanted *blockchain.ShardBlock, have %+v", reflect.TypeOf(msg.Value))
					continue
				}
				for index, tx := range shardBlock.Body.Transactions {
					if tx.Hash().IsEqual(txHash) {
						res, err := (&HttpServer{}).revertTxToResponseObject(tx, shardBlock.Hash(), shardBlock.Header.Height, index, shardBlock.Header.ShardID)
						cResult <- RpcSubResult{Result: res, Error: err}
						return
					}
				}

			}
		case <-closeChan:
			{
				cResult <- RpcSubResult{Result: jsonresult.UnsubcribeResult{Message: "Unsubscribe Pending Transaction " + txHashTemp}}
				return
			}
		}
	}
}
