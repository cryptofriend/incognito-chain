package blockchain

import (
	"strconv"
	"strings"
	"time"

	"github.com/incognitochain/incognito-chain/common"
)

func CreateBeaconGenesisBlock(
	version int,
	genesisParams GenesisParams,
) *BeaconBlock {
	inst := [][]string{}
	// build validator beacon
	// test generate public key in utility/generateKeys
	beaconAssingInstruction := []string{StakeAction}
	beaconAssingInstruction = append(beaconAssingInstruction, strings.Join(genesisParams.PreSelectBeaconNodeSerializedPubkey[:], ","))
	beaconAssingInstruction = append(beaconAssingInstruction, "beacon")

	shardAssingInstruction := []string{StakeAction}
	shardAssingInstruction = append(shardAssingInstruction, strings.Join(genesisParams.PreSelectShardNodeSerializedPubkey[:], ","))
	shardAssingInstruction = append(shardAssingInstruction, "shard")

	inst = append(inst, beaconAssingInstruction)
	inst = append(inst, shardAssingInstruction)

	// init network param
	inst = append(inst, []string{SetAction, "randomnumber", strconv.Itoa(int(0))})

	body := BeaconBody{ShardState: nil, Instructions: inst}
	header := BeaconHeader{
		Timestamp:                       time.Date(2018, 8, 1, 0, 0, 0, 0, time.UTC).Unix(),
		Height:                          1,
		Version:                         1,
		Round:                           1,
		Epoch:                           1,
		PreviousBlockHash:               common.Hash{},
		BeaconCommitteeAndValidatorRoot: common.Hash{},
		BeaconCandidateRoot:             common.Hash{},
		ShardCandidateRoot:              common.Hash{},
		ShardCommitteeAndValidatorRoot:  common.Hash{},
		ShardStateHash:                  common.Hash{},
		InstructionHash:                 common.Hash{},
	}

	block := &BeaconBlock{
		Body:   body,
		Header: header,
	}

	return block
}
