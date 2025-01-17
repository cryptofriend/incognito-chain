// Copyright (c) 2014-2016 The thaibaoautonomous developers
// Use of this source Code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"

	"github.com/pkg/errors"
)

const (
	UnExpectedError = iota
	UpdateMerkleTreeForBlockError
	UnmashallJsonShardBlockError
	MashallJsonShardBlockError
	UnmashallJsonShardBestStateError
	MashallJsonShardBestStateError
	UnmashallJsonBeaconBlockError
	MashallJsonBeaconBlockError
	UnmashallJsonBeaconBestStateError
	MashallJsonBeaconBestStateError
	MashallJsonError
	CanNotCheckDoubleSpendError
	HashError
	WrongVersionError
	WrongBlockHeightError
	DatabaseError
	EpochError
	WrongTimestampError
	InstructionHashError
	ShardStateHashError
	RandomError
	VerificationError
	ShardError
	BeaconError
	SignatureError
	CrossShardBlockError
	CandidateError
	ShardIDError
	ProducerError
	ShardStateError
	TransactionFromNewBlockError
	GenerateInstructionError
	SwapError
	DuplicateShardBlockError
	CommitteeOrValidatorError
	ShardBlockSanityError
	StoreIncomingCrossShardError
	DeleteIncomingCrossShardError
	WrongShardIDError
	CloneShardBestStateError
	CloneBeaconBestStateError
	ShardBestStateNotCompatibleError
	RegisterEstimatorFeeError
	FetchPreviousBlockError
	TransactionRootHashError
	ShardTransactionRootHashError
	CrossShardTransactionRootHashError
	FetchBeaconBlocksError
	WrongBlockTotalFeeError
	ShardIntructionFromTransactionAndInstructionError
	InstructionsHashError
	FlattenAndConvertStringInstError
	InstructionMerkleRootError
	FetchBeaconBlockHashError
	FetchBeaconBlockError
	BeaconBlockNotCompatibleError
	SwapInstructionError
	TransactionCreatedByMinerError
	ResponsedTransactionWithMetadataError
	UnmashallJsonShardCommitteesError
	MashallJsonShardCommitteesError
	VerifyCrossShardBlockError
	NextCrossShardBlockError
	FetchShardCommitteeError
	CrossTransactionHashError
	VerifyCrossShardCustomTokenError
	ShardCommitteeRootHashError
	ShardPendingValidatorRootHashError
	BeaconCommitteeAndPendingValidatorRootError
	ShardCommitteeAndPendingValidatorRootError
	ShardCandidateRootError
	BeaconCandidateRootError
	StoreShardBlockError
	StoreBestStateError
	FetchAndStoreTransactionError
	FetchAndStoreCrossTransactionError
	RemoveCommitteeRewardError
	StoreBurningConfirmError
	SwapValidatorError
	CrossShardBitMapError
	ShardCommitteeLengthAndCommitteeIndexError
	UpdateBridgeIssuanceStatusError
	BeaconCommitteeLengthAndCommitteeIndexError
	BuildRewardInstructionError
	GenerateBeaconCommitteeAndValidatorRootError
	GenerateShardCommitteeAndValidatorRootError
	GenerateBeaconCandidateRootError
	GenerateShardCandidateRootError
	GenerateShardStateError
	GenerateShardCommitteeError
	GenerateShardPendingValidatorError
	ProduceSignatureError
	BeaconBestStateBestBlockNotCompatibleError
	BeaconBlockProducerError
	BeaconBlockSignatureError
	WrongEpochError
	GenerateInstructionHashError
	GetShardBlocksError
	ShardStateHeightError
	ShardStateCrossShardBitMapError
	ShardBlockSignatureError
	ShardBestStateBeaconHeightNotCompatibleError
	BeaconBestStateBestShardHeightNotCompatibleError
	ProcessRandomInstructionError
	ProcessSwapInstructionError
	AssignValidatorToShardError
	ShuffleBeaconCandidateError
	CleanBackUpError
	BackUpBestStateError
	StoreAcceptedShardToBeaconError
	StoreCrossShardNextHeightError
	StoreShardCommitteeByHeightError
	StoreBeaconCommitteeByHeightError
	StoreBeaconBestStateError
	StoreBeaconBlockError
	StoreBeaconBlockIndexError
	StoreCommitteeFromShardBestStateError
	ProcessBridgeInstructionError
	UpdateDatabaseWithBlockRewardInfoError
	CreateCrossShardBlockError
	VerifyCrossShardBlockShardTxRootError
)

var ErrCodeMessage = map[int]struct {
	Code    int
	message string
}{
	UnExpectedError:                                   {-1000, "Unexpected error"},
	UpdateMerkleTreeForBlockError:                     {-1001, "updateShardBestState Merkle Commitments Tree For Block is failed"},
	UnmashallJsonShardBlockError:                      {-1002, "Unmarshall Json Shard Block Is Failed"},
	MashallJsonShardBlockError:                        {-1003, "Marshall Json Shard Block Is Failed"},
	UnmashallJsonShardBestStateError:                  {-1004, "Unmarshall Json Shard Best State Is Failed"},
	MashallJsonShardBestStateError:                    {-1005, "Marshall Json Shard Best State Is Failed"},
	UnmashallJsonBeaconBlockError:                     {-1006, "Unmarshall Json Beacon Block Is Failed"},
	MashallJsonBeaconBlockError:                       {-1007, "Marshall Json Beacon Block Is Failed"},
	UnmashallJsonBeaconBestStateError:                 {-1008, "Unmarshall Json Beacon Best State Is Failed"},
	MashallJsonBeaconBestStateError:                   {-1009, "Marshall Json Beacon Best State Is Failed"},
	CanNotCheckDoubleSpendError:                       {-1010, "CanNotCheckDoubleSpend Error"},
	HashError:                                         {-1011, "Hash error"},
	WrongVersionError:                                 {-1012, "Version error"},
	WrongBlockHeightError:                             {-1013, "Wrong Block Height Error"},
	DatabaseError:                                     {-1014, "Database Error"},
	EpochError:                                        {-1015, "Epoch Error"},
	WrongTimestampError:                               {-1016, "Timestamp Error"},
	InstructionHashError:                              {-1017, "Instruction Hash Error"},
	ShardStateHashError:                               {-1018, "ShardState Hash Error"},
	RandomError:                                       {-1019, "Random Number Error"},
	VerificationError:                                 {-1020, "Verify Block Error"},
	BeaconError:                                       {-1021, "Beacon Error"},
	CrossShardBlockError:                              {-1022, "CrossShardBlockError"},
	SignatureError:                                    {-1023, "Signature Error"},
	CandidateError:                                    {-1024, "Candidate Error"},
	ShardIDError:                                      {-1025, "ShardID Error"},
	ProducerError:                                     {-1026, "Producer Error"},
	ShardStateError:                                   {-1027, "Shard State Error"},
	TransactionFromNewBlockError:                      {-1028, "Transaction invalid"},
	GenerateInstructionError:                          {-1029, "Instruction Error"},
	SwapError:                                         {-1030, "Swap Error"},
	MashallJsonError:                                  {-1031, "MashallJson Error"},
	DuplicateShardBlockError:                          {-1032, "Duplicate Shard Block Error"},
	CommitteeOrValidatorError:                         {-1033, "Committee or Validator Error"},
	ShardBlockSanityError:                             {-1034, "Shard Block Sanity Data Error"},
	StoreIncomingCrossShardError:                      {-1035, "Store Incoming Cross Shard Block Error"},
	DeleteIncomingCrossShardError:                     {-1036, "Delete Incoming Cross Shard Block Error"},
	WrongShardIDError:                                 {-1037, "Wrong Shard ID Error"},
	CloneShardBestStateError:                          {-1038, "Clone Shard Best State Error"},
	CloneBeaconBestStateError:                         {-1039, "Clone Beacon Best State Error"},
	ShardBestStateNotCompatibleError:                  {-1040, "New Block and Shard Best State Is NOT Compatible"},
	RegisterEstimatorFeeError:                         {-1041, "Register Fee Estimator Error"},
	FetchPreviousBlockError:                           {-1042, "Failed To Fetch Previous Block Error"},
	TransactionRootHashError:                          {-1043, "Transaction Root Hash Error"},
	ShardTransactionRootHashError:                     {-1044, "Shard Transaction Root Hash Error"},
	CrossShardTransactionRootHashError:                {-1045, "Cross Shard Transaction Root Hash Error"},
	FetchBeaconBlocksError:                            {-1046, "Fetch Beacon Blocks Error"},
	FetchBeaconBlockHashError:                         {-1047, "Fetch Beacon Block Hash Error"},
	FetchBeaconBlockError:                             {-1048, "Fetch Beacon Block Error"},
	WrongBlockTotalFeeError:                           {-1049, "Wrong Block Total Fee Error"},
	ShardIntructionFromTransactionAndInstructionError: {-1050, "Shard Instruction From Transaction And Instruction Error"},
	InstructionsHashError:                             {-1051, "Instruction Hash Error"},
	FlattenAndConvertStringInstError:                  {-1052, "Flatten And Convert String Instruction Error"},
	InstructionMerkleRootError:                        {-1053, "Instruction Merkle Root Error"},
	BeaconBlockNotCompatibleError:                     {-1054, "Beacon Block Not Compatible Error"},
	SwapInstructionError:                              {-1055, "Swap Instruction Error"},
	TransactionCreatedByMinerError:                    {-1056, "Transaction Created By Miner Error"},
	ResponsedTransactionWithMetadataError:             {-1057, "Responsed Transaction With Metadata Error"},
	UnmashallJsonShardCommitteesError:                 {-1058, "Unmashall Json Shard Committees Error"},
	MashallJsonShardCommitteesError:                   {-1059, "Mashall Json Shard Committees Error"},
	VerifyCrossShardBlockError:                        {-1060, "Verify Cross Shard Block Error"},
	NextCrossShardBlockError:                          {-1061, "Next Cross Shard Block Error"},
	FetchShardCommitteeError:                          {-1062, "Fetch Shard Committee Error"},
	CrossTransactionHashError:                         {-1063, "Cross Transaction Hash Error"},
	VerifyCrossShardCustomTokenError:                  {-1064, "Verify Cross Shard Custom Token Error"},
	ShardCommitteeRootHashError:                       {-1065, "Shard Committee Root Hash Error"},
	ShardPendingValidatorRootHashError:                {-1066, "Shard Pending Validator Root Hash Error"},
	StoreShardBlockError:                              {-1067, "Store Shard Block Error"},
	StoreBestStateError:                               {-1068, "Store Shard Shard Best State Error"},
	FetchAndStoreTransactionError:                     {-1069, "Fetch And Store Transaction Error"},
	FetchAndStoreCrossTransactionError:                {-1070, "Fetch And Store Cross Transaction Error"},
	RemoveCommitteeRewardError:                        {-1071, "Remove Committee Reward Error"},
	StoreBurningConfirmError:                          {-1072, "Store Burning Confirm Error"},
	SwapValidatorError:                                {-1073, "Swap Validator Error"},
	CrossShardBitMapError:                             {-1074, "Cross Shard Bitmap Error"},
	ShardCommitteeLengthAndCommitteeIndexError:        {-1075, "Shard Committee Length And Committee Index Error"},
	BuildRewardInstructionError:                       {-1076, "Build Reward Transaction Error"},
	GenerateBeaconCommitteeAndValidatorRootError:      {-1077, "Generate Beacon Committee And Validator Root Error"},
	GenerateShardCommitteeAndValidatorRootError:       {-1078, "Generate Shard Committee And Validator Root Error"},
	GenerateBeaconCandidateRootError:                  {-1079, "Generate Beacon Candidate Root Error"},
	GenerateShardCandidateRootError:                   {-1080, "Generate Shard Candidate Root Error"},
	GenerateShardStateError:                           {-1081, "Generate Shard State Error"},
	GenerateShardCommitteeError:                       {-1082, "Generate Shard Committee Root Error"},
	GenerateShardPendingValidatorError:                {-1083, "Generate Shard Pending Validator Root Error"},
	ProduceSignatureError:                             {-1084, "Produce Signature Error"},
	BeaconBestStateBestBlockNotCompatibleError:        {-1085, "New Beacon Block and Beacon Best State Is NOT Compatible"},
	BeaconBlockProducerError:                          {-1086, "Beacon Block Producer Error"},
	BeaconBlockSignatureError:                         {-1087, "Beacon Block Signature Error"},
	WrongEpochError:                                   {-1088, "Wrong Epoch Error"},
	GenerateInstructionHashError:                      {-1089, "Generate Instruction Hash Error"},
	ShardStateHeightError:                             {-1090, "Generate Instruction Hash Error"},
	ShardStateCrossShardBitMapError:                   {-1091, "Shard State Cross Shard BitMap Error"},
	BeaconCommitteeLengthAndCommitteeIndexError:       {-1092, "Shard Committee Length And Committee Index Error"},
	ShardBlockSignatureError:                          {-1093, "Shard Block Signature Error"},
	ShardBestStateBeaconHeightNotCompatibleError:      {-1094, "Shard BestState Beacon Height Not Compatible Error"},
	BeaconBestStateBestShardHeightNotCompatibleError:  {-1095, "Beacon BestState Best Shard Height Not Compatible Error"},
	BeaconCommitteeAndPendingValidatorRootError:       {-1096, "Beacon Committee And Pending Validator Root Hash Error"},
	ShardCommitteeAndPendingValidatorRootError:        {-1097, "Shard Committee And Pending Validator Root Hash Error"},
	ShardCandidateRootError:                           {-1098, "Shard Candidate Root Hash Error"},
	ProcessRandomInstructionError:                     {-1100, "Process Random Instruction Error"},
	ProcessSwapInstructionError:                       {-1101, "Process Swap Instruction Error"},
	AssignValidatorToShardError:                       {-1102, "Assign Validator To Shard Error"},
	ShuffleBeaconCandidateError:                       {-1103, "Shuffle Beacon Candidate Error"},
	CleanBackUpError:                                  {-1104, "Clean Back Up Error"},
	BackUpBestStateError:                              {-1105, "Back Up Best State Error"},
	ProcessBridgeInstructionError:                     {-1106, "Process Bridge Instruction Error"},
	UpdateDatabaseWithBlockRewardInfoError:            {-1107, "Update Database With Block Reward Info Error"},
	CreateCrossShardBlockError:                        {-1108, "Create Cross Shard Block Error"},
	VerifyCrossShardBlockShardTxRootError:             {-1109, "Verify Cross Shard Block ShardTxRoot Error"},
}

type BlockChainError struct {
	Code    int
	Message string
	err     error
}

func (e BlockChainError) Error() string {
	return fmt.Sprintf("%d: %s \n %+v", e.Code, e.Message, e.err)
}

func NewBlockChainError(key int, err error) *BlockChainError {
	return &BlockChainError{
		Code:    ErrCodeMessage[key].Code,
		Message: ErrCodeMessage[key].message,
		err:     errors.Wrap(err, ErrCodeMessage[key].message),
	}
}
