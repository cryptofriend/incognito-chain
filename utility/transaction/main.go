package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/incognitochain/incognito-chain/database"
	_ "github.com/incognitochain/incognito-chain/database/lvdb"
	"github.com/incognitochain/incognito-chain/transaction"
	"github.com/incognitochain/incognito-chain/wallet"
)

func main() {
	// init an ico tx for ico account
	initTx()
}

func initTx() {
	db, err := database.Open("leveldb", filepath.Join("./", "./"))
	if err != nil {
		fmt.Print("could not open connection to leveldb")
		fmt.Print(err)
		panic(err)
	}
	var initTxs []string
	var initAmount, _ = strconv.Atoi(os.Args[1]) // amount init
	var privateKey = os.Args[2]                  // spending key str
	testUserkeyList := []string{
		privateKey,
	}
	for _, val := range testUserkeyList {

		testUserKey, _ := wallet.Base58CheckDeserialize(val)
		testUserKey.KeySet.InitFromPrivateKey(&testUserKey.KeySet.PrivateKey)

		testSalaryTX := transaction.Tx{}
		testSalaryTX.InitTxSalary(uint64(initAmount), &testUserKey.KeySet.PaymentAddress, &testUserKey.KeySet.PrivateKey,
			db,
			nil,
		)
		initTx, _ := json.MarshalIndent(testSalaryTX, "", "  ")
		initTxs = append(initTxs, string(initTx))
	}
	fmt.Println(initTxs)
}
