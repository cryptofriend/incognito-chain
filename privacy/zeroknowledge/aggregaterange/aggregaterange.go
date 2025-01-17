package aggregaterange

import (
	"github.com/pkg/errors"
	"math/big"
	"sync"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/privacy"
)

// This protocol proves in zero-knowledge that a list of committed values falls in [0, 2^64)

type AggregatedRangeWitness struct {
	values []*big.Int
	rands  []*big.Int
}

type AggregatedRangeProof struct {
	cmsValue          []*privacy.EllipticPoint
	a                 *privacy.EllipticPoint
	s                 *privacy.EllipticPoint
	t1                *privacy.EllipticPoint
	t2                *privacy.EllipticPoint
	tauX              *big.Int
	tHat              *big.Int
	mu                *big.Int
	innerProductProof *InnerProductProof
}

func (proof AggregatedRangeProof) ValidateSanity() bool {
	for i := 0; i < len(proof.cmsValue); i++ {
		if !proof.cmsValue[i].IsSafe() {
			return false
		}
	}
	if !proof.a.IsSafe() {
		return false
	}
	if !proof.s.IsSafe() {
		return false
	}
	if !proof.t1.IsSafe() {
		return false
	}
	if !proof.t2.IsSafe() {
		return false
	}
	if proof.tauX.BitLen() > 256 {
		return false
	}
	if proof.tHat.BitLen() > 256 {
		return false
	}
	if proof.mu.BitLen() > 256 {
		return false
	}

	return proof.innerProductProof.ValidateSanity()
}

func (proof *AggregatedRangeProof) Init() {
	proof.a = new(privacy.EllipticPoint)
	proof.a.Zero()
	proof.s = new(privacy.EllipticPoint)
	proof.s.Zero()
	proof.t1 = new(privacy.EllipticPoint)
	proof.t1.Zero()
	proof.t2 = new(privacy.EllipticPoint)
	proof.t2.Zero()
	proof.tauX = new(big.Int)
	proof.tHat = new(big.Int)
	proof.mu = new(big.Int)
	proof.innerProductProof = new(InnerProductProof)
}

func (proof AggregatedRangeProof) IsNil() bool {
	if proof.a == nil {
		return true
	}
	if proof.s == nil {
		return true
	}
	if proof.t1 == nil {
		return true
	}
	if proof.t2 == nil {
		return true
	}
	if proof.tauX == nil {
		return true
	}
	if proof.tHat == nil {
		return true
	}
	if proof.mu == nil {
		return true
	}
	return proof.innerProductProof == nil
}

func (proof AggregatedRangeProof) Bytes() []byte {
	var res []byte

	if proof.IsNil() {
		return []byte{}
	}

	res = append(res, byte(len(proof.cmsValue)))
	for i := 0; i < len(proof.cmsValue); i++ {
		res = append(res, proof.cmsValue[i].Compress()...)
	}

	res = append(res, proof.a.Compress()...)
	res = append(res, proof.s.Compress()...)
	res = append(res, proof.t1.Compress()...)
	res = append(res, proof.t2.Compress()...)

	res = append(res, common.AddPaddingBigInt(proof.tauX, common.BigIntSize)...)
	res = append(res, common.AddPaddingBigInt(proof.tHat, common.BigIntSize)...)
	res = append(res, common.AddPaddingBigInt(proof.mu, common.BigIntSize)...)
	res = append(res, proof.innerProductProof.Bytes()...)

	//privacy.Logger.Log.Debugf("BYTES ------------ %v\n", res)
	return res

}

func (proof *AggregatedRangeProof) SetBytes(bytes []byte) error {
	if len(bytes) == 0 {
		return nil
	}

	//privacy.Logger.Log.Debugf("BEFORE SETBYTES ------------ %v\n", bytes)

	lenValues := int(bytes[0])
	offset := 1

	proof.cmsValue = make([]*privacy.EllipticPoint, lenValues)
	for i := 0; i < lenValues; i++ {
		proof.cmsValue[i] = new(privacy.EllipticPoint)
		err := proof.cmsValue[i].Decompress(bytes[offset : offset+privacy.CompressedEllipticPointSize])
		if err != nil {
			return err
		}
		offset += privacy.CompressedEllipticPointSize
	}

	proof.a = new(privacy.EllipticPoint)
	err := proof.a.Decompress(bytes[offset:])
	if err != nil {
		return err
	}
	offset += privacy.CompressedEllipticPointSize

	proof.s = new(privacy.EllipticPoint)
	err = proof.s.Decompress(bytes[offset:])
	if err != nil {
		return err
	}
	offset += privacy.CompressedEllipticPointSize

	proof.t1 = new(privacy.EllipticPoint)
	err = proof.t1.Decompress(bytes[offset:])
	if err != nil {
		return err
	}
	offset += privacy.CompressedEllipticPointSize

	proof.t2 = new(privacy.EllipticPoint)
	err = proof.t2.Decompress(bytes[offset:])
	if err != nil {
		return err
	}
	offset += privacy.CompressedEllipticPointSize

	proof.tauX = new(big.Int).SetBytes(bytes[offset : offset+common.BigIntSize])
	offset += common.BigIntSize

	proof.tHat = new(big.Int).SetBytes(bytes[offset : offset+common.BigIntSize])
	offset += common.BigIntSize

	proof.mu = new(big.Int).SetBytes(bytes[offset : offset+common.BigIntSize])
	offset += common.BigIntSize

	proof.innerProductProof = new(InnerProductProof)
	proof.innerProductProof.SetBytes(bytes[offset:])

	//privacy.Logger.Log.Debugf("AFTER SETBYTES ------------ %v\n", proof.Bytes())
	return nil
}

func (wit *AggregatedRangeWitness) Set(values []*big.Int, rands []*big.Int) {
	numValue := len(values)
	wit.values = make([]*big.Int, numValue)
	wit.rands = make([]*big.Int, numValue)

	for i := range values {
		wit.values[i] = new(big.Int).Set(values[i])
		wit.rands[i] = new(big.Int).Set(rands[i])
	}
}

func (wit AggregatedRangeWitness) Prove() (*AggregatedRangeProof, error) {
	proof := new(AggregatedRangeProof)

	numValue := len(wit.values)
	numValuePad := pad(numValue)
	values := make([]*big.Int, numValuePad)
	rands := make([]*big.Int, numValuePad)

	for i := range wit.values {
		values[i] = new(big.Int).Set(wit.values[i])
		rands[i] = new(big.Int).Set(wit.rands[i])
	}

	for i := numValue; i < numValuePad; i++ {
		values[i] = big.NewInt(0)
		rands[i] = big.NewInt(0)
	}

	AggParam := newBulletproofParams(numValuePad)

	proof.cmsValue = make([]*privacy.EllipticPoint, numValue)
	for i := 0; i < numValue; i++ {
		proof.cmsValue[i] = privacy.PedCom.CommitAtIndex(values[i], rands[i], privacy.PedersenValueIndex)
	}

	n := maxExp
	// Convert values to binary array
	aL := make([]*big.Int, numValuePad*n)
	for i, value := range values {
		tmp := privacy.ConvertBigIntToBinary(value, n)
		for j := 0; j < n; j++ {
			aL[i*n+j] = tmp[j]
		}
	}

	twoNumber := big.NewInt(2)
	twoVectorN := powerVector(twoNumber, n)

	aR := make([]*big.Int, numValuePad*n)

	for i := 0; i < numValuePad*n; i++ {
		aR[i] = new(big.Int).Sub(aL[i], big.NewInt(1))
		aR[i].Mod(aR[i], privacy.Curve.Params().N)
	}

	// random alpha
	alpha := privacy.RandScalar()

	// Commitment to aL, aR: A = h^alpha * G^aL * H^aR
	A, err := encodeVectors(aL, aR, AggParam.g, AggParam.h)
	if err != nil {
		return nil, err
	}
	A = A.Add(privacy.PedCom.G[privacy.PedersenRandomnessIndex].ScalarMult(alpha))
	proof.a = A

	// Random blinding vectors sL, sR
	sL := make([]*big.Int, n*numValuePad)
	sR := make([]*big.Int, n*numValuePad)
	for i := range sL {
		sL[i] = privacy.RandScalar()
		sR[i] = privacy.RandScalar()
	}

	// random rho
	rho := privacy.RandScalar()

	// Commitment to sL, sR : S = h^rho * G^sL * H^sR
	S, err := encodeVectors(sL, sR, AggParam.g, AggParam.h)
	if err != nil {
		return nil, err
	}
	S = S.Add(privacy.PedCom.G[privacy.PedersenRandomnessIndex].ScalarMult(rho))
	proof.s = S

	// challenge y, z
	y := generateChallengeForAggRange(AggParam, [][]byte{A.Compress(), S.Compress()})
	z := generateChallengeForAggRange(AggParam, [][]byte{A.Compress(), S.Compress(), y.Bytes()})
	zNeg := new(big.Int).Neg(z)
	zNeg.Mod(zNeg, privacy.Curve.Params().N)
	zSquare := new(big.Int).Mul(z, z)
	zSquare.Mod(zSquare, privacy.Curve.Params().N)

	// l(X) = (aL -z*1^n) + sL*X
	yVector := powerVector(y, n*numValuePad)

	l0 := vectorAddScalar(aL, zNeg)
	l1 := sL

	// r(X) = y^n hada (aR +z*1^n + sR*X) + z^2 * 2^n
	hadaProduct, err := hadamardProduct(yVector, vectorAddScalar(aR, z))
	if err != nil {
		return nil, err
	}

	vectorSum := make([]*big.Int, n*numValuePad)
	zTmp := new(big.Int).Set(z)
	for j := 0; j < numValuePad; j++ {
		zTmp.Mul(zTmp, z)
		zTmp.Mod(zTmp, privacy.Curve.Params().N)
		for i := 0; i < n; i++ {
			vectorSum[j*n+i] = new(big.Int).Mul(twoVectorN[i], zTmp)
			vectorSum[j*n+i].Mod(vectorSum[j*n+i], privacy.Curve.Params().N)
		}
	}

	r0, err := vectorAdd(hadaProduct, vectorSum)
	if err != nil {
		return nil, err
	}

	r1, err := hadamardProduct(yVector, sR)
	if err != nil {
		return nil, err
	}

	//t(X) = <l(X), r(X)> = t0 + t1*X + t2*X^2

	//calculate t0 = v*z^2 + delta(y, z)
	deltaYZ := new(big.Int).Sub(z, zSquare)

	// innerProduct1 = <1^(n*m), y^(n*m)>
	innerProduct1 := big.NewInt(0)
	for i := 0; i < n*numValuePad; i++ {
		innerProduct1 = innerProduct1.Add(innerProduct1, yVector[i])
	}
	innerProduct1.Mod(innerProduct1, privacy.Curve.Params().N)

	deltaYZ.Mul(deltaYZ, innerProduct1)

	// innerProduct2 = <1^n, 2^n>
	innerProduct2 := big.NewInt(0)
	for i := 0; i < n; i++ {
		innerProduct2 = innerProduct2.Add(innerProduct2, twoVectorN[i])
	}
	innerProduct2.Mod(innerProduct2, privacy.Curve.Params().N)

	sum := big.NewInt(0)
	zTmp = new(big.Int).Set(zSquare)
	for j := 0; j < numValuePad; j++ {
		zTmp.Mul(zTmp, z)
		zTmp.Mod(zTmp, privacy.Curve.Params().N)

		sum.Add(sum, zTmp)
	}
	sum.Mul(sum, innerProduct2)
	deltaYZ.Sub(deltaYZ, sum)
	deltaYZ.Mod(deltaYZ, privacy.Curve.Params().N)

	// t1 = <l1, r0> + <l0, r1>
	innerProduct3, err := innerProduct(l1, r0)
	if err != nil {
		return nil, err
	}

	innerProduct4, err := innerProduct(l0, r1)
	if err != nil {
		return nil, err
	}

	t1 := new(big.Int).Add(innerProduct3, innerProduct4)
	t1.Mod(t1, privacy.Curve.Params().N)

	// t2 = <l1, r1>
	t2, err := innerProduct(l1, r1)
	if err != nil {
		return nil, err
	}

	// commitment to t1, t2
	tau1 := privacy.RandScalar()
	tau2 := privacy.RandScalar()

	proof.t1 = privacy.PedCom.CommitAtIndex(t1, tau1, privacy.PedersenValueIndex)
	proof.t2 = privacy.PedCom.CommitAtIndex(t2, tau2, privacy.PedersenValueIndex)

	// challenge x = hash(G || H || A || S || T1 || T2)
	x := generateChallengeForAggRange(AggParam, [][]byte{proof.a.Compress(), proof.s.Compress(), proof.t1.Compress(), proof.t2.Compress()})
	xSquare := new(big.Int).Exp(x, twoNumber, privacy.Curve.Params().N)

	// lVector = aL - z*1^n + sL*x
	lVector, err := vectorAdd(vectorAddScalar(aL, zNeg), vectorMulScalar(sL, x))
	if err != nil {
		return nil, err
	}

	// rVector = y^n hada (aR +z*1^n + sR*x) + z^2*2^n
	tmpVector, err := vectorAdd(vectorAddScalar(aR, z), vectorMulScalar(sR, x))
	if err != nil {
		return nil, err
	}
	rVector, err := hadamardProduct(yVector, tmpVector)
	if err != nil {
		return nil, err
	}

	vectorSum = make([]*big.Int, n*numValuePad)
	zTmp = new(big.Int).Set(z)
	for j := 0; j < numValuePad; j++ {
		zTmp.Mul(zTmp, z)
		zTmp.Mod(zTmp, privacy.Curve.Params().N)
		for i := 0; i < n; i++ {
			vectorSum[j*n+i] = new(big.Int).Mul(twoVectorN[i], zTmp)
			vectorSum[j*n+i].Mod(vectorSum[j*n+i], privacy.Curve.Params().N)
		}
	}

	rVector, err = vectorAdd(rVector, vectorSum)
	if err != nil {
		return nil, err
	}

	// tHat = <lVector, rVector>
	proof.tHat, err = innerProduct(lVector, rVector)
	if err != nil {
		return nil, err
	}

	// blinding value for tHat: tauX = tau2*x^2 + tau1*x + z^2*rand
	proof.tauX = new(big.Int).Mul(tau2, xSquare)
	proof.tauX.Add(proof.tauX, new(big.Int).Mul(tau1, x))
	zTmp = new(big.Int).Set(z)
	tmpBN := new(big.Int)
	for j := 0; j < numValuePad; j++ {
		zTmp.Mul(zTmp, z)
		zTmp.Mod(zTmp, privacy.Curve.Params().N)

		proof.tauX.Add(proof.tauX, tmpBN.Mul(zTmp, rands[j]))
	}
	proof.tauX.Mod(proof.tauX, privacy.Curve.Params().N)

	// alpha, rho blind A, S
	// mu = alpha + rho*x
	proof.mu = new(big.Int).Mul(rho, x)
	proof.mu.Add(proof.mu, alpha)
	proof.mu.Mod(proof.mu, privacy.Curve.Params().N)

	// instead of sending left vector and right vector, we use inner sum argument to reduce proof size from 2*n to 2(log2(n)) + 2
	innerProductWit := new(InnerProductWitness)
	innerProductWit.a = lVector
	innerProductWit.b = rVector
	innerProductWit.p, err = encodeVectors(lVector, rVector, AggParam.g, AggParam.h)
	if err != nil {
		return nil, err
	}
	innerProductWit.p = innerProductWit.p.Add(AggParam.u.ScalarMult(proof.tHat))

	proof.innerProductProof, err = innerProductWit.Prove(AggParam)
	if err != nil {
		return nil, err
	}

	return proof, nil
}

func (proof AggregatedRangeProof) Verify() (bool, error) {
	numValue := len(proof.cmsValue)
	numValuePad := pad(numValue)

	tmpcmsValue := proof.cmsValue

	for i := numValue; i < numValuePad; i++ {
		zero := new(privacy.EllipticPoint)
		zero.Zero()
		tmpcmsValue = append(tmpcmsValue, zero)
	}

	AggParam := newBulletproofParams(numValuePad)
	n := maxExp
	oneNumber := big.NewInt(1)
	twoNumber := big.NewInt(2)
	oneVector := powerVector(oneNumber, n*numValuePad)
	oneVectorN := powerVector(oneNumber, n)
	twoVectorN := powerVector(twoNumber, n)

	// recalculate challenge y, z
	y := generateChallengeForAggRange(AggParam, [][]byte{proof.a.Compress(), proof.s.Compress()})
	z := generateChallengeForAggRange(AggParam, [][]byte{proof.a.Compress(), proof.s.Compress(), y.Bytes()})
	zNeg := new(big.Int).Neg(z)
	zNeg.Mod(zNeg, privacy.Curve.Params().N)
	zSquare := new(big.Int).Exp(z, twoNumber, privacy.Curve.Params().N)

	// challenge x = hash(G || H || A || S || T1 || T2)
	//fmt.Printf("T2: %v\n", proof.t2)
	x := generateChallengeForAggRange(AggParam, [][]byte{proof.a.Compress(), proof.s.Compress(), proof.t1.Compress(), proof.t2.Compress()})
	xSquare := new(big.Int).Exp(x, twoNumber, privacy.Curve.Params().N)

	yVector := powerVector(y, n*numValuePad)

	// HPrime = H^(y^(1-i)
	HPrime := make([]*privacy.EllipticPoint, n*numValuePad)
	var wg sync.WaitGroup
	wg.Add(len(HPrime))
	for i := 0; i < n*numValuePad; i++ {
		go func(i int, wg *sync.WaitGroup) {
			defer wg.Done()
			HPrime[i] = AggParam.h[i].ScalarMult(new(big.Int).Exp(y, big.NewInt(int64(-i)), privacy.Curve.Params().N))
		}(i, &wg)
	}
	wg.Wait()

	// g^tHat * h^tauX = V^(z^2) * g^delta(y,z) * T1^x * T2^(x^2)
	deltaYZ := new(big.Int).Sub(z, zSquare)

	// innerProduct1 = <1^(n*m), y^(n*m)>
	innerProduct1, err := innerProduct(oneVector, yVector)
	if err != nil {
		return false, privacy.NewPrivacyErr(privacy.CalInnerProductErr, err)
	}

	deltaYZ.Mul(deltaYZ, innerProduct1)

	// innerProduct2 = <1^n, 2^n>
	innerProduct2, err := innerProduct(oneVectorN, twoVectorN)
	if err != nil {
		return false, privacy.NewPrivacyErr(privacy.CalInnerProductErr, err)
	}

	sum := big.NewInt(0)
	zTmp := new(big.Int).Set(zSquare)
	for j := 0; j < numValuePad; j++ {
		zTmp.Mul(zTmp, z)
		zTmp.Mod(zTmp, privacy.Curve.Params().N)

		sum.Add(sum, zTmp)
	}
	sum.Mul(sum, innerProduct2)
	deltaYZ.Sub(deltaYZ, sum)
	deltaYZ.Mod(deltaYZ, privacy.Curve.Params().N)

	left1 := privacy.PedCom.CommitAtIndex(proof.tHat, proof.tauX, privacy.PedersenValueIndex)

	var temp1, temp2, temp3 *privacy.EllipticPoint

	wg.Add(3)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		temp1 = privacy.PedCom.G[privacy.PedersenValueIndex].ScalarMult(deltaYZ)
	}(&wg)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		temp2 = proof.t1.ScalarMult(x)
	}(&wg)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		temp3 = proof.t2.ScalarMult(xSquare)
	}(&wg)
	wg.Wait()
	right1 := temp1.Add(temp2).Add(temp3)

	expVector := vectorMulScalar(powerVector(z, numValuePad), zSquare)
	for i, cm := range tmpcmsValue {
		right1 = right1.Add(cm.ScalarMult(expVector[i]))
	}

	if !left1.IsEqual(right1) {
		privacy.Logger.Log.Errorf("verify aggregated range proof statement 1 failed")
		return false, errors.New("verify aggregated range proof statement 1 failed")
	}

	innerProductArgValid := proof.innerProductProof.Verify(AggParam)
	if !innerProductArgValid {
		privacy.Logger.Log.Errorf("verify aggregated range proof statement 2 failed")
		return false, errors.New("verify aggregated range proof statement 2 failed")
	}

	return true, nil
}
