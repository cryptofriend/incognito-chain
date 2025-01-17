package privacy

import (
	"crypto/elliptic"
	"encoding/json"
	"math/big"

	"errors"
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/common/base58"
)

var InvalidXCoordErr = errors.New("X is not an abscissa of a point on the elliptic curve")
var IsNotAnEllipticPointErr = errors.New("the point is not an elliptic point on P256 curve")

// The NIST curve P-256 will be used in the whole protocol
// https://csrc.nist.gov/publications/detail/fips/186/3/archive/2009-06-25
var Curve = elliptic.P256()

// EllipticPoint represents a point (X, y) on the elliptic curve
type EllipticPoint struct {
	x, y *big.Int
}

func (ellipticPoint EllipticPoint) GetX() *big.Int {
	return ellipticPoint.x
}

func (ellipticPoint EllipticPoint) GetY() *big.Int {
	return ellipticPoint.y
}

// Zero returns the elliptic point (0, 0)
func (point *EllipticPoint) Zero() {
	point.x = big.NewInt(0)
	point.y = big.NewInt(0)
}

// UnmarshalJSON (EllipticPoint) receives bytes array of elli[tic point (it was be MarshalJSON before),
// json.Unmarshal the bytes array to string
// base58 check decode that string to bytes array
// and decompress the bytes array to elliptic point
func (point *EllipticPoint) UnmarshalJSON(data []byte) error {
	dataStr := ""
	_ = json.Unmarshal(data, &dataStr)
	temp, _, err := base58.Base58Check{}.Decode(dataStr)
	if err != nil {
		return err
	}
	point.Decompress(temp)
	return nil
}

// MarshalJSON (EllipticPoint) compresses elliptic point to bytes array,
// base58 check encode that bytes array into string
// json.Marshal the string
func (point EllipticPoint) MarshalJSON() ([]byte, error) {
	data := point.Compress()
	temp := base58.Base58Check{}.Encode(data, common.ZeroByte)
	return json.Marshal(temp)
}

// ComputeYCoord returns Y-coordinate from X-coordinate
func (point *EllipticPoint) computeYCoord() error {
	// Y = +-sqrt(x^3 - 3*x + B)
	xCube := new(big.Int).Exp(point.x, big.NewInt(3), Curve.Params().P)
	xCube.Add(xCube, Curve.Params().B)
	xCube.Sub(xCube, new(big.Int).Mul(point.x, big.NewInt(3)))
	xCube.Mod(xCube, Curve.Params().P)

	// compute sqrt(x^3 - 3*x + B) mod p
	// https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294
	tmpY := new(big.Int).Exp(xCube, padd1Div4(Curve.Params().P), Curve.Params().P)

	// check if y is a square root of x^3 - 3*x + B.
	ySquared := new(big.Int).Mul(tmpY, tmpY)
	ySquared.Mod(ySquared, Curve.Params().P)

	// check if (X, Y) is a point on the curve
	if ySquared.Cmp(xCube) != 0 {
		return InvalidXCoordErr
	}

	point.y = tmpY
	return nil
}

// Inverse returns the inverse point of an input elliptic point
func (point EllipticPoint) inverse() (*EllipticPoint, error) {
	// check if point is on the curve
	if !Curve.IsOnCurve(point.x, point.y) {
		return nil, IsNotAnEllipticPointErr
	}

	resPoint := new(EllipticPoint)
	resPoint.Zero()

	// the inverse of the point (x, y) mod P is the point (x, -y) mod P
	resPoint.x.Set(point.x)
	resPoint.y.Sub(Curve.Params().P, point.y)
	resPoint.y.Mod(resPoint.y, Curve.Params().P)

	return resPoint, nil
}

// Randomize generates a random elliptic point on P256 curve
// the elliptic point must be not a double point (which is the point has order is two)
func (point *EllipticPoint) randomize() {
	for {
		point.x = RandScalar()
		err := point.computeYCoord()
		if (err == nil) && (point.IsSafe()) {
			break
		}
	}
}

// IsSafe returns true if an input elliptic point is on the curve and has order not equal to 2
func (point EllipticPoint) IsSafe() bool {
	if !Curve.IsOnCurve(point.x, point.y) {
		return false
	}

	var doublePoint EllipticPoint
	doublePoint.x, doublePoint.y = Curve.Double(point.x, point.y)

	zero := new(EllipticPoint)
	zero.Zero()
	return !doublePoint.IsEqual(zero)
}

// Compress compresses point from 64 bytes to CompressedPointSize bytes (33 bytes)
func (point EllipticPoint) Compress() []byte {
	if Curve.IsOnCurve(point.x, point.y) {
		b := make([]byte, 0, CompressedEllipticPointSize)
		format := pointCompressed
		if isOdd(point.y) {
			format |= 0x1
		}
		b = append(b, format)
		return paddedAppend(common.BigIntSize, b, point.x.Bytes())
	}
	return nil
}

// Decompress decompresses a byte array, which was created by CompressPoint func,
// to a point on the given curve.
func (point *EllipticPoint) Decompress(compressPointBytes []byte) error {
	format := compressPointBytes[0]
	yBit := (format & 0x1) == 0x1
	format &= ^byte(0x1)

	if format != pointCompressed {
		return errors.New("invalid magic in compressed compressPoint bytes")
	}

	point.x = new(big.Int).SetBytes(compressPointBytes[1:33])

	err := point.computeYCoord()
	if err != nil {
		return err
	}

	if yBit != isOdd(point.y) {
		point.y.Sub(Curve.Params().P, point.y)
	}

	return nil
}

// Hash derives a new elliptic point from an elliptic point and an index using hash function
func (point EllipticPoint) Hash(index int64) *EllipticPoint {
	res := new(EllipticPoint)
	res.Zero()
	tmp := common.AddPaddingBigInt(point.x, common.BigIntSize)
	if index == 0 {
		tmp = append(tmp, byte(0))
	} else {
		tmp = append(tmp, big.NewInt(index).Bytes()...)
	}

	for {
		tmp = common.HashB(tmp)
		res.x.SetBytes(tmp)
		err := res.computeYCoord()

		if (err == nil) && (res.IsSafe()) {
			break
		}
	}

	return res
}

// Set sets two coordinates to an elliptic point
func (point *EllipticPoint) Set(x, y *big.Int) {
	if point.x == nil {
		point.x = new(big.Int)
	}
	if point.y == nil {
		point.y = new(big.Int)
	}

	point.x.Set(x)
	point.y.Set(y)
}

// Add adds an elliptic point to another elliptic point
func (point EllipticPoint) Add(targetPoint *EllipticPoint) *EllipticPoint {
	res := new(EllipticPoint)
	res.x, res.y = Curve.Add(point.x, point.y, targetPoint.x, targetPoint.y)
	return res
}

// Sub subtracts an elliptic point to another elliptic point
func (point EllipticPoint) Sub(targetPoint *EllipticPoint) (*EllipticPoint, error) {
	invPoint, err := targetPoint.inverse()
	if err != nil {
		return nil, err
	}

	res := point.Add(invPoint)
	return res, nil
}

// IsEqual returns true if two input elliptic points are equal, false otherwise
func (point EllipticPoint) IsEqual(p *EllipticPoint) bool {
	return point.x.Cmp(p.x) == 0 && point.y.Cmp(p.y) == 0
}

// ScalarMult returns x*P for x in Z_N and P in E(Z_P)
func (point EllipticPoint) ScalarMult(factor *big.Int) *EllipticPoint {
	res := new(EllipticPoint)
	res.Zero()
	res.x, res.y = Curve.ScalarMult(point.x, point.y, factor.Bytes())
	return res
}

// Derive returns a pseudo-random elliptic curve point P = F(seed, derivator), where
// F is a pseudo-random function defined by F(x, y) = 1/(x + y)*G, where x, y are integers,
// seed and derivator are integers of size at least 32 bytes,
// G is a generating point of the group of points of an elliptic curve.
func (point EllipticPoint) Derive(seed, derivator *big.Int) *EllipticPoint {
	// point must be on the curve
	if !point.IsSafe() {
		return nil
	}
	res := point.ScalarMult(new(big.Int).ModInverse(new(big.Int).Add(seed, derivator), Curve.Params().N))
	return res
}
