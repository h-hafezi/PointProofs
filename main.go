package main

import (
	"crypto/rand"
	"fmt"
	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
	"log"
	"math/big"
)

// constant n which is the length of the vectors in the scheme
const n = 1024

// defining tha global parameters which will be accessed by all functions
var engine *bls.Engine

// pp1[i-1] = {g1 ^ {alpha ^ i}} for 1 <= i <= 2n except for N + 1, pp1[n] = 0
var pp1 [2 * n]*bls.PointG1

// pp2[i-1] = {g2 ^ {alpha ^ i}} for 1 <= i <= n
var pp2 [n]*bls.PointG2

/*
	It returns the followings:
		1. bls.Engine which has the groups and the operations
		2. {g1 ^ {alpha ^ i}} for 1 <= i <= 2n except for N + 1
		3. {g2 ^ {alpha ^ i}} for 1 <= i <= n
	Note g_T^{alpha ^ {n +1}} can be computed later
*/
func setup() (*bls.Engine, [2 * n]*bls.PointG1, [n]*bls.PointG2, *big.Int) {
	engine := bls.NewPairingEngine()
	// alpha is large number and cannot be generated using normal rand.int()
	// Instead we generate a random byte array and convert it into big.Int and set it modulo the order of the group
	buf := make([]byte, 70)
	_, err := rand.Read(buf)
	if err != nil {
		log.Fatalf("error while generating random string: %s", err)
	}
	temp := big.NewInt(0)
	temp.SetBytes(buf)
	alpha := big.NewInt(0)
	alpha.Mod(temp, engine.G1.Q())
	// generate array of g1 ^ {alpha ^ i}} for 1 <= i <= 2n except for N + 1
	var pp1 [2 * n]*bls.PointG1
	for i := 1; i < 2*n+1; i++ {
		if i == n+1 {
			pp1[i-1] = engine.G1.Zero()
		} else {
			// compute alpha ^ i
			temp = big.NewInt(0)
			temp.Exp(alpha, big.NewInt(int64(i)), engine.G1.Q())
			c := engine.G1.New()
			engine.G1.MulScalar(c, engine.G1.One(), temp)
			pp1[i-1] = c
		}
	}
	// generate array of {g2 ^ {alpha ^ i}} for 1 <= i <= n
	var pp2 [n]*bls.PointG2
	for i := 0; i < n; i++ {
		// compute alpha ^ i
		temp = big.NewInt(0)
		temp.Exp(alpha, big.NewInt(int64(i+1)), engine.G1.Q())
		c := engine.G2.New()
		engine.G2.MulScalar(c, engine.G2.One(), temp)
		pp2[i] = c
	}
	// returning the values
	return engine, pp1, pp2, alpha
}

/*
	It takes the following arguments
		1. bls.Engine (implicitly)
		2. the array of {g1 ^ {alpha ^ i}} for 1 <= i <= n which is the sliced output of setup() (implicitly)
		3. the message vector = (m_1, ..., m_n)
	It output a single group G1 point
*/
func commit(message []*big.Int) *bls.PointG1 {
	// Check length of the array
	if len(message) != n {
		panic("wrong array size")
	}
	// First checking if the message lies in the field, 0 <= vector < p = engine.G1.Q()
	for i := 0; i < n; i++ {
		if message[i].Cmp(engine.G1.Q()) != -1 {
			panic("the message does not lie in the group")
		}
		if message[i].Cmp(big.NewInt(0)) == -1 {
			panic("the message does not lie in the group")
		}
	}
	// res, first set it to zero
	com := engine.G1.Zero()
	for i := 0; i < n; i++ {
		temp := engine.G1.New()
		engine.G1.MulScalar(temp, pp1[i], message[i])
		engine.G1.Add(com, com, temp)
	}
	// return of the commitment value
	return com
}

/*
	Given the vector message and the commitment and a specific index, it can generate a proof which is group element again
	1. bls.Engine (implicitly)
	2. 2. pp1 = {g1 ^ {alpha ^ i}} for 1 <= i <= 2n except for N + 1 (implicitly)
	3. vector message
	4. index
*/
func generateProofSingle(message []*big.Int, index int) *bls.PointG1 {
	/*
		// Check length of the array
		if len(message) != n {
			panic("wrong array size")
		}
		// First checking if the message lies in the field, 0 <= vector < p = engine.G1.Q()
		for i := 0; i < n; i++ {
			if message[i].Cmp(engine.G1.Q()) != -1 {
				panic("the message does not lie in the group")
			}
			if message[i].Cmp(big.NewInt(0)) == -1 {
				panic("the message does not lie in the group")
			}
		}
		// Making sure in index lies in the boundaries
		if !(0 <= index && index < n) {
			panic("out of range index")
		}
	*/
	// res, first set it to zero
	proof := engine.G1.Zero()
	for j := 0; j < n; j++ {
		if j != index {
			temp := engine.G1.New()
			engine.G1.MulScalar(temp, pp1[n-index+j], message[j])
			engine.G1.Add(proof, proof, temp)
		}
	}
	// return of the commitment value
	return proof
}

/*
	It takes the following arguments:
		1. bls.Engine (implicitly)
		2. commitment
		3. entry m_i
		4. proof pi
		5. index
		6. pp1 and pp2 (implicitly)
*/
func verifySingleProof(com *bls.PointG1, entry *big.Int, proof *bls.PointG1, index int) bool {
	// Making sure in index lies in the boundaries
	if !(0 <= index && index < n) {
		panic("out of range index")
	}
	// e(C, g_2^{alpha^{N+1-i}})
	lhs := engine.AddPair(com, pp2[n-index-1]).Result()
	engine.Reset()
	// e(proof, g_2)
	temp1 := engine.AddPair(proof, engine.G2.One()).Result()
	engine.Reset()
	// g_T^{alpha^{n+1}*m_i} = e(g_1^{alpha * m_i}, g_2^{alpha^{n})
	temp2 := pp1[0]
	engine.G1.MulScalar(temp2, temp2, entry)
	rhs := engine.AddPair(temp2, pp2[n-1]).Result()
	engine.Reset()
	engine.GT().Mul(rhs, temp1, rhs)
	return lhs.Equal(rhs)
}

/*
	It takes the following arguments:
		1. bls.Engine (implicitly)
		2. proofs pi_i
		3. scalars t_i's
		4. number of proofs we'd like to aggregate
	And finally it returns \prod \pi_i^{t_i}
*/
func aggregateProof(proofs []*bls.PointG1, scalars []*big.Int, number int) *bls.PointG1 {
	// Making sure proof and scalar arrays are of the right size
	if !(len(proofs) == number && len(scalars) == number) {
		panic("arrays with incorrect length")
	}
	res := engine.G1.Zero()
	for i := 0; i < number; i++ {
		temp := engine.G1.New()
		engine.G1.MulScalar(temp, proofs[i], scalars[i])
		engine.G1.Add(res, res, temp)
	}
	return res
}

/*
	It takes the following arguments:
		1. bls.Engine (implicitly)
		2. commitment c
		3. aggregated proof
		4. list of messages
		5. scalars
		6. pp1 (implicitly)
		7. pp2 (implicitly)
		8. Index lists
		9. number of messages
*/
func verifySameCommitmentAggregation(com *bls.PointG1, proof *bls.PointG1, messages []*big.Int, scalars []*big.Int, indices []int, number int) bool {
	// check if the arrays message, indices, and scalar are of the right size
	if !(len(messages) == number && len(scalars) == number && len(indices) == number) {
		panic("arrays with incorrect length")
	}
	// Making sure the indices are in the right boundaries
	for j := 0; j < number; j++ {
		if !(0 <= indices[j] && indices[j] < n) {
			panic("out of range index")
		}
	}
	// First compute \prod g_2^{alpha^{n+1-i}t_i}
	prod := engine.G2.Zero()
	for i := 0; i < number; i++ {
		temp := engine.G2.New()
		// this fucking line of code took 2 fucking hours to debug :')
		engine.G2.MulScalar(temp, pp2[n-indices[i]-1], scalars[i])
		engine.G2.Add(prod, prod, temp)
	}
	// compute the left hand side
	lhs := engine.AddPair(com, prod).Result()
	engine.Reset()
	// e(proof, g_2)
	temp1 := engine.AddPair(proof, engine.G2.One()).Result()
	engine.Reset()
	// sum will be equal to \sum m_it_i
	sum := big.NewInt(0)
	for i := 0; i < number; i++ {
		temp := big.NewInt(0)
		temp.Mul(messages[i], scalars[i])
		sum.Add(sum, temp)
	}
	// g_T^{alpha^{n+1} * sum} = e(g_1^{alpha * m_i * t_i}, g_2^{alpha^{n})
	temp2 := pp1[0]
	engine.G1.MulScalar(temp2, temp2, sum)
	rhs := engine.AddPair(temp2, pp2[n-1]).Result()
	engine.Reset()
	engine.GT().Mul(rhs, temp1, rhs)
	// check if right hand size and left hand sise are equal
	return lhs.Equal(rhs)
}

/*
It takes the following arguments (m is the total number of commitments)
	1. com = {com_1, ..., com_m}
	2. proof
	3. message = {msgVec_1, ..., msgVec_m}
	4. message scalars = {t_{S_1}, t_{S_2}, ..., t_{S_m}}
	5. com scalars = {t_1, ..., t_m}
	6. indices = {S_1, ..., S_n}
	7. number = {|S_1|, |S_2|, ..., |S_m|}
	8. total number = m
*/
func verifyCrossCommitmentAggregation(com []*bls.PointG1, proof *bls.PointG1, messages []*[]*big.Int, messageScalars []*[]*big.Int, comScalars []*big.Int, indices []*[]int, number []int, totalNum int) bool {
	// check if the arrays message, indices, and scalar are of the right size
	if !(len(com) == totalNum && len(comScalars) == totalNum && len(number) == totalNum) {
		panic("arrays with incorrect length")
	}
	// For the sake of performance we don't check if the indices provided are in the right range
	for j := 0; j < totalNum; j++ {
		if !(len(*messages[j]) == number[j] && len(*messageScalars[j]) == number[j] && len(*indices[j]) == number[j]) {
			panic("arrays with incorrect length")
		}
	}
	// computing left hand side
	// zero is zero in G_t
	lhs := engine.AddPair(engine.G1.Zero(), engine.G2.New()).Result()
	engine.Reset()
	for j := 0; j < totalNum; j++ {
		prod := engine.G2.Zero()
		for i := 0; i < number[j]; i++ {
			temp := engine.G2.New()
			// this fucking line of code took 2 fucking hours to debug :')
			engine.G2.MulScalar(temp, pp2[n-(*indices[j])[i]-1], (*messageScalars[j])[i])
			engine.G2.Add(prod, prod, temp)
		}
		// compute the left hand side
		temp := engine.AddPair(com[j], prod).Result()
		engine.Reset()
		res := engine.GT().New()
		engine.GT().Exp(res, temp, comScalars[j])
		engine.GT().Mul(lhs, res, lhs)
	}
	// computing right hand side
	// e(proof, g_2)
	temp1 := engine.AddPair(proof, engine.G2.One()).Result()
	engine.Reset()
	// sum will be equal to \sum m_{j, i}t_{j, i}t_j'
	sum := big.NewInt(0)
	for j := 0; j < totalNum; j++ {
		for i := 0; i < number[j]; i++ {
			temp := big.NewInt(0)
			temp.Mul((*messages[j])[i], (*messageScalars[j])[i])
			temp.Mul(temp, comScalars[j])
			sum.Add(sum, temp)
		}
	}
	// g_T^{alpha^{n+1} * sum} = e(g_1^{alpha * m_i * t_i}, g_2^{alpha^{n})
	temp := pp1[0]
	engine.G1.MulScalar(temp, temp, sum)
	rhs := engine.AddPair(temp, pp2[n-1]).Result()
	engine.Reset()
	engine.GT().Mul(rhs, temp1, rhs)
	// check if right hand side and left hand side are equal
	return lhs.Equal(rhs)

}

func generateBigIntegerArray(length int, mod *big.Int) []*big.Int {
	res := make([]*big.Int, length)
	for i := 0; i < length; i++ {
		// generate a random byte array
		buf := make([]byte, 70)
		_, err := rand.Read(buf)
		if err != nil {
			log.Fatalf("error while generating random string: %s", err)
		}
		// convert the byte array into big.Integer
		temp := big.NewInt(0)
		temp.SetBytes(buf)
		if mod.Sign() != 0 {
			temp.Mod(temp, mod)
		}
		// set the array element
		res[i] = temp
	}
	return res
}

func main() {
	// ******************************************* setup *******************************************
	eng, arr1, arr2, _ := setup()
	engine = eng
	pp1 = arr1
	pp2 = arr2
	// *************************************** first message ***************************************
	// number of entries to be aggregated
	n1 := 2
	msg1 := generateBigIntegerArray(n, big.NewInt(1000000000000000))
	// generate its commitment
	com1 := commit(msg1)
	// generate proofs for indices i1, i2
	i1 := 10
	i2 := 100
	proof10 := generateProofSingle(msg1, i1)
	proof11 := generateProofSingle(msg1, i2)
	scalar1 := generateBigIntegerArray(n1, big.NewInt(1000000000000000))
	// generate the aggregated proof
	aggregated1 := aggregateProof([]*bls.PointG1{proof10, proof11}[:], scalar1[:], n1)
	entries1 := []*big.Int{msg1[i1], msg1[i2]}
	indices1 := []int{i1, i2}
	// *************************************** second message ***************************************
	// number of entries to be aggregated
	n2 := 3
	// generate the second message
	msg2 := generateBigIntegerArray(n, big.NewInt(1000000000000000))
	// generate its commitment
	com2 := commit(msg2)
	// generate proofs for indices j1, j2
	j1 := 10
	j2 := 100
	j3 := 90
	proof20 := generateProofSingle(msg2, j1)
	proof21 := generateProofSingle(msg2, j2)
	proof22 := generateProofSingle(msg2, j3)
	scalar2 := generateBigIntegerArray(n2, big.NewInt(1000000000000000))
	// generate the aggregated proof
	aggregated2 := aggregateProof([]*bls.PointG1{proof20, proof21, proof22}[:], scalar2[:], n2)
	entries2 := []*big.Int{msg2[j1], msg2[j2], msg2[j3]}
	indices2 := []int{j1, j2, j3}
	// ******************************* cross commitment aggregation *********************************
	// The new scalar array
	sc := generateBigIntegerArray(2, big.NewInt(1000000000000000))
	// the aggregate proof
	pi := aggregateProof([]*bls.PointG1{aggregated1, aggregated2}, sc, 2)
	fmt.Println(verifyCrossCommitmentAggregation([]*bls.PointG1{com1, com2}, pi, []*[]*big.Int{&entries1, &entries2},
		[]*[]*big.Int{&scalar1, &scalar2}, sc, []*[]int{&indices1, &indices2}, []int{n1, n2}, 2))
}
