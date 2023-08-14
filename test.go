package main

import (
	"fmt"
)

func testSetup() {
	engine, array1, array2, _ := setup()
	// mid element of array1 has to be zero
	if !engine.G1.IsZero(array1[n]) {
		panic("the middle element is not zero")
	}
	// check e(g1^{a^i}, g2^{a^j}) = e(g1^{a^{i-1}}, g2^{a^{j+1}})
	for i := 1; i < 2*n-1; i++ {
		for j := 1; j < n-1; j++ {
			if i != n && i-1 != n {
				temp1 := engine.AddPair(array1[i], array2[j]).Result()
				engine.Reset()
				temp2 := engine.AddPair(array1[i-1], array2[j+1]).Result()
				engine.Reset()
				if !temp1.Equal(temp2) {
					fmt.Println(i, j)
					panic("The pairing identity does not hold")
				}
			}
		}
	}
	fmt.Println("Passed the test successfully")
}
