/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "inner.h"
#include "g_header.h"

/* see inner.h */
uint32_t
br_i31_bit_length(uint32_t *x, size_t xlen)
{
    size_t xlen_init = xlen;
	uint32_t tw, twk;
	size_t C = __VERIFIER_nondet_size_t();
	tw = 0;
	twk = 0;

	while (xlen > 0) {
        __SMACK_code(
            "assume {:loop_invariant} {:custom \"br_i31_bit_length\"} {:free_var @} {:x @} {:xlen @} {:twk @} {:tw @} {:mem_map MEM(@)} "
            "$and.i1("
                // 1. Witness Bounds (C < xlen_init)
                "$ult.i64(@, @), " 
        
                "$and.i1("
                    // -------------------------------------------------------
                    // 2. Witness Property: x[C] != 0
                    // Manual Load: load(MEM(x), x + C*4)
                    "$ne.i32("
                        "$load.i32(MEM(@), $add.i64(@, $mul.i64(@, 4))), " 
                        "0"
                    "), "
        
                    "$and.i1("
                        // 3. Implication: (xlen <= C) ==> (twk == C)
                        "$or.i1("
                            "$ugt.i64(@, @), "          
                            "$eq.i32(@, $trunc.i64.i32(@))" 
                        "), "
        
                        "$and.i1("
                            // -----------------------------------------------
                            // 4. Implication: (xlen <= C) ==> (tw == x[C])
                            // Manual Load: val(MEM(x), x + C*4)
                            "$or.i1("
                                "$ugt.i64(@, @), "      
                                "$eq.i32(@, "           
                                    "$load.i32(MEM(@), $add.i64(@, $mul.i64(@, 4)))"
                                ")"
                            "), "
        
                            // 5. Implication: (xlen > C) ==> (twk == xlen)
                            "$or.i1("
                                "$ule.i64(@, @), "          
                                "$eq.i32(@, $trunc.i64.i32(@))" 
                            ")"
                        ")"
                    ")"
                ")"
            ") == 1;",
            // --- Argument Mapping ---
            // 0. Free Variable (C)
            C, x, xlen, twk, tw, x, 
            // 1. Witness Bounds
            C, xlen_init,
            // 2. Witness Non-Zero: Needs (x, x, C)
            x, x, C, 
            // 3. Post-Latch Index
            xlen, C, twk, C,
            // 4. Post-Latch Value: Needs (xlen, C, tw) AND (x, x, C)
            xlen, C, tw, x, x, C,
            // 5. Pre-Latch Index
            xlen, C, twk, xlen
        );
		xlen--;
        uint32_t c = EQ(tw, 0);
		tw = MUX(c, x[xlen], tw);

        // Preconditions -> is this enough to prove the below target assert?
        // (xlen <= C) ==> (twk == C)
        // (xlen <= C) ==> (tw == x[C])
        // (xlen >  C) ==> (twk == xlen)
        // (xlen >  C) ==> (x[xlen] == 0)
        // (C >= 0) /\ (C < xlen)
        // x[C] != 0
        // xlen in {0, 1 .. 16, 17, 18, 19, 20}
        // twk_old in {20, 19, 18, 17, 16}
        // x[16] == 0x1834

        twk = MUX(c, (uint32_t)xlen, twk);
	}
    // Preconditions: 
    // twk in {20, 19, 18, 17, 16}
    // xlen_init == 21
    // xlen <= 0
    // xlen in {0, 1 .. 16, 17, 18, 19, 20}
    // (xlen <= C) ==> (twk == C)
    // (xlen <= C) ==> (tw == x[C])
    // (xlen >  C) ==> (twk == xlen)
    // (xlen >  C) ==> (x[xlen] == 0)
    // (C >= 0) /\ (C < xlen_init)
    // x[C] != 0
    // x[16] != 0 /\ x[17] == 0 /\ x[18] == 0 /\ x[19] == 0 /\ x[20] == 0

    // assert(twk == 16); // <- I want to prove this


        // My facts:
        // xlen <= C => twk == C /\ tw == x[C]
        // xlen > C => twk == xlen /\ x[xlen] == 0
        // x[C] != 0 /\ 0 <= C < xlen
        // (xlen < C) ==> (c == 0)
        // c == tw == 0
 
        // tw in {0x1934, 0}
        // c in {0, 1}
        // xlen in [0, 1 .. 16] 
        // twk_old in {20, 19, 18, 17, 16} 
        // xlen in (0, 1 .. 17, 18 19 20)

        // tw == 0 

        // WHAT I WANT TO PROVE: 
        // twk_new in {20, 19, 18, 17, 16}
        // twk_new = twk_old if (tw != 0) else twk_new = xlen

    // requires: twk in {20, 18, 17, 16} /\  xlen in (0, 1 .. 17, 18 19 20}
	// assert(twk == 16)
    // twk == C
    
    // xlen <= 0 
    // xlen <= C => twk == C /\   tw == x[C]
    // xlen > C => twk == xlen /\ x[xlen] == 0
    // x[C] != 0 /\ 0 <= C < xlen

    // xlen in (0, 1 .. 17, 18 19 20)
    // tw = 0x1934, 0
    // twk in (20, 18, 17, 16)

    // twk == 16 <- the target i want to prove

    
	return (twk << 5) + BIT_LENGTH(tw);
}
