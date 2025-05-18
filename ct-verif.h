#ifndef CT_VERIF_H
#define CT_VERIF_H

#ifndef COMPILE
#include <smack.h>

/*
Security levels are the following.

For inputs:
- public - function requires (assumes) these to be equal.
- private - no requirement (allowed to vary freely)

For outputs (both by reference and return values):
- public - function ensures these are equal
           can be used on left-hand side of implications everywhere
- private - no guarantee (allowed to vary freely)
- declassified - we only analyse executions in which these
                 possibly private values are fixed.

We omit annotations for private since nothing needs to be generated
 for them. We may need to add them back in for modular analyses.
*/

/* The abstract prototypes that form our annotation language */
void public_in(smack_value_t);
void private_in(smack_value_t);
void public_out(smack_value_t);
void declassified_out(smack_value_t);
void public_invariant(smack_value_t);

#define __disjoint_regions(addr1,len1,addr2,len2) \
  assume(addr1 + len1 * sizeof(*addr1) < addr2 || \
         addr2 + len2 * sizeof(*addr2) < addr1)

#else /* COMPILE */

/* SMACK helpers stripped away */
#undef  __SMACK_value
#define __VERIFIER_assume(x)         ((void)0)
#define __SMACK_value(x)             ((void)0)
#define __SMACK_return_value(x)      ((void)0)
#define __SMACK_values(x,y)          ((void)0)
#define __SMACK_return_values(x)     ((void)0)

/* annotation macros now evaluate their arguments but emit no code */
#define public_in(x)                 ((void)(x))
#define private_in(x)                ((void)(x))
#define public_out(x)                ((void)(x))
#define declassified_out(x)          ((void)(x))
#define public_invariant(x)          ((void)(x))

#define __disjoint_regions(a,l1,b,l2)  ((void)0)

#endif /* COMPILE */
#endif /* CT_VERIF_H */
