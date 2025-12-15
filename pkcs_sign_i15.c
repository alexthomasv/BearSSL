#include "../../ct-verif.h"
#include "inner.h"
void sign_wrapper(const unsigned char *hash_oid,
	const unsigned char *hash, size_t hash_len,
	const br_rsa_private_key *sk, unsigned char *x){
	public_in(__SMACK_value(hash_oid));
	public_in(__SMACK_value(hash));
	public_in(__SMACK_value(hash_len));
	public_in(__SMACK_value(sk));
	public_in(__SMACK_value(x));


	public_in(__SMACK_value(sk->n_bitlen));

	public_in(__SMACK_value(sk->p));
	private_in(__SMACK_values(sk->p, 64));
	public_in(__SMACK_value(sk->plen));

	public_in(__SMACK_value(sk->q));
	private_in(__SMACK_values(sk->q, 64));
	public_in(__SMACK_value(sk->qlen));

	public_in(__SMACK_value(sk->dp));
	private_in(__SMACK_values(sk->dp, 64));
	public_in(__SMACK_value(sk->dplen));

	public_in(__SMACK_value(sk->dq));
	private_in(__SMACK_values(sk->dq, 64));
	public_in(__SMACK_value(sk->dqlen));

	public_in(__SMACK_value(sk->iq));
	private_in(__SMACK_values(sk->iq, 64));
	public_in(__SMACK_value(sk->iqlen));

	public_in(__SMACK_values(hash_oid, 6));
	public_in(__SMACK_values(hash, 20));
	public_in(__SMACK_values(x, 128));
	
	
	br_rsa_i15_pkcs1_sign(hash_oid, hash, hash_len, sk, x);
}


// const unsigned char * getcharpt();
// const unsigned char * getcharpt2();
// const br_rsa_private_key getpk();
// size_t getsize_t();
// unsigned char * getuschar();

// void vfct_taintseed(unsigned char *, unsigned char *, unsigned char *, unsigned char *, unsigned char *);

// // void vfct_tmp(unsigned char *p, unsigned char *q, unsigned char *dp, unsigned char *dq, unsigned char *iq, const unsigned char *hash_oid,
// // 	const unsigned char *hash, size_t hash_len,
// // 	const br_rsa_private_key *sk, unsigned char *x){
// // 		br_rsa_i15_pkcs1_sign(hash_oid, hash, hash_len, sk, x);

// // }

// void sign_wrapper_t(){

// const unsigned char *hash_oid = getcharpt();
// 	const unsigned char *hash = getcharpt2();
// 	size_t hash_len = getsize_t();
// 	br_rsa_private_key key = getpk();
// 	br_rsa_private_key *sk = &key;
// 	 unsigned char *x = getuschar();
// unsigned char *p = sk->p;
// unsigned char *q = sk->q;
// unsigned char *dp = sk->dp;
// unsigned char *dq = sk->dq;
// unsigned char *iq = sk->iq;

// vfct_taintseed(p,q,dp,dq,iq);

// sk->p = p;
// sk->q = q;
// sk->dp = dp;
// sk->dq = dq;
// sk->iq = iq;
// br_rsa_i15_pkcs1_sign(hash_oid, hash, hash_len, sk, x);
// }
