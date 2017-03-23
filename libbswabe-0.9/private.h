/*
	Include glib.h, pbc.h, and bswabe.h before including this file.
*/

#define N 30

struct bswabe_pub_s
{
	char* pairing_desc;
	pairing_t p;
	element_t g;           /* G_1 */
	element_t g_beta;      /* G_1 */	
	element_t u;           /* G_2 */ /*--------*/
	element_t u_beta;      /* G_2 */ /*--------*/
	element_t g_power[N];  /* G_1 */ /*--------*/
	element_t u_power[N];  /* G_2 */ /*--------*/
	//element_t g2;          /* G_2 */
	element_t g_hat_alpha; /* G_T */
	element_t g_hat;       /* G_T */ /*--------*/
	element_t g2_alpha;    /* G_2 */ /*--------*/
};

struct bswabe_msk_s
{
	element_t beta;     /* Z_r */
	//element_t g2_alpha; /* G_2 */

	element_t alpha;    /* Z_r */ /*--------*/
	element_t g2;       /* G_2 */ /*--------*/
};

typedef struct
{
	/* these actually get serialized */
	char* attr;
	element_t d;  /* G_2 */
	element_t dp; /* G_2 */

	/* only used during dec (only by dec_merge) */
	int used;
	element_t z;  /* G_1 */
	element_t zp; /* G_1 */
}
bswabe_prv_comp_t;

struct bswabe_prv_s
{
	element_t s;   /* G_2 */ /*--------*/
	element_t d;   /* G_2 */
	GArray* comps; /* bswabe_prv_comp_t's */
};

typedef struct
{
	int deg;
	/* coefficients from [0] x^0 to [deg] x^deg */
	element_t* coef; /* G_T (of length deg + 1) */
}
bswabe_polynomial_t;

typedef struct
{
	/* serialized */
	int k;            /* one if leaf, otherwise threshold */
	char* attr;       /* attribute string if leaf, otherwise null */
	element_t c;      /* G_1, only for leaves */
	element_t cp;     /* G_1, only for leaves */
	GPtrArray* children; /* pointers to bswabe_policy_t's, len == 0 for leaves */

	/* only used during encryption */
	bswabe_polynomial_t* q;

	/* only used during decryption */
	int satisfiable;
	int min_leaves;
	int attri;
	GArray* satl;
}
bswabe_policy_t;

typedef struct
{
	/* serialized */
	char* identity;       /* attribute string if leaf, otherwise null */
}
bswabe_identity_t;

struct bswabe_cph_s
{
	element_t cs; /* G_T */
	element_t c2; /* G_1 */
	element_t c3; /* G_2 */
	element_t c4; /* G_T */
	element_t c;  /* G_1 */
	bswabe_policy_t* p;
	GArray* id;
};

struct bswabe_rekey_s
{
	element_t r1;  /* G_2 */ /*--------*/
	element_t r2;  /* G_1 */
	element_t r3;  /* G_1 */
	element_t r4;  /* G_2 */
	GArray* comps; /* bswabe_prv_comp_t's */
	GArray* id;
};

struct bswabe_rcp_s
{
	element_t cs; /* G_T */
	element_t c2; /* G_1 */
	element_t c3; /* G_2 */
	element_t c4; /* G_1 */
	element_t c; /* G_T */
	GArray* id;
};
