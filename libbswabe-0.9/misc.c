#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <pbc.h>

#include "bswabe.h"
#include "private.h"

void
serialize_uint32( GByteArray* b, uint32_t k )
{
	int i;
	guint8 byte;

	for( i = 3; i >= 0; i-- )
	{
		byte = (k & 0xff<<(i*8))>>(i*8);
		g_byte_array_append(b, &byte, 1);
	}
}

uint32_t
unserialize_uint32( GByteArray* b, int* offset )
{
	int i;
	uint32_t r;

	r = 0;
	for( i = 3; i >= 0; i-- )
		r |= (b->data[(*offset)++])<<(i*8);

	return r;
}

void
serialize_element( GByteArray* b, element_t e )
{
	uint32_t len;
	unsigned char* buf;

	len = element_length_in_bytes(e);
	serialize_uint32(b, len);

	buf = (unsigned char*) malloc(len);
	element_to_bytes(buf, e);
	g_byte_array_append(b, buf, len);
	free(buf);
}

void
unserialize_element( GByteArray* b, int* offset, element_t e )
{
	uint32_t len;
	unsigned char* buf;

	len = unserialize_uint32(b, offset);

	buf = (unsigned char*) malloc(len);
	memcpy(buf, b->data + *offset, len);
	*offset += len;

	element_from_bytes(e, buf);
	free(buf);
}

void
serialize_string( GByteArray* b, char* s )
{
	g_byte_array_append(b, (unsigned char*) s, strlen(s) + 1);
}

char*
unserialize_string( GByteArray* b, int* offset )
{
	GString* s;
	char* r;
	char c;

	s = g_string_sized_new(32);
	while( 1 )
	{
		c = b->data[(*offset)++];
		if( c && c != EOF )
			g_string_append_c(s, c);
		else
			break;
	}

	r = s->str;
	g_string_free(s, 0);

	return r;
}

GByteArray*
bswabe_pub_serialize( bswabe_pub_t* pub )
{
	GByteArray* b;
	int i;

	b = g_byte_array_new();
	serialize_string(b,  pub->pairing_desc);
	serialize_element(b, pub->g);
	serialize_element(b, pub->g_beta);
	serialize_element(b, pub->u);
	serialize_element(b, pub->u_beta);
	for( i = 0; i < N; i++ )
	{
		serialize_element(b, pub->g_power[i]);
		serialize_element(b, pub->u_power[i]);
	}
	//serialize_element(b, pub->g2);
	serialize_element(b, pub->g_hat_alpha);
	serialize_element(b, pub->g_hat);
	serialize_element(b, pub->g2_alpha);

	return b;
}

bswabe_pub_t*
bswabe_pub_unserialize( GByteArray* b, int free )
{
	bswabe_pub_t* pub;
	int offset;
	int i;

	pub = (bswabe_pub_t*) malloc(sizeof(bswabe_pub_t));
	offset = 0;

	pub->pairing_desc = unserialize_string(b, &offset);
	pairing_init_set_buf(pub->p, pub->pairing_desc, strlen(pub->pairing_desc));

	element_init_G1(pub->g,           pub->p);
	element_init_G1(pub->g_beta,      pub->p);
	element_init_G2(pub->u,           pub->p);
	element_init_G2(pub->u_beta,      pub->p);
	for( i = 0; i < N; i++ )
	{
		element_init_G1(pub->g_power[i],      pub->p);
		element_init_G2(pub->u_power[i],      pub->p);
	}
	//element_init_G2(pub->g2,          pub->p);
	element_init_GT(pub->g_hat_alpha, pub->p);
	element_init_GT(pub->g_hat,       pub->p);
	element_init_G2(pub->g2_alpha,    pub->p);	

	unserialize_element(b, &offset, pub->g);
	unserialize_element(b, &offset, pub->g_beta);
	unserialize_element(b, &offset, pub->u);
	unserialize_element(b, &offset, pub->u_beta);
	for( i = 0; i < N; i++ )
	{
		unserialize_element(b, &offset, pub->g_power[i]);
		unserialize_element(b, &offset, pub->u_power[i]);
	}
	//unserialize_element(b, &offset, pub->g2);
	unserialize_element(b, &offset, pub->g_hat_alpha);
	unserialize_element(b, &offset, pub->g_hat);
	unserialize_element(b, &offset, pub->g2_alpha);

	if( free )
		g_byte_array_free(b, 1);

	return pub;
}

GByteArray*
bswabe_msk_serialize( bswabe_msk_t* msk )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_element(b, msk->beta);
	//serialize_element(b, msk->g2_alpha);
	serialize_element(b, msk->alpha);
	serialize_element(b, msk->g2);

	return b;
}

bswabe_msk_t*
bswabe_msk_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
	bswabe_msk_t* msk;
	int offset;

	msk = (bswabe_msk_t*) malloc(sizeof(bswabe_msk_t));
	offset = 0;

	element_init_Zr(msk->beta, pub->p);
	//element_init_G2(msk->g2_alpha, pub->p);
	element_init_Zr(msk->alpha, pub->p);
	element_init_G2(msk->g2, pub->p);

	unserialize_element(b, &offset, msk->beta);
	//unserialize_element(b, &offset, msk->g2_alpha);
	unserialize_element(b, &offset, msk->alpha);
	unserialize_element(b, &offset, msk->g2);

	if( free )
		g_byte_array_free(b, 1);

	return msk;
}

GByteArray*
bswabe_prv_serialize( bswabe_prv_t* prv )
{
	GByteArray* b;
	int i;

	b = g_byte_array_new();
	
	serialize_element(b, prv->s);
	serialize_element(b, prv->d);
	serialize_uint32( b, prv->comps->len);

	for( i = 0; i < prv->comps->len; i++ )
	{
		serialize_string( b, g_array_index(prv->comps, bswabe_prv_comp_t, i).attr);
		serialize_element(b, g_array_index(prv->comps, bswabe_prv_comp_t, i).d);
		serialize_element(b, g_array_index(prv->comps, bswabe_prv_comp_t, i).dp);
	}

	return b;
}

bswabe_prv_t*
bswabe_prv_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
	bswabe_prv_t* prv;
	int i;
	int len;
	int offset;

	prv = (bswabe_prv_t*) malloc(sizeof(bswabe_prv_t));
	offset = 0;

	element_init_G2(prv->s, pub->p);
	unserialize_element(b, &offset, prv->s);

	element_init_G2(prv->d, pub->p);
	unserialize_element(b, &offset, prv->d);

	prv->comps = g_array_new(0, 1, sizeof(bswabe_prv_comp_t));
	len = unserialize_uint32(b, &offset);

	for( i = 0; i < len; i++ )
	{
		bswabe_prv_comp_t c;

		c.attr = unserialize_string(b, &offset);

		element_init_G2(c.d,  pub->p);
		element_init_G2(c.dp, pub->p);

		unserialize_element(b, &offset, c.d);
		unserialize_element(b, &offset, c.dp);

		g_array_append_val(prv->comps, c);
	}

	if( free )
		g_byte_array_free(b, 1);

	return prv;
}

void
serialize_policy( GByteArray* b, bswabe_policy_t* p )
{
	int i;

	serialize_uint32(b, (uint32_t) p->k);

	serialize_uint32(b, (uint32_t) p->children->len);
	if( p->children->len == 0 )
	{
		serialize_string( b, p->attr);
		serialize_element(b, p->c);
		serialize_element(b, p->cp);
	}
	else
		for( i = 0; i < p->children->len; i++ )
			serialize_policy(b, g_ptr_array_index(p->children, i));
}

bswabe_policy_t*
unserialize_policy( bswabe_pub_t* pub, GByteArray* b, int* offset )
{
	int i;
	int n;
	bswabe_policy_t* p;

	p = (bswabe_policy_t*) malloc(sizeof(bswabe_policy_t));

	p->k = (int) unserialize_uint32(b, offset);
	p->attr = 0;
	p->children = g_ptr_array_new();

	n = unserialize_uint32(b, offset);
	if( n == 0 )
	{
		p->attr = unserialize_string(b, offset);
		element_init_G1(p->c,  pub->p);
		element_init_G1(p->cp, pub->p);
		unserialize_element(b, offset, p->c);
		unserialize_element(b, offset, p->cp);
	}
	else
		for( i = 0; i < n; i++ )
			g_ptr_array_add(p->children, unserialize_policy(pub, b, offset));

	return p;
}

GByteArray*
bswabe_cph_serialize( bswabe_cph_t* cph )
{
	int i;
	GByteArray* b;

	b = g_byte_array_new();
	serialize_element(b, cph->cs);
	serialize_element(b, cph->c2);
	serialize_element(b, cph->c3);
	serialize_element(b, cph->c4);
	serialize_element(b, cph->c);
	serialize_policy( b, cph->p);
	serialize_uint32( b, cph->id->len);

	for( i = 0; i < cph->id->len; i++ )
	{
		serialize_string( b, g_array_index(cph->id, bswabe_identity_t, i).identity);
	}

	return b;
}

bswabe_cph_t*
bswabe_cph_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
	bswabe_cph_t* cph;
	int offset;
	int i;
	int len;

	cph = (bswabe_cph_t*) malloc(sizeof(bswabe_cph_t));
	offset = 0;

	element_init_GT(cph->cs, pub->p);
	element_init_G1(cph->c2, pub->p);
	element_init_G2(cph->c3, pub->p);
	element_init_GT(cph->c4, pub->p);
	element_init_G1(cph->c,  pub->p);
	unserialize_element(b, &offset, cph->cs);
	unserialize_element(b, &offset, cph->c2);
	unserialize_element(b, &offset, cph->c3);
	unserialize_element(b, &offset, cph->c4);
	unserialize_element(b, &offset, cph->c);
	cph->p = unserialize_policy(pub, b, &offset);

	cph->id = g_array_new(0, 1, sizeof(bswabe_identity_t));
	len = unserialize_uint32(b, &offset);

	for( i = 0; i < len; i++ )
	{
		bswabe_identity_t c;

		c.identity = unserialize_string(b, &offset);

		g_array_append_val(cph->id, c);
	}

	if( free )
		g_byte_array_free(b, 1);

	return cph;
}

GByteArray*
bswabe_rekey_serialize( bswabe_rekey_t* rekey )
{
	GByteArray* b;
	int i;

	b = g_byte_array_new();
	
	serialize_element(b, rekey->r1);
	serialize_element(b, rekey->r2);
	serialize_element(b, rekey->r3);
	serialize_element(b, rekey->r4);
	serialize_uint32( b, rekey->comps->len);

	for( i = 0; i < rekey->comps->len; i++ )
	{
		serialize_string( b, g_array_index(rekey->comps, bswabe_prv_comp_t, i).attr);
		serialize_element(b, g_array_index(rekey->comps, bswabe_prv_comp_t, i).d);
		serialize_element(b, g_array_index(rekey->comps, bswabe_prv_comp_t, i).dp);
	}

	serialize_uint32( b, rekey->id->len);

	for( i = 0; i < rekey->id->len; i++ )
	{
		serialize_string( b, g_array_index(rekey->id, bswabe_identity_t, i).identity);
	}

	return b;
}

bswabe_rekey_t*
bswabe_rekey_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
	bswabe_rekey_t* rekey;
	int i;
	int len;
	int offset;

	rekey = (bswabe_rekey_t*) malloc(sizeof(bswabe_rekey_t));
	offset = 0;

	element_init_G2(rekey->r1, pub->p);
	unserialize_element(b, &offset, rekey->r1);

	element_init_G1(rekey->r2, pub->p);
	unserialize_element(b, &offset, rekey->r2);

	element_init_G1(rekey->r3, pub->p);
	unserialize_element(b, &offset, rekey->r3);

	element_init_G2(rekey->r4, pub->p);
	unserialize_element(b, &offset, rekey->r4);

	rekey->comps = g_array_new(0, 1, sizeof(bswabe_prv_comp_t));
	len = unserialize_uint32(b, &offset);

	for( i = 0; i < len; i++ )
	{
		bswabe_prv_comp_t c;

		c.attr = unserialize_string(b, &offset);

		element_init_G2(c.d,  pub->p);
		element_init_G2(c.dp, pub->p);

		unserialize_element(b, &offset, c.d);
		unserialize_element(b, &offset, c.dp);

		g_array_append_val(rekey->comps, c);
	}

	rekey->id = g_array_new(0, 1, sizeof(bswabe_identity_t));
	len = unserialize_uint32(b, &offset);

	for( i = 0; i < len; i++ )
	{
		bswabe_identity_t c;

		c.identity = unserialize_string(b, &offset);

		g_array_append_val(rekey->id, c);
	}

	if( free )
		g_byte_array_free(b, 1);

	return rekey;
}

GByteArray*
bswabe_rcp_serialize( bswabe_rcp_t* rcp )
{
	int i;
	GByteArray* b;

	b = g_byte_array_new();
	serialize_element(b, rcp->cs);
	serialize_element(b, rcp->c2);
	serialize_element(b, rcp->c3);
	serialize_element(b, rcp->c4);
	serialize_element(b, rcp->c);
	serialize_uint32( b, rcp->id->len);

	for( i = 0; i < rcp->id->len; i++ )
	{
		serialize_string( b, g_array_index(rcp->id, bswabe_identity_t, i).identity);
	}

	return b;
}

bswabe_rcp_t*
bswabe_rcp_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
	bswabe_rcp_t* rcp;
	int offset;
	int i;
	int len;

	rcp = (bswabe_rcp_t*) malloc(sizeof(bswabe_rcp_t));
	offset = 0;

	element_init_GT(rcp->cs, pub->p);
	element_init_G1(rcp->c2, pub->p);
	element_init_G2(rcp->c3, pub->p);
	element_init_G1(rcp->c4, pub->p);
	element_init_GT(rcp->c,  pub->p);
	unserialize_element(b, &offset, rcp->cs);
	unserialize_element(b, &offset, rcp->c2);
	unserialize_element(b, &offset, rcp->c3);
	unserialize_element(b, &offset, rcp->c4);
	unserialize_element(b, &offset, rcp->c);

	rcp->id = g_array_new(0, 1, sizeof(bswabe_identity_t));
	len = unserialize_uint32(b, &offset);

	for( i = 0; i < len; i++ )
	{
		bswabe_identity_t c;

		c.identity = unserialize_string(b, &offset);

		g_array_append_val(rcp->id, c);
	}

	if( free )
		g_byte_array_free(b, 1);

	return rcp;
}

void
bswabe_pub_free( bswabe_pub_t* pub )
{
	int i;

	element_clear(pub->g);
	element_clear(pub->g_beta);
	element_clear(pub->u);
	element_clear(pub->u_beta);
	for( i = 0; i < N; i++ )
	{
		element_clear(pub->g_power[i]);
		element_clear(pub->u_power[i]);
	}
	//element_clear(pub->g2);
	element_clear(pub->g_hat_alpha);
	element_clear(pub->g_hat);	
	element_clear(pub->g2_alpha);	
	pairing_clear(pub->p);
	free(pub->pairing_desc);
	free(pub);
}

void
bswabe_msk_free( bswabe_msk_t* msk )
{
	element_clear(msk->beta);
	//element_clear(msk->g2_alpha);
	element_clear(msk->alpha);
	element_clear(msk->g2);
	free(msk);
}

void
bswabe_prv_free( bswabe_prv_t* prv )
{
	int i;
	
	element_clear(prv->s);
	element_clear(prv->d);

	for( i = 0; i < prv->comps->len; i++ )
	{
		bswabe_prv_comp_t c;

		c = g_array_index(prv->comps, bswabe_prv_comp_t, i);
		free(c.attr);
		element_clear(c.d);
		element_clear(c.dp);
	}

	g_array_free(prv->comps, 1);

	free(prv);
}

void
bswabe_policy_free( bswabe_policy_t* p )
{
	int i;

	if( p->attr )
	{
		free(p->attr);
		element_clear(p->c);
		element_clear(p->cp);
	}

	for( i = 0; i < p->children->len; i++ )
		bswabe_policy_free(g_ptr_array_index(p->children, i));

	g_ptr_array_free(p->children, 1);

	free(p);
}

void
bswabe_cph_free( bswabe_cph_t* cph )
{
	element_clear(cph->cs);
	element_clear(cph->c2);
	element_clear(cph->c3);
	element_clear(cph->c4);
	element_clear(cph->c);
	bswabe_policy_free(cph->p);

	g_array_free(cph->id, 1);

	free(cph);
}

void
bswabe_rekey_free( bswabe_rekey_t* rekey )
{
	int i;
	
	element_clear(rekey->r1);
	element_clear(rekey->r2);
	element_clear(rekey->r3);
	element_clear(rekey->r4);

	for( i = 0; i < rekey->comps->len; i++ )
	{
		bswabe_prv_comp_t c;

		c = g_array_index(rekey->comps, bswabe_prv_comp_t, i);
		free(c.attr);
		element_clear(c.d);
		element_clear(c.dp);
	}

	g_array_free(rekey->comps, 1);

	g_array_free(rekey->id, 1);

	free(rekey);
}

void
bswabe_rcp_free( bswabe_rcp_t* rcp )
{
	element_clear(rcp->cs);
	element_clear(rcp->c2);
	element_clear(rcp->c3);
	element_clear(rcp->c4);
	element_clear(rcp->c);
	
	g_array_free(rcp->id, 1);

	free(rcp);
}
