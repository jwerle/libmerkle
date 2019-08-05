#include <assert.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <ok/ok.h>

#include "merkle/merkle.h"

unsigned char *
blake2b(unsigned char **data, unsigned long int *size) {
  unsigned char *hash = malloc(crypto_generichash_BYTES);
  memset(hash, 0, crypto_generichash_BYTES);
  crypto_generichash_state state;

  crypto_generichash_init(&state, 0, 0, crypto_generichash_BYTES);

  for (int i = 0; 0 != data[i]; ++i) {
    crypto_generichash_update(&state, data[i], size[i]);
  }

  crypto_generichash_final(&state, hash, crypto_generichash_BYTES);
  return hash;
}

unsigned long int
node(unsigned char **hash, merkle_node_t *node, merkle_node_list_t *roots) {
  *hash = blake2b(
    (unsigned char *[]){ node->data, 0 },
    (unsigned long int []){ node->size, 0 });
  return crypto_generichash_BYTES;
}

unsigned long int
parent(unsigned char **hash, merkle_node_t *left, merkle_node_t *right) {
  *hash = blake2b(
    (unsigned char *[]) { left->hash, right->hash, 0 },
    (unsigned long int []) { left->hash_size, right->hash_size, 0 });
  return crypto_generichash_BYTES;
}

int
main(void) {
  merkle_t merkle = { 0 };
  merkle_options_t options = {
    .codec = (merkle_codec_t) { node, parent }
  };

#ifdef OK_EXPECTED
  ok_expect(OK_EXPECTED);
#else
  ok_expect(0);
#endif

  assert(0 == merkle_init(&merkle, options));

  {
    int i = 0;
    unsigned int count = 0;
    unsigned char data[] = "a";
    unsigned long int length = strlen((char *) data);
    merkle_node_list_t *nodes = merkle_next(&merkle, data, length, 0);

    while (0 != nodes->list[count]) { count++; }

    unsigned char *hash = blake2b(
        (unsigned char *[]) { data, 0 },
        (unsigned long int []) { length, 0 });

    if (0 != hash) {
      if (0 == memcmp(hash, nodes->list[i]->hash, nodes->list[i]->hash_size)) {
        ok("node #%d hash (count=%d)", i, count);
      }

      free(hash);
      hash = 0;
    }

    if (0 == strcmp((char *) nodes->list[i]->data, (char *) data)) {
      ok("node #%d data (count=%d)", i, count);
    }

    if (0 == nodes->list[i]->index) {
      ok("node #%d index (count=%d)", i, count);
    }

    if (1 == nodes->list[i]->parent) {
      ok("node #%d parent (count=%d)", i, count);
    }

    if (1 == nodes->list[i]->size) {
      ok("node #%d parent (count=%d)", i, count);
    }

    if (1 == count) {
      ok("first");
    }

    merkle_node_list_destroy(nodes);
  }

  {
    int i = 0;
    unsigned int count = 0;
    unsigned char data[] = "b";
    unsigned long int length = strlen((char *) data);
    merkle_node_list_t *nodes = merkle_next(&merkle, data, strlen((char *) data), 0);

    while (0 != nodes->list[count]) { count++; }

    /*/
    for (int i = 0; i < count; ++i) {
      printf(
          "node#%d { index=%lu, parent=%lu, size=%lu, hash=%p, data=%p }\n",
          i,
          nodes->list[i]->index,
          nodes->list[i]->parent,
          nodes->list[i]->size,
          nodes->list[i]->hash,
          nodes->list[i]->data
          );
    }
    */

    unsigned char *hash = blake2b(
        (unsigned char *[]) { data, 0 },
        (unsigned long int []) { length, 0 });

    if (0 != hash) {
      if (0 == memcmp(hash, nodes->list[i]->hash, nodes->list[i]->hash_size)) {
        ok("node #%d hash (count=%d)", i, count);
      }

      free(hash);
      hash = 0;
    }

    if (0 == strcmp((char *) nodes->list[i]->data, (char *) data)) {
      ok("node #%d data (count=%d)", i, count);
    }

    if (2 == nodes->list[i]->index) {
      ok("node #%d index (count=%d)", i, count);
    }

    if (1 == nodes->list[i]->parent) {
      ok("node #%d parent (count=%d)", i, count);
    }

    if (1 == nodes->list[i]->size) {
      ok("node #%d size (count=%d)", i, count);
    }

    i = 1;

    {
      unsigned char *a = blake2b(
        (unsigned char *[]) { (unsigned char *) "a", 0 },
        (unsigned long int []) { 1 });

      unsigned char *b = blake2b(
        (unsigned char *[]) { (unsigned char *) "b", 0 },
        (unsigned long int []) { 1 });

      hash = blake2b(
          (unsigned char *[]) { a, b, 0 },
          (unsigned long int []) {
            crypto_generichash_BYTES,
            crypto_generichash_BYTES });

      free(a);
      free(b);
    }

    if (0 != hash) {
      if (0 == memcmp(hash, nodes->list[i]->hash, nodes->list[i]->hash_size)) {
        ok("node #%d hash (count=%d)", i, count);
      }

      free(hash);
      hash = 0;
    }

    if (0 == nodes->list[i]->data) {
      ok("node #%d data (count=%d)", i, count);
    }

    if (1 == nodes->list[i]->index) {
      ok("node #%d index (count=%d)", i, count);
    }

    if (3 == nodes->list[i]->parent) {
      ok("node #%d parent (count=%d)", i, count);
    }

    if (2 == nodes->list[i]->size) {
      ok("node #%d size (count=%d)", i, count);
    }

    if (2 == count) {
      ok("second");
    }

    merkle_node_list_destroy(nodes);
  }

  {
    unsigned int count = 0;
    unsigned char data[] = "c";
    unsigned long int length = strlen((char *) data);
    merkle_node_list_t *nodes = merkle_next(&merkle, data, length, 0);

    while (0 != merkle.roots.list[count]) { count++; }
    if (2 == count) {
      ok("correct number of roots for 3 leafs");
    }
    merkle_node_list_destroy(nodes);
  }

  {
    unsigned int count = 0;
    unsigned char data[] = "d";
    unsigned long int length = strlen((char *) data);
    merkle_node_list_t *nodes = merkle_next(&merkle, data, length, 0);

    while (0 != merkle.roots.list[count]) { count++; }
    if (1 == count) {
      ok("correct number of roots for 4 leafs");
    }
    merkle_node_list_destroy(nodes);
  }

  merkle_destroy(&merkle);
  ok_done();
  return ok_count() == ok_expected() ? 0 : 1;
}
