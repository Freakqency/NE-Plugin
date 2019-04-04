#include <r_types.h>
#include <r_list.h>
#include <r_util.h>
#include <r_bin.h>
#include "ne_specs.h"





struct r_bin_ne_obj_t {
	const NEHEADER *ne_header;
	const Dos_header *dos_header;	
	int size;
	const char *file;
	struct r_buf_t *b;
	Sdb *kv;
};

RBinAddr *r_bin_ne_get_entrypoint (const struct r_bin_ne_obj_t *bin);
void *r_bin_ne_free (struct r_bin_ne_obj_t *bin);
struct r_bin_ne_obj_t *r_bin_ne_new (const char *file);
struct r_bin_ne_obj_t *r_bin_ne_new_buf (const RBuffer *buf);
