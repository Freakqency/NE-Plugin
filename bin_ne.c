#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_io.h>
#include <r_cons.h>
#include <r_list.h>
#include "ne.h"



static ut64 loader;

//ne.c code start
static ut64 r_bin_ne_va_to_la(const ut16 segment, const ut16 offset) {
        return (segment << 4) + offset -0x10 ;
}
static ut64 r_bin_ne_la_to_pa(const struct r_bin_ne_obj_t *bin, ut64 la) {
	return la + (bin->ne_header->cbenttab << 4);
}
RBinAddr *r_bin_ne_get_entrypoint (const struct r_bin_ne_obj_t *bin) {
        const NEHEADER *ne;
        ut64 la;
        RBinAddr *entrypoint;
        if (!bin || !bin->ne_header) {
                return NULL;
        }
        ne = bin->ne_header;
        la=r_bin_ne_va_to_la(ne->cs,ne->ip);
        entrypoint = R_NEW0 (RBinAddr);
        if (entrypoint) {
                entrypoint->vaddr = la;
                entrypoint->paddr = 0x00003031;
        }

        return entrypoint;
}
static int cmp_sections(const void *a, const void *b) {
	const RBinSection *s_a, *s_b;

	s_a = a;
	s_b = b;

	return s_a->vaddr - s_b->vaddr;
}
static RBinSection *r_bin_ne_init_section(const struct r_bin_ne_obj_t *bin,
					  ut64 laddr) {
	RBinSection *section;

	section = R_NEW0 (RBinSection);
	if (section) {
		section->vaddr = laddr;
	}

	return section;
}
// RList *r_bin_ne_get_segments (const struct r_bin_ne_obj_t *bin) {
// 	RList *seg_list;
// 	RListIter *iter;
// 	RBinSection *section;
// 	MZ_image_relocation_entry *relocs;
// 	int i, num_relocs, section_number;
// 	ut16 ss;

// 	if (!bin || !bin->dos_header) {
// 		return NULL;
// 	}

// 	seg_list = r_list_newf (free);
// 	if (!seg_list) {
// 		return NULL;
// 	}

// 	/* Add address of first segment to make sure that it is present
// 	 * even if there are no relocations or there isn't first segment in
// 	 * the relocations. */
// 	section = r_bin_mz_init_section (bin, 0);
// 	if (!section) {
// 		goto err_out;
// 	}
// 	r_list_add_sorted (seg_list, section, cmp_sections);

// 	relocs = bin->relocation_entries;
// 	num_relocs = bin->dos_header->num_relocs;
// 	for (i = 0; i < num_relocs; i++) {
// 		RBinSection c;
// 		ut64 laddr, paddr, section_laddr;
// 		ut16 *curr_seg;
// 		int left;

// 		laddr = r_bin_mz_va_to_la (relocs[i].segment, relocs[i].offset);
// 		if ((laddr + 2) >= bin->load_module_size) {
// 			continue;
// 		}

// 		paddr = r_bin_mz_la_to_pa (bin, laddr);
// 		curr_seg = (ut16 *)r_buf_get_at (bin->b, paddr, &left);
// 		if (left < 2) {
// 			continue;
// 		}

// 		section_laddr = r_bin_mz_va_to_la (r_read_le16 (curr_seg), 0);
// 		if (section_laddr > bin->load_module_size) {
// 			continue;
// 		}

// 		c.vaddr = section_laddr;
// 		if (r_list_find (seg_list, &c, cmp_sections)) {
// 			continue;
// 		}

// 		section = r_bin_mz_init_section (bin, section_laddr);
// 		if (!section) {
// 			goto err_out;
// 		}
// 		r_list_add_sorted (seg_list, section, cmp_sections);
// 	}

// 	/* Add address of stack segment if it's inside the load module. */
// 	ss = bin->dos_header->ss;
// 	if (r_bin_mz_va_to_la (ss, 0) < bin->load_module_size) {
// 		section = r_bin_mz_init_section (bin, r_bin_mz_va_to_la (ss, 0));
// 		if (!section) {
// 			goto err_out;
// 		}
// 		r_list_add_sorted (seg_list, section, cmp_sections);
// 	}

// 	/* Fixup sizes and addresses, set name, permissions and set add flag */
// 	section_number = 0;
// 	r_list_foreach (seg_list, iter, section) {
// 		section->name = r_str_newf ("seg_%03d", section_number);
// 		if (section_number) {
// 			RBinSection *p_section = iter->p->data;
// 			p_section->size = section->vaddr - p_section->vaddr;
// 			p_section->vsize = p_section->size;
// 		}
// 		section->vsize = section->size;
// 		section->paddr = r_bin_mz_la_to_pa (bin, section->vaddr);
// 		section->perm = r_str_rwx ("rwx");
// 		section->add = true;
// 		section_number++;
// 	}
// 	section = r_list_get_top (seg_list);
// 	section->size = bin->load_module_size - section->vaddr;
// 	section->vsize = section->size;

// 	return seg_list;

// err_out:
// 	eprintf ("Error: alloc (RBinSection)\n");
// 	r_list_free (seg_list);

// 	return NULL;
// }       
void *r_bin_ne_free (struct r_bin_ne_obj_t *bin) {
        if (!bin) {
                return NULL;
        }
        free ((void *)bin->dos_header);
        free ((void *)bin->ne_header);
        r_buf_free (bin->b);
        bin->b = NULL;
        free (bin);
        return NULL;
}
static int r_bin_ne_init_hdr(struct r_bin_ne_obj_t *bin) {
 if (!bin) {
  return false;
 }
 if (!(bin->dos_header = malloc (sizeof(Dos_header)))) {
  r_sys_perror ("malloc (dos_header)");
  return false;
 }
 if (r_buf_read_at (bin->b, 0, (ut8*)bin->dos_header, sizeof (Dos_header)) == -1) {
  eprintf("Error: read (dos_header)\n");
  return false;
 }
 if (!(bin->ne_header = malloc (sizeof(NEHEADER)))) {
  r_sys_perror ("malloc (dos_header)");
  return false;
 }
 if (r_buf_read_at (bin->b,bin->dos_header->e_lfanew, (ut8*)bin->ne_header, sizeof (NEHEADER)) == -1) {
  eprintf("Error: read (dos_header)\n");
  return false;
 }
 if (!bin->kv) {
  eprintf("Error: sdb instance is empty\n");
  return false;
 }
 return true;
}
static int r_bin_ne_init(struct r_bin_ne_obj_t *bin) {
        bin->dos_header =NULL;
        bin->ne_header = NULL;
        bin->kv = sdb_new0 ();
        if (!r_bin_ne_init_hdr (bin)) {
                eprintf ("Warning: File is not MZ\n");
                return false;
        }
        return true;
}
struct r_bin_ne_obj_t *r_bin_ne_new (const char *file) {
        const ut8 *buf;
        struct r_bin_ne_obj_t *bin = R_NEW0 (struct r_bin_ne_obj_t);
        if (!bin) {
                return NULL;
        }
        bin->file = file;
        if (!(buf = (ut8 *)r_file_slurp (file, &bin->size))) {
                return r_bin_ne_free (bin);
        }
        bin->b = r_buf_new ();
        if (!r_buf_set_bytes (bin->b, buf, bin->size)) {
                free ((void *)buf);
                return r_bin_ne_free (bin);
        }
        free ((void *)buf);
        if (!r_bin_ne_init (bin)) {
                return r_bin_ne_free (bin);
        }
        return bin;
}
struct r_bin_ne_obj_t *r_bin_ne_new_buf (const RBuffer *buf) {
        struct r_bin_ne_obj_t *bin = R_NEW0 (struct r_bin_ne_obj_t);
        if (!bin) {
                return NULL;
        }

        bin->b = r_buf_new ();
        bin->size = r_buf_size(buf);
        if (!r_buf_set_bytes (bin->b, buf->buf, bin->size)) {
                return r_bin_ne_free (bin);
        }
        return r_bin_ne_init (bin) ? bin : r_bin_ne_free (bin);
}
/*
struct r_bin_ne_obj_t *r_bin_ne_new_buf (const RBuffer *buf) {
	struct r_bin_mz_obj_t *bin = R_NEW0 (struct r_bin_mz_obj_t);
	if (!bin) {
		return NULL;
	}
	bin->b = r_buf_new ();
	bin->size = r_buf_size (buf);
	if (!r_buf_set_bytes (bin->b, buf->buf, bin->size)) {
		return r_bin_mz_free (bin);
	}

	return r_bin_mz_init (bin)? bin: r_bin_mz_free (bin);
}

*/
//ne.c code end

static Sdb *get_sdb(RBinFile *bf) {
        const struct r_bin_ne_obj_t *bin;
        if (bf && bf->o && bf->o->bin_obj) {
                bin = (struct r_bin_ne_obj_t *)bf->o->bin_obj;
                if (bin && bin->kv) {
                        return bin->kv;
                }
        }
        return NULL;
}
static bool check_bytes(const ut8 *buf, ut64 length) {
        unsigned int idx;
 if (!buf) {
  return false;
 }
 if (length <= 0x3d) {
  return false;
 }
 idx = (buf[0x3c] | (buf[0x3d]<<8));
 if (length > idx + 0x18 + 2) {
  if (!memcmp (buf, "MZ", 2)) {
   if (!memcmp (buf+idx, "NE", 2)) {
    return true;
   }
  }
 }
 return false;
}
static void *load(RBinFile *bf, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
        struct r_bin_ne_obj_t *ne_obj;

        ne_obj = r_bin_ne_new_buf (buf);
        if (ne_obj) {
                sdb_ns_set (sdb, "info", ne_obj->kv);
        }
        return ne_obj;
}
static int destroy(RBinFile *bf) {
        r_bin_ne_free ((struct r_bin_ne_obj_t *)bf->o->bin_obj);
        return true;
}
static RList *entries(RBinFile *bf) {
        RBinAddr *ptr = NULL;
        RList *res = NULL;
        if (!(res = r_list_newf (free))) {
                return NULL;
        }
        ptr = r_bin_ne_get_entrypoint (bf->o->bin_obj);
        if (ptr) {
                r_list_append (res, ptr);
        }
        return res;
}
static RBinInfo *info(RBinFile *bf) {
	RBinInfo *const ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("MZ");
	ret->rclass = strdup ("ne");
	ret->os = strdup ("DOS");
	ret->arch = strdup ("x86");
	ret->machine = strdup ("i386");
	ret->type = strdup ("New EXEC (New Executable file)");
	ret->subsystem = strdup ("DOS");
	ret->bits = 16;
	ret->dbg_info = 0;
	ret->big_endian = false;
	ret->has_crypto = false;
	ret->has_canary = false;
	ret->has_retguard = -1;
	ret->has_nx = false;
	ret->has_pi = false;
	ret->has_va = true;
	return ret;
}
#if !R_BIN_NE
struct r_bin_plugin_t r_bin_plugin_ne = {
    .get_sdb = &get_sdb,
    .check_bytes = &check_bytes,
    .load_buffer = &load,
    .destroy = &destroy,
    .name = "ne",
    .desc = "NE",
    .license = "BSD",
    .entries = &entries,
    .info=&info,
    .minstrlen = 4,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
    .type = R_LIB_TYPE_BIN,
    .data = &r_bin_plugin_ne,
    .version = R2_VERSION
};
#endif
#endif
