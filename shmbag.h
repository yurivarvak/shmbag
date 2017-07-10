
#ifndef SHMBAG
#define SHMBAG

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct shmbag_mgr;
struct shmbag_item;
typedef struct shmbag_mgr *shmbag_mgr_t;
typedef struct shmbag_item *shmbag_item_t;

/* manager protocol */
shmbag_mgr_t shmbag_mgr_open(const char *path, int reset);
int shmbag_mgr_close(shmbag_mgr_t mgr);

shmbag_item_t shmbag_mgr_item_acquire(shmbag_mgr_t mgr, const char *item_id);
shmbag_item_t shmbag_mgr_item_acquire_or_alloc(shmbag_mgr_t mgr, const char *item_id, int64_t size);  /* id & size are optional */
int shmbag_mgr_item_realloc(shmbag_mgr_t mgr, shmbag_item_t item, int64_t new_size);
int shmbag_mgr_item_set_id(shmbag_mgr_t mgr, shmbag_item_t item, const char *new_id);

/* consumer protocol */
shmbag_item_t shmbag_item_get(const char *path, int64_t ofs);

/* common protocol */
int shmbag_item_free(shmbag_item_t item);  /* for mgr items will unlink a reference */
int shmbag_item_close(shmbag_item_t item);
int shmbag_item_read(shmbag_item_t item, int64_t lofs, int64_t size, char *data);
int shmbag_item_write(shmbag_item_t item, int64_t lofs, int64_t size, const char *data);
int shmbag_item_append(shmbag_item_t item, int64_t size, const char *data);
int64_t shmbag_item_get_offset(shmbag_item_t item);
int64_t shmbag_item_get_size(shmbag_item_t item);
int64_t shmbag_item_get_capacity(shmbag_item_t item);
int shmbag_item_get_id(shmbag_item_t item, char *id_buf); // id_buf may be 0 or buffer at least 36 chars
char *shmbag_item_get_ptr(shmbag_item_t item);

#ifdef __cplusplus
}
#endif

#endif  /* SHMBAG */

