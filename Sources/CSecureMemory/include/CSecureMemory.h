#ifndef CSECUREMEMORY_H
#define CSECUREMEMORY_H
#include <stddef.h>
#include <stdbool.h>

/// Zero `len` bytes at `ptr` in a way the compiler may not elide (C11 memset_s).
void pv_memzero(void *ptr, size_t len);
/// Constant-time comparison of `len` bytes. Returns true if equal.
bool pv_ct_equal(const void *a, const void *b, size_t len);
/// Best-effort: pin pages so they are not swapped. Returns true on success.
bool pv_mlock(void *ptr, size_t len);
/// Best-effort: unpin pages previously pinned with pv_mlock.
bool pv_munlock(void *ptr, size_t len);

#endif

/// sqlite3_db_config(SQLITE_DBCONFIG_DEFENSIVE) is variadic and not callable from Swift; this wraps it.
/// `db` is a sqlite3* handle. Returns the SQLite result code.
int pv_sqlite_set_defensive(void *db);
