#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include <hs.h>

#include "thread_classifier.h"

// Hard-coded Hyperscan database
static const char **fqdn_list = {
    "google.com",
    "youtube.com",
    "facebook.com",
    "github.com"
};
static const uint8_t fqdn_str_len[] = {
    sizeof ("google.com"),
    sizeof ("youtube.com"),
    sizeof ("facebook.com"),
    sizeof ("github.com")
};
enum fqdn_enum {
    GOOGLE_id,
    YOUTUBE_id,
    FACEBOOK_id,
    GITHUB_id,
    UNKNOWN
};
static const uint8_t fqdn_enum_list[] = {
    GOOGLE_id, YOUTUBE_id, FACEBOOK_id, GITHUB_id
};

extern bool force_quit;
extern uint64_t Google_cnt, YouTube_cnt, FaceBook_cnt, GitHub_cnt, UnKnown_cnt;

int
match_found(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void *context)
{
    switch (id) {
        case GOOGLE_id:
            ++Google_cnt;
            break;
        case YOUTUBE_id:
            ++YouTube_cnt;
            break;
        case FACEBOOK_id:
            ++FaceBook_cnt;
            break;
        case GITHUB_id:
            ++GitHub_cnt;
            break;
    }
    return 0;
}

static int
thread_classifier(__rte_unused void *arg)
{
    hs_database_t *hs_fqdn_db;
    hs_compile_error_t *compile_err;
    hs_scratch_t *scratch_space;
    hs_error_t err;

    // hs_set_allocator(rte_malloc, rte_free);
    hs_compile_lit_multi(fqdn_list, 0, fqdn_enum_list, fqdn_str_len, 4, HS_MODE_VECTORED, NULL, &hs_fqdn_db, &compile_err);
    // hs_free_compile_error(compile_err);
    err = hs_alloc_scratch(hs_fqdn_db, &scratch_space);
    if (err != HS_SUCCESS)
    {
        printf("HyperScan Scratch Allocation failed!");
        return EXIT_FAILURE;
    }

    while (!force_quit) {
        hs_error_t err = hs_scan_vector(hs_fqdn_db, const char *const mbuf, const unsigned int *length, unsigned int len, 0, scratch_space, match_found, void *context)
    }

    hs_free_scratch(scratch_space);
    hs_free_database

    return EXIT_SUCCESS;
}
