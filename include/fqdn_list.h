#pragma once

/**
 * @file fqdn_list.h
 * @brief Single source of truth for FQDN patterns and display names.
 */

#define FQDN_LIST                        \
    X(GOOGLE, "google.com", "Google")    \
    X(YOUTUBE, "youtube.com", "YouTube") \
    X(FACEBOOK, "facebook.com", "Facebook") \
    X(GITHUB, "github.com", "GitHub")

/** FQDN identifiers. */
enum fqdn_id {
#define X(id, str, name) FQDN_##id,
    FQDN_LIST
#undef X
    FQDN_UNKNOWN,
    FQDN_COUNT
};

/** @brief Human-readable name for an FQDN id. */
static inline const char *fqdn_name(enum fqdn_id id)
{
    switch (id) {
#define X(id, str, name) case FQDN_##id: return name;
        FQDN_LIST
#undef X
    case FQDN_UNKNOWN:
    default:
        return "Unknown";
    }
}

/** @brief Pattern string for an FQDN id. */
static inline const char *fqdn_pattern(enum fqdn_id id)
{
    switch (id) {
#define X(id, str, name) case FQDN_##id: return str;
        FQDN_LIST
#undef X
    case FQDN_UNKNOWN:
    default:
        return NULL;
    }
}

/** @brief Number of literal patterns (excluding Unknown). */
static inline unsigned int fqdn_pattern_count(void)
{
    return (unsigned int)FQDN_UNKNOWN;
}
