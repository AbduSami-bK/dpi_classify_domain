#pragma once

#define FQDN_LIST                      \
    X(GOOGLE, "google.com", "Google") \
    X(YOUTUBE, "youtube.com", "YouTube") \
    X(FACEBOOK, "facebook.com", "Facebook") \
    X(GITHUB, "github.com", "GitHub")

enum fqdn_id {
#define X(id, str, name) FQDN_##id,
    FQDN_LIST
#undef X
    FQDN_UNKNOWN,
    FQDN_COUNT
};

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

static inline unsigned int fqdn_pattern_count(void)
{
    return (unsigned int)FQDN_UNKNOWN;
}
