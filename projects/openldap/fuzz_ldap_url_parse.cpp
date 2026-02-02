/*
 * LibFuzzer harness for OpenLDAP ldap_url_parse API
 *
 * Public API Used:
 *   - ldap_url_parse(const char *url, LDAPURLDesc **ludpp)
 *   - ldap_free_urldesc(LDAPURLDesc *ludp)
 *
 * Documentation Consulted:
 *   - /src/openldap/doc/man/man3/ldap_url.3
 *   - /src/openldap/include/ldap.h
 *
 * Target: LDAP URL parsing functionality
 * Offline-safe: Yes (pure parsing, no network operations)
 *
 * This harness fuzzes the LDAP URL parser which handles URLs in the format:
 *   ldap[s]://[host[:port]][/[dn[?[attrs][?[scope][?[filter][?exts]]]]]]
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

extern "C" {
#include <ldap.h>
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Bound input size to prevent excessive memory usage
    // LDAP URLs are typically short; 64KB is more than reasonable
    if (size == 0 || size > 65536) {
        return 0;
    }

    // Create null-terminated string for ldap_url_parse
    // Use stack allocation for small inputs, heap for larger ones
    char *url_str;
    char stack_buf[1024];

    if (size < sizeof(stack_buf)) {
        url_str = stack_buf;
    } else {
        url_str = (char *)malloc(size + 1);
        if (!url_str) {
            return 0;
        }
    }

    memcpy(url_str, data, size);
    url_str[size] = '\0';

    // Parse the URL using public API
    LDAPURLDesc *ludp = NULL;
    int rc = ldap_url_parse(url_str, &ludp);

    // If parsing succeeded, the structure was allocated
    // Free it using the public API
    if (rc == LDAP_URL_SUCCESS && ludp != NULL) {
        ldap_free_urldesc(ludp);
    }

    // Clean up heap allocation if used
    if (size >= sizeof(stack_buf)) {
        free(url_str);
    }

    return 0;
}
