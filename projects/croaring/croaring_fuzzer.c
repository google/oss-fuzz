#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "roaring/roaring.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    roaring_statistics_t stats;
    bool answer = true;
    roaring_bitmap_t* bitmap = roaring_bitmap_portable_deserialize_safe(data, size);
    if(bitmap) {
        uint64_t card1 = roaring_bitmap_get_cardinality(bitmap);
        roaring_bitmap_statistics(bitmap, &stats);
        unsigned universe_size = stats.max_value + 1;
        roaring_bitmap_t *inverted = roaring_bitmap_flip(bitmap, 0U, universe_size);
        if(inverted) {
            roaring_bitmap_t *double_inverted = roaring_bitmap_flip(inverted, 0U, universe_size);
            if(double_inverted)
            {
                answer = (roaring_bitmap_get_cardinality(inverted) + roaring_bitmap_get_cardinality(bitmap) == universe_size);
                if (answer) answer = roaring_bitmap_equals(bitmap, double_inverted);
                if (!answer) {
                    printf("Bad flip\n\nbitmap1:\n");
                    roaring_bitmap_printf_describe(bitmap);  // debug
                    printf("\n\nflipped:\n");
                    roaring_bitmap_printf_describe(inverted);  // debug
                }
                roaring_bitmap_free(double_inverted);
            }
            roaring_bitmap_free(inverted);
        }
        roaring_bitmap_free(bitmap);
    }
    return 0;
}