// Implementation of the swfec C++ port. See fec_swfec.hpp for provenance.
#include "fec_swfec.hpp"

#include <cstring>
#include "zfex.h"   // zfex_swfec_{init,mul,inv,addmul}

namespace swfec {

void CoeffGen::coeffs(uint32_t repair_id, size_t n, uint8_t* out)
{
    CoeffGen g(repair_id);
    size_t i = 0;
    while (i < n) {
        uint64_t v = g.next_u64();
        for (int b = 0; b < 8 && i < n; b++, i++)
            out[i] = (uint8_t)(v >> (8 * b));   // little-endian byte order
    }
}

} // namespace swfec
