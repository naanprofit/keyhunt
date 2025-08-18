#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "../bloom/bloom.h"
#include "../bloom/bloomfile.h"

int main() {
    const char *path = "bloom-0.dat";
    ::unlink(path);
    uint16_t tier = 1; uint16_t shard = 0;
    uint64_t items = 1000;
    uint64_t m_bits; uint32_t k;
    bloom_size_params(items, 0.001, m_bits, k);
    size_t payload_bytes = (m_bits + 7) / 8;
    size_t header_sz = sizeof(BloomHeader);
    size_t file_bytes = header_sz + payload_bytes;
    int fd = ::open(path, O_RDWR | O_CREAT, 0644);
    assert(fd >= 0);
    assert(::ftruncate(fd, file_bytes) == 0);
    uint8_t *base = (uint8_t*)::mmap(NULL, file_bytes, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    assert(base != MAP_FAILED);
    ::memset(base, 0, file_bytes);
    BloomHeader hdr{0x4B48424C,1,tier,shard,(uint16_t)k,items,payload_bytes};
    write_header(base, hdr);
    ::msync(base, file_bytes, MS_SYNC);
    ::close(fd);
    uint8_t *payload = base + header_sz;
    for(size_t i=0;i<payload_bytes;i++) assert(payload[i]==0);
    struct bloom b{};
    b.bf = payload;
    b.bytes = payload_bytes;
    b.bits = m_bits;
    b.entries = items;
    b.hashes = (uint8_t)k;
    b.ready = 1;
    const char *a="abc"; bloom_add(&b,a,3);
    const char *d="def"; bloom_add(&b,d,3);
    ::msync(payload, payload_bytes, MS_SYNC);
    size_t ff=0;
    for(size_t i=0;i<payload_bytes;i++) if(payload[i]==0xff) ff++;
    assert(ff < payload_bytes);
    ::munmap(base, file_bytes);
    ::unlink(path);
    return 0;
}
