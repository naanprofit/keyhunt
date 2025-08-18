#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <cstdint>
#include <iostream>
#include <cassert>

struct BloomHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t tier;
    uint16_t shard;
    uint16_t k;
    uint64_t items;
    uint64_t bytes;
};

int main() {
    const char *path = "test-bloom.dat";
    size_t payload = 1024;
    size_t file_bytes = sizeof(BloomHeader) + payload;
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) { perror("open"); return 1; }
    if (ftruncate(fd, file_bytes) != 0) { perror("ftruncate"); return 1; }
    uint8_t *base = (uint8_t*)mmap(nullptr, file_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) { perror("mmap"); return 1; }
    memset(base, 0, file_bytes);
    BloomHeader hdr{0x4B48424C, 1, 1, 0, 3, 100, payload};
    memcpy(base, &hdr, sizeof(hdr));
    msync(base, file_bytes, MS_SYNC);
    for (size_t i = 0; i < payload; ++i) {
        if (base[sizeof(BloomHeader)+i] != 0) { std::cerr << "nonzero"; return 1; }
    }
    base[sizeof(BloomHeader)+1] = 0xAA;
    base[sizeof(BloomHeader)+100] = 0x55;
    msync(base, file_bytes, MS_SYNC);
    munmap(base, file_bytes);
    close(fd);

    fd = open(path, O_RDONLY);
    std::vector<uint8_t> buf(file_bytes);
    read(fd, buf.data(), file_bytes);
    close(fd);
    size_t ff = 0;
    for (size_t i = sizeof(BloomHeader); i < buf.size(); ++i) {
        if (buf[i] == 0xFF) ff++;
    }
    assert(ff < payload);
    std::cout << "ff%=" << (100.0 * ff / payload) << std::endl;
    return 0;
}
