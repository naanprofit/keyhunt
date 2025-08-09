ARCH := $(shell uname -m)

ifeq ($(ARCH),aarch64)
ARCH_FLAGS := -march=armv8-a -mtune=generic -U__SSE2__
HASH_OBJS := hash/ripemd160.o hash/sha256.o hash/ripemd160_neon.o hash/sha256_neon.o
else
ARCH_FLAGS := -m64 -march=native -mtune=native -mssse3
HASH_OBJS := hash/ripemd160.o hash/sha256.o hash/ripemd160_sse.o hash/sha256_sse.o
endif

CXXFLAGS := $(ARCH_FLAGS) -Wall -Wextra -Wno-deprecated-copy -Ofast -ftree-vectorize
CFLAGS := $(ARCH_FLAGS) -Wall -Wextra -Ofast -ftree-vectorize

.RECIPEPREFIX = >

default:
>g++ $(CXXFLAGS) -flto -c oldbloom/bloom.cpp -o oldbloom.o
>g++ $(CXXFLAGS) -flto -c bloom/bloom.cpp -o bloom.o
>gcc $(CFLAGS) -Wno-unused-parameter -c base58/base58.c -o base58.o
>gcc $(CFLAGS) -c rmd160/rmd160.c -o rmd160.o
>g++ $(CXXFLAGS) -c sha3/sha3.c -o sha3.o
>g++ $(CXXFLAGS) -c sha3/keccak.c -o keccak.o
>gcc $(CFLAGS) -c xxhash/xxhash.c -o xxhash.o
>g++ $(CXXFLAGS) -c util.c -o util.o
>g++ $(CXXFLAGS) -c secp256k1/Int.cpp -o Int.o
>g++ $(CXXFLAGS) -c secp256k1/Point.cpp -o Point.o
>g++ $(CXXFLAGS) -c secp256k1/SECP256K1.cpp -o SECP256K1.o
>g++ $(CXXFLAGS) -c secp256k1/IntMod.cpp -o IntMod.o
>g++ $(CXXFLAGS) -flto -c secp256k1/Random.cpp -o Random.o
>g++ $(CXXFLAGS) -flto -c secp256k1/IntGroup.cpp -o IntGroup.o
>g++ $(CXXFLAGS) -flto -c hash/ripemd160.cpp -o hash/ripemd160.o
>g++ $(CXXFLAGS) -flto -c hash/sha256.cpp -o hash/sha256.o
ifeq ($(ARCH),aarch64)
>g++ $(CXXFLAGS) -flto -c hash/ripemd160_neon.cpp -o hash/ripemd160_neon.o
>g++ $(CXXFLAGS) -flto -c hash/sha256_neon.cpp -o hash/sha256_neon.o
else
>g++ $(CXXFLAGS) -flto -c hash/ripemd160_sse.cpp -o hash/ripemd160_sse.o
>g++ $(CXXFLAGS) -flto -c hash/sha256_sse.cpp -o hash/sha256_sse.o
endif
>g++ $(CXXFLAGS) -o keyhunt keyhunt.cpp base58.o rmd160.o $(HASH_OBJS) bloom.o oldbloom.o xxhash.o util.o Int.o Point.o SECP256K1.o IntMod.o Random.o IntGroup.o sha3.o keccak.o -lm -lpthread
>rm -r *.o

clean:
>rm -f keyhunt

legacy:
>g++ $(CXXFLAGS) -flto -c oldbloom/bloom.cpp -o oldbloom.o
>g++ $(CXXFLAGS) -flto -c bloom/bloom.cpp -o bloom.o
>gcc $(CFLAGS) -Wno-unused-result -c base58/base58.c -o base58.o
>gcc $(CFLAGS) -c xxhash/xxhash.c -o xxhash.o
>g++ $(CXXFLAGS) -c util.c -o util.o
>g++ $(CXXFLAGS) -c sha3/sha3.c -o sha3.o
>g++ $(CXXFLAGS) -c sha3/keccak.c -o keccak.o
>g++ $(CXXFLAGS) -c hashing.c -o hashing.o
>g++ $(CXXFLAGS) -c gmp256k1/Int.cpp -o Int.o
>g++ $(CXXFLAGS) -c gmp256k1/Point.cpp -o Point.o
>g++ $(CXXFLAGS) -c gmp256k1/GMP256K1.cpp -o GMP256K1.o
>g++ $(CXXFLAGS) -c gmp256k1/IntMod.cpp -o IntMod.o
>g++ $(CXXFLAGS) -flto -c gmp256k1/Random.cpp -o Random.o
>g++ $(CXXFLAGS) -flto -c gmp256k1/IntGroup.cpp -o IntGroup.o
>g++ $(CXXFLAGS) -o keyhunt keyhunt_legacy.cpp base58.o bloom.o oldbloom.o xxhash.o util.o Int.o Point.o GMP256K1.o IntMod.o IntGroup.o Random.o hashing.o sha3.o keccak.o -lm -lpthread -lcrypto -lgmp
>rm -r *.o

bsgsd:
>g++ $(CXXFLAGS) -flto -c oldbloom/bloom.cpp -o oldbloom.o
>g++ $(CXXFLAGS) -flto -c bloom/bloom.cpp -o bloom.o
>gcc $(CFLAGS) -Wno-unused-parameter -c base58/base58.c -o base58.o
>gcc $(CFLAGS) -c rmd160/rmd160.c -o rmd160.o
>g++ $(CXXFLAGS) -c sha3/sha3.c -o sha3.o
>g++ $(CXXFLAGS) -c sha3/keccak.c -o keccak.o
>gcc $(CFLAGS) -c xxhash/xxhash.c -o xxhash.o
>g++ $(CXXFLAGS) -c util.c -o util.o
>g++ $(CXXFLAGS) -c secp256k1/Int.cpp -o Int.o
>g++ $(CXXFLAGS) -c secp256k1/Point.cpp -o Point.o
>g++ $(CXXFLAGS) -c secp256k1/SECP256K1.cpp -o SECP256K1.o
>g++ $(CXXFLAGS) -c secp256k1/IntMod.cpp -o IntMod.o
>g++ $(CXXFLAGS) -flto -c secp256k1/Random.cpp -o Random.o
>g++ $(CXXFLAGS) -flto -c secp256k1/IntGroup.cpp -o IntGroup.o
>g++ $(CXXFLAGS) -flto -c hash/ripemd160.cpp -o hash/ripemd160.o
>g++ $(CXXFLAGS) -flto -c hash/sha256.cpp -o hash/sha256.o
ifeq ($(ARCH),aarch64)
>g++ $(CXXFLAGS) -flto -c hash/ripemd160_neon.cpp -o hash/ripemd160_neon.o
>g++ $(CXXFLAGS) -flto -c hash/sha256_neon.cpp -o hash/sha256_neon.o
else
>g++ $(CXXFLAGS) -flto -c hash/ripemd160_sse.cpp -o hash/ripemd160_sse.o
>g++ $(CXXFLAGS) -flto -c hash/sha256_sse.cpp -o hash/sha256_sse.o
endif
>g++ $(CXXFLAGS) -o bsgsd bsgsd.cpp base58.o rmd160.o $(HASH_OBJS) bloom.o oldbloom.o xxhash.o util.o Int.o Point.o SECP256K1.o IntMod.o Random.o IntGroup.o sha3.o keccak.o -lm -lpthread
>rm -r *.o

