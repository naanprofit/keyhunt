/*
 * This file is part of the BSGS distribution (https://github.com/JeanLucPons/BSGS).
 * Copyright (c) 2020 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include "SECP256k1.h"
#include "Point.h"
#include "../util.h"
#include "../hash/sha256.h"
#include "../hash/ripemd160.h"

namespace {

using Uint256 = std::array<uint64_t, 4>;
using Uint512 = std::array<uint64_t, 8>;

static Uint256 IntToUint256(const Int &value) {
  Uint256 out{};
  for (size_t i = 0; i < 4; ++i) {
    out[i] = value.bits64[i];
  }
  return out;
}

static void Uint256ToInt(const Uint256 &src, Int &dst) {
  for (size_t i = 0; i < 4; ++i) {
    dst.bits64[i] = src[i];
  }
  dst.bits64[4] = 0;
}

static void Mul256(const Uint256 &a, const Uint256 &b, Uint512 &out) {
  out.fill(0);
  for (size_t i = 0; i < 4; ++i) {
    unsigned __int128 carry = 0;
    for (size_t j = 0; j < 4; ++j) {
      unsigned __int128 prod = static_cast<unsigned __int128>(a[i]) * static_cast<unsigned __int128>(b[j]);
      unsigned __int128 sum = prod + static_cast<unsigned __int128>(out[i + j]) + carry;
      out[i + j] = static_cast<uint64_t>(sum);
      carry = sum >> 64;
    }
    size_t pos = i + 4;
    while (carry != 0 && pos < out.size()) {
      unsigned __int128 sum = static_cast<unsigned __int128>(out[pos]) + (carry & 0xFFFFFFFFFFFFFFFFULL);
      out[pos] = static_cast<uint64_t>(sum);
      carry = sum >> 64;
      ++pos;
    }
  }
}

static void AddBit(Uint512 &value, int bit) {
  size_t idx = static_cast<size_t>(bit / 64);
  uint64_t mask = 1ULL << (bit % 64);
  uint64_t carry = mask;
  for (size_t i = idx; i < value.size() && carry; ++i) {
    uint64_t prev = value[i];
    value[i] += carry;
    carry = value[i] < prev ? 1ULL : 0ULL;
  }
}

static Uint256 ShiftRight(const Uint512 &value, int shiftBits) {
  Uint256 result{};
  int wordShift = shiftBits / 64;
  int bitShift = shiftBits % 64;
  for (int i = wordShift; i < static_cast<int>(value.size()); ++i) {
    uint64_t low = value[i];
    uint64_t high = (i + 1 < static_cast<int>(value.size())) ? value[i + 1] : 0;
    uint64_t combined = bitShift == 0 ? low : (low >> bitShift) | (high << (64 - bitShift));
    int dest = i - wordShift;
    if (dest >= 0 && dest < static_cast<int>(result.size())) {
      result[dest] = combined;
    }
  }
  return result;
}

static void ComputeWNAF(Int value, unsigned int window, std::vector<int8_t> &wnaf) {
  wnaf.clear();
  if (value.IsZero()) {
    return;
  }

  Int twoPowW;
  twoPowW.SetInt32(1);
  twoPowW.ShiftL(window);
  Int half(twoPowW);
  half.ShiftR(1);

  while (!value.IsZero()) {
    int8_t digit = 0;
    if (value.IsOdd()) {
      Int mod(value);
      mod.Mod(&twoPowW);
      uint64_t modVal = mod.bits64[0];
      if (modVal > half.bits64[0]) {
        modVal -= twoPowW.bits64[0];
      }
      digit = static_cast<int8_t>(modVal);
      Int adjust;
      adjust.SetInt32(static_cast<uint32_t>(digit > 0 ? digit : -digit));
      if (digit > 0) {
        value.Sub(&adjust);
      } else {
        value.Add(&adjust);
      }
    }
    wnaf.push_back(digit);
    value.ShiftR(1);
  }
}

static unsigned int ChoosePippengerWindow(size_t nPoints) {
  if (nPoints <= 2) {
    return 3;
  }
  if (nPoints <= 4) {
    return 4;
  }
  if (nPoints <= 8) {
    return 5;
  }
  if (nPoints <= 16) {
    return 6;
  }
  return 7;
}

}

Secp256K1::Secp256K1() {
}

void Secp256K1::Init() {
  // Prime for the finite field
  P.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

  // Set up field
  Int::SetupField(&P);

  // Generator point and order
  G.x.SetBase16("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
  G.y.SetBase16("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
  G.z.SetInt32(1);
  order.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

  Int::InitK1(&order);
  lambda.SetBase16("5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72");
  minus_b1.SetBase16("00000000000000000000000000000000E4437ED6010E88286F547FA90ABFE4C3");
  minus_b2.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE8A280AC50774346DD765CDA83DB1562C");
  g1Const.SetBase16("3086D221A7D46BCDE86C90E49284EB153DAA8A1471E8CA7FE893209A45DBB031");
  g2Const.SetBase16("E4437ED6010E88286F547FA90ABFE4C4221208AC9DF506C61571B4AE8AC47F71");

  Int three;
  three.SetInt32(3);
  Int minusThree(&three);
  minusThree.ModNeg();
  Int sqrtMinusThree(&minusThree);
  sqrtMinusThree.ModSqrt();
  Int one;
  one.SetInt32(1);
  Int two;
  two.SetInt32(2);
  Int invTwo(&two);
  invTwo.ModInv();

  beta.Set(&sqrtMinusThree);
  beta.ModSub(&one);
  beta.ModMul(&invTwo);
  if (beta.IsOne()) {
    Int alt(&sqrtMinusThree);
    alt.ModNeg();
    alt.ModSub(&one);
    alt.ModMul(&invTwo);
    beta.Set(&alt);
  }

  baseWindow = 7;
  baseOddMultiples = BuildOddMultiples(G, baseWindow);

}

Secp256K1::~Secp256K1() {
}

Point Secp256K1::ComputePublicKey(Int *privKey) {
  return ScalarBaseMultiplication(privKey);
}

std::vector<Point> Secp256K1::BuildOddMultiples(Point base, unsigned int window) {
  if (window < 2) {
    window = 2;
  }
  size_t tableSize = 1u << (window - 2);
  std::vector<Point> table(tableSize);
  if (base.z.IsZero()) {
    for (auto &p : table) {
      p.Clear();
    }
    return table;
  }
  if (!base.z.IsOne()) {
    base.Reduce();
  }
  table[0] = base;
  if (tableSize == 1) {
    return table;
  }
  Point twoP = DoubleDirect(base);
  twoP.Reduce();
  Point current = base;
  for (size_t i = 1; i < tableSize; ++i) {
    current = AddDirect(current, twoP);
    current.Reduce();
    table[i] = current;
  }
  return table;
}

Point Secp256K1::ApplyEndomorphism(Point &p) {
  Point affine(p);
  if (affine.z.IsZero()) {
    return affine;
  }
  if (!affine.z.IsOne()) {
    affine.Reduce();
  }
  affine.x.ModMulK1(&affine.x, &beta);
  affine.z.SetInt32(1);
  return affine;
}

void Secp256K1::DecomposeScalar(Int *scalar, Int &r1, Int &r2) {
  Int k(scalar);
  k.Mod(&order);

  Uint256 kArr = IntToUint256(k);
  Uint256 g1Arr = IntToUint256(g1Const);
  Uint256 g2Arr = IntToUint256(g2Const);

  Uint512 prod1;
  Mul256(kArr, g1Arr, prod1);
  AddBit(prod1, 383);
  Uint256 c1Arr = ShiftRight(prod1, 384);

  Uint512 prod2;
  Mul256(kArr, g2Arr, prod2);
  AddBit(prod2, 383);
  Uint256 c2Arr = ShiftRight(prod2, 384);

  Int c1;
  Uint256ToInt(c1Arr, c1);
  Int c2;
  Uint256ToInt(c2Arr, c2);

  Int term1(&minus_b1);
  term1.ModMulK1order(&c1);
  Int term2(&minus_b2);
  term2.ModMulK1order(&c2);

  Int sum;
  sum.ModAddK1order(&term1, &term2);

  Int prodLambda(sum);
  prodLambda.ModMulK1order(&lambda);

  Int r1tmp(&k);
  r1tmp.Sub(&prodLambda);
  if (r1tmp.IsNegative()) {
    r1tmp.Add(&order);
  }
  r1tmp.Mod(&order);

  r1.Set(&r1tmp);
  r2.Set(&sum);
}

Point Secp256K1::NextKey(Point &key) {
  // Input key must be reduced and different from G
  // in order to use AddDirect
  return AddDirect(key,G);
}

uint8_t Secp256K1::GetByte(char *str, int idx) {
  char tmp[3];
  int  val;
  tmp[0] = str[2 * idx];
  tmp[1] = str[2 * idx + 1];
  tmp[2] = 0;
  if (sscanf(tmp, "%X", &val) != 1) {
    printf("ParsePublicKeyHex: Error invalid public key specified (unexpected hexadecimal digit)\n");
    exit(-1);
  }
  return (uint8_t)val;
}

Point Secp256K1::Negation(Point &p) {
  Point Q;
  Q.Clear();
  Q.x.Set(&p.x);
  Q.y.Set(&this->P);
  Q.y.Sub(&p.y);
  Q.z.SetInt32(1);
  return Q;
}


bool Secp256K1::ParsePublicKeyHex(char *str,Point &ret,bool &isCompressed) {
  int len = strlen(str);
  ret.Clear();
  if (len < 2) {
    printf("ParsePublicKeyHex: Error invalid public key specified (66 or 130 character length)\n");
    return false;
  }
  uint8_t type = GetByte(str, 0);
  switch (type) {
    case 0x02:
      if (len != 66) {
        printf("ParsePublicKeyHex: Error invalid public key specified (66 character length)\n");
        return false;
      }
      for (int i = 0; i < 32; i++)
        ret.x.SetByte(31 - i, GetByte(str, i + 1));
      ret.y = GetY(ret.x, true);
      isCompressed = true;
      break;

    case 0x03:
      if (len != 66) {
        printf("ParsePublicKeyHex: Error invalid public key specified (66 character length)\n");
        return false;
      }
      for (int i = 0; i < 32; i++)
        ret.x.SetByte(31 - i, GetByte(str, i + 1));
      ret.y = GetY(ret.x, false);
      isCompressed = true;
      break;

    case 0x04:
      if (len != 130) {
        printf("ParsePublicKeyHex: Error invalid public key specified (130 character length)\n");
        exit(-1);
      }
      for (int i = 0; i < 32; i++)
        ret.x.SetByte(31 - i, GetByte(str, i + 1));
      for (int i = 0; i < 32; i++)
        ret.y.SetByte(31 - i, GetByte(str, i + 33));
      isCompressed = false;
      break;

    default:
      printf("ParsePublicKeyHex: Error invalid public key specified (Unexpected prefix (only 02,03 or 04 allowed)\n");
      return false;
  }

  ret.z.SetInt32(1);

  if (!EC(ret)) {
    printf("ParsePublicKeyHex: Error invalid public key specified (Not lie on elliptic curve)\n");
    return false;
  }

  return true;
}

char* Secp256K1::GetPublicKeyHex(bool compressed, Point &pubKey) {
  unsigned char publicKeyBytes[65];
  char *ret = NULL;
  if (!compressed) {
    //Uncompressed public key
    publicKeyBytes[0] = 0x4;
    pubKey.x.Get32Bytes(publicKeyBytes + 1);
    pubKey.y.Get32Bytes(publicKeyBytes + 33);
    ret = (char*) tohex((char*)publicKeyBytes,65);
  }
  else {
    // Compressed public key
    publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
    pubKey.x.Get32Bytes(publicKeyBytes + 1);
    ret = (char*) tohex((char*)publicKeyBytes,33);
  }
  return ret;
}

void Secp256K1::GetPublicKeyHex(bool compressed, Point &pubKey,char *dst){
  unsigned char publicKeyBytes[65];
  if (!compressed) {
    //Uncompressed public key
    publicKeyBytes[0] = 0x4;
    pubKey.x.Get32Bytes(publicKeyBytes + 1);
    pubKey.y.Get32Bytes(publicKeyBytes + 33);
    tohex_dst((char*)publicKeyBytes,65,dst);
  }
  else {
    // Compressed public key
    publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
    pubKey.x.Get32Bytes(publicKeyBytes + 1);
	tohex_dst((char*)publicKeyBytes,33,dst);
  }
}

char* Secp256K1::GetPublicKeyRaw(bool compressed, Point &pubKey) {
  char *ret = (char*) malloc(65);
  if(ret == NULL) {
    ::fprintf(stderr,"Can't alloc memory\n");
    exit(0);
  }
  if (!compressed) {
    //Uncompressed public key
    ret[0] = 0x4;
    pubKey.x.Get32Bytes((unsigned char*) (ret + 1));
    pubKey.y.Get32Bytes((unsigned char*) (ret + 33));
  }
  else {
    // Compressed public key
    ret[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
    pubKey.x.Get32Bytes((unsigned char*) (ret + 1));
  }
  return ret;
}

void Secp256K1::GetPublicKeyRaw(bool compressed, Point &pubKey,char *dst) {
  if (!compressed) {
    //Uncompressed public key
    dst[0] = 0x4;
    pubKey.x.Get32Bytes((unsigned char*) (dst + 1));
    pubKey.y.Get32Bytes((unsigned char*) (dst + 33));
  }
  else {
    // Compressed public key
    dst[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
    pubKey.x.Get32Bytes((unsigned char*) (dst + 1));
  }
}

Point Secp256K1::AddDirect(Point &p1,Point &p2) {
  Int _s;
  Int _p;
  Int dy;
  Int dx;
  Point r;
  r.z.SetInt32(1);

  dy.ModSub(&p2.y,&p1.y);
  dx.ModSub(&p2.x,&p1.x);
  dx.ModInv();
  _s.ModMulK1(&dy,&dx);     // s = (p2.y-p1.y)*inverse(p2.x-p1.x);

  _p.ModSquareK1(&_s);       // _p = pow2(s)

  r.x.ModSub(&_p,&p1.x);
  r.x.ModSub(&p2.x);       // rx = pow2(s) - p1.x - p2.x;

  r.y.ModSub(&p2.x,&r.x);
  r.y.ModMulK1(&_s);
  r.y.ModSub(&p2.y);       // ry = - p2.y - s*(ret.x-p2.x);

  return r;
}


Point Secp256K1::Add2(Point &p1, Point &p2) {
  // P2.z = 1
  Int u;
  Int v;
  Int u1;
  Int v1;
  Int vs2;
  Int vs3;
  Int us2;
  Int a;
  Int us2w;
  Int vs2v2;
  Int vs3u2;
  Int _2vs2v2;
  Point r;
  u1.ModMulK1(&p2.y, &p1.z);
  v1.ModMulK1(&p2.x, &p1.z);
  u.ModSub(&u1, &p1.y);
  v.ModSub(&v1, &p1.x);
  us2.ModSquareK1(&u);
  vs2.ModSquareK1(&v);
  vs3.ModMulK1(&vs2, &v);
  us2w.ModMulK1(&us2, &p1.z);
  vs2v2.ModMulK1(&vs2, &p1.x);
  _2vs2v2.ModAdd(&vs2v2, &vs2v2);
  a.ModSub(&us2w, &vs3);
  a.ModSub(&_2vs2v2);

  r.x.ModMulK1(&v, &a);

  vs3u2.ModMulK1(&vs3, &p1.y);
  r.y.ModSub(&vs2v2, &a);
  r.y.ModMulK1(&r.y, &u);
  r.y.ModSub(&vs3u2);

  r.z.ModMulK1(&vs3, &p1.z);

  return r;
}

Point Secp256K1::Add(Point &p1,Point &p2) {
  Int u;
  Int v;
  Int u1;
  Int u2;
  Int v1;
  Int v2;
  Int vs2;
  Int vs3;
  Int us2;
  Int w;
  Int a;
  Int us2w;
  Int vs2v2;
  Int vs3u2;
  Int _2vs2v2;
  Int x3;
  Int vs3y1;
  Point r;

  /*
  U1 = Y2 * Z1
  U2 = Y1 * Z2
  V1 = X2 * Z1
  V2 = X1 * Z2
  if (V1 == V2)
    if (U1 != U2)
      return POINT_AT_INFINITY
    else
      return POINT_DOUBLE(X1, Y1, Z1)
  U = U1 - U2
  V = V1 - V2
  W = Z1 * Z2
  A = U ^ 2 * W - V ^ 3 - 2 * V ^ 2 * V2
  X3 = V * A
  Y3 = U * (V ^ 2 * V2 - A) - V ^ 3 * U2
  Z3 = V ^ 3 * W
  return (X3, Y3, Z3)
  */

  u1.ModMulK1(&p2.y,&p1.z);
  u2.ModMulK1(&p1.y,&p2.z);
  v1.ModMulK1(&p2.x,&p1.z);
  v2.ModMulK1(&p1.x,&p2.z);
  u.ModSub(&u1,&u2);
  v.ModSub(&v1,&v2);
  w.ModMulK1(&p1.z,&p2.z);
  us2.ModSquareK1(&u);
  vs2.ModSquareK1(&v);
  vs3.ModMulK1(&vs2,&v);
  us2w.ModMulK1(&us2,&w);
  vs2v2.ModMulK1(&vs2,&v2);
  _2vs2v2.ModAdd(&vs2v2,&vs2v2);
  a.ModSub(&us2w,&vs3);
  a.ModSub(&_2vs2v2);

  r.x.ModMulK1(&v,&a);

  vs3u2.ModMulK1(&vs3,&u2);
  r.y.ModSub(&vs2v2,&a);
  r.y.ModMulK1(&r.y,&u);
  r.y.ModSub(&vs3u2);

  r.z.ModMulK1(&vs3,&w);

  return r;
}

Point Secp256K1::DoubleDirect(Point &p) {
  Int _s;
  Int _p;
  Int a;
  Point r;
  r.z.SetInt32(1);
  _s.ModMulK1(&p.x,&p.x);
  _p.ModAdd(&_s,&_s);
  _p.ModAdd(&_s);

  a.ModAdd(&p.y,&p.y);
  a.ModInv();
  _s.ModMulK1(&_p,&a);     // s = (3*pow2(p.x))*inverse(2*p.y);

  _p.ModMulK1(&_s,&_s);
  a.ModAdd(&p.x,&p.x);
  a.ModNeg();
  r.x.ModAdd(&a,&_p);    // rx = pow2(s) + neg(2*p.x);

  a.ModSub(&r.x,&p.x);

  _p.ModMulK1(&a,&_s);
  r.y.ModAdd(&_p,&p.y);
  r.y.ModNeg();           // ry = neg(p.y + s*(ret.x+neg(p.x)));
  return r;
}

Point Secp256K1::Double(Point &p) {
  /*
  if (Y == 0)
    return POINT_AT_INFINITY
    W = a * Z ^ 2 + 3 * X ^ 2
    S = Y * Z
    B = X * Y*S
    H = W ^ 2 - 8 * B
    X' = 2*H*S
    Y' = W*(4*B - H) - 8*Y^2*S^2
    Z' = 8*S^3
    return (X', Y', Z')
  */
  Int z2;
  Int x2;
  Int _3x2;
  Int w;
  Int s;
  Int s2;
  Int b;
  Int _8b;
  Int _8y2s2;
  Int y2;
  Int h;
  Point r;
  z2.ModSquareK1(&p.z);
  z2.SetInt32(0); // a=0
  x2.ModSquareK1(&p.x);
  _3x2.ModAdd(&x2,&x2);
  _3x2.ModAdd(&x2);
  w.ModAdd(&z2,&_3x2);
  s.ModMulK1(&p.y,&p.z);
  b.ModMulK1(&p.y,&s);
  b.ModMulK1(&p.x);
  h.ModSquareK1(&w);
  _8b.ModAdd(&b,&b);
  _8b.ModDouble();
  _8b.ModDouble();
  h.ModSub(&_8b);
  r.x.ModMulK1(&h,&s);
  r.x.ModAdd(&r.x);
  s2.ModSquareK1(&s);
  y2.ModSquareK1(&p.y);
  _8y2s2.ModMulK1(&y2,&s2);
  _8y2s2.ModDouble();
  _8y2s2.ModDouble();
  _8y2s2.ModDouble();
  r.y.ModAdd(&b,&b);
  r.y.ModAdd(&r.y,&r.y);
  r.y.ModSub(&h);
  r.y.ModMulK1(&w);
  r.y.ModSub(&_8y2s2);
  r.z.ModMulK1(&s2,&s);
  r.z.ModDouble();
  r.z.ModDouble();
  r.z.ModDouble();
  return r;
}

Int Secp256K1::GetY(Int x,bool isEven) {
  Int _s;
  Int _p;
  _s.ModSquareK1(&x);
  _p.ModMulK1(&_s,&x);
  _p.ModAdd(7);
  _p.ModSqrt();
  if(!_p.IsEven() && isEven) {
    _p.ModNeg();
  }
  else if(_p.IsEven() && !isEven) {
    _p.ModNeg();
  }
  return _p;
}

bool Secp256K1::EC(Point &p) {
  Int _s;
  Int _p;
  _s.ModSquareK1(&p.x);
  _p.ModMulK1(&_s,&p.x);
  _p.ModAdd(7);
  _s.ModMulK1(&p.y,&p.y);
  _s.ModSub(&_p);
  return _s.IsZero(); // ( ((pow2(y) - (pow3(x) + 7)) % P) == 0 );
}

Point Secp256K1::ScalarBaseMultiplication(Int *scalar) {
  Point result;
  result.Clear();
  Int k(scalar);
  k.Mod(&order);

  std::vector<int8_t> wnaf;
  ComputeWNAF(k, baseWindow, wnaf);
  if (wnaf.empty()) {
    return result;
  }
  if (baseOddMultiples.empty()) {
    baseOddMultiples = BuildOddMultiples(G, baseWindow);
  }

  for (int i = static_cast<int>(wnaf.size()) - 1; i >= 0; --i) {
    if (!result.z.IsZero()) {
      Point dbl = Double(result);
      result.Set(dbl);
    }
    int8_t digit = wnaf[static_cast<size_t>(i)];
    if (digit == 0) {
      continue;
    }
    int absDigit = digit > 0 ? digit : -digit;
    size_t idx = static_cast<size_t>((absDigit - 1) >> 1);
    if (idx >= baseOddMultiples.size()) {
      continue;
    }
    Point addend(baseOddMultiples[idx]);
    if (digit < 0) {
      addend = Negation(addend);
    }
    if (result.z.IsZero()) {
      result.Set(addend);
    } else {
      Point tmp = Add2(result, addend);
      result.Set(tmp);
    }
  }

  if (!result.z.IsZero()) {
    result.Reduce();
  }
  return result;
}

Point Secp256K1::ScalarMultiplication(Point &P,Int *scalar) {
  Point result;
  result.Clear();
  if (scalar->IsZero() || P.z.IsZero()) {
    return result;
  }

  Int r1;
  Int r2;
  DecomposeScalar(scalar, r1, r2);

  Int halfOrder(&order);
  halfOrder.ShiftR(1);

  bool neg1 = false;
  bool neg2 = false;
  Int k1Abs;
  Int k2Abs;

  if (r1.IsGreater(&halfOrder)) {
    neg1 = true;
    k1Abs.Set(&order);
    k1Abs.Sub(&r1);
  } else {
    k1Abs.Set(&r1);
  }

  if (r2.IsGreater(&halfOrder)) {
    neg2 = true;
    k2Abs.Set(&order);
    k2Abs.Sub(&r2);
  } else {
    k2Abs.Set(&r2);
  }

  const unsigned int window = 5;
  std::vector<int8_t> wnaf1;
  std::vector<int8_t> wnaf2;
  ComputeWNAF(k1Abs, window, wnaf1);
  ComputeWNAF(k2Abs, window, wnaf2);

  Point base(P);
  if (!base.z.IsZero() && !base.z.IsOne()) {
    base.Reduce();
  }
  Point phiP = ApplyEndomorphism(base);
  std::vector<Point> table1 = BuildOddMultiples(base, window);
  std::vector<Point> table2 = BuildOddMultiples(phiP, window);

  size_t maxLen = std::max(wnaf1.size(), wnaf2.size());
  for (int64_t i = static_cast<int64_t>(maxLen) - 1; i >= 0; --i) {
    if (!result.z.IsZero()) {
      Point dbl = Double(result);
      result.Set(dbl);
    }

    if (i < static_cast<int64_t>(wnaf1.size())) {
      int8_t digit = wnaf1[static_cast<size_t>(i)];
      if (neg1) {
        digit = -digit;
      }
      if (digit != 0) {
        int absDigit = digit > 0 ? digit : -digit;
        size_t idx = static_cast<size_t>((absDigit - 1) >> 1);
        if (idx < table1.size()) {
          Point addend(table1[idx]);
          if (digit < 0) {
            addend = Negation(addend);
          }
          if (result.z.IsZero()) {
            result.Set(addend);
          } else {
            Point tmp = Add2(result, addend);
            result.Set(tmp);
          }
        }
      }
    }

    if (i < static_cast<int64_t>(wnaf2.size())) {
      int8_t digit = wnaf2[static_cast<size_t>(i)];
      if (neg2) {
        digit = -digit;
      }
      if (digit != 0) {
        int absDigit = digit > 0 ? digit : -digit;
        size_t idx = static_cast<size_t>((absDigit - 1) >> 1);
        if (idx < table2.size()) {
          Point addend(table2[idx]);
          if (digit < 0) {
            addend = Negation(addend);
          }
          if (result.z.IsZero()) {
            result.Set(addend);
          } else {
            Point tmp = Add2(result, addend);
            result.Set(tmp);
          }
        }
      }
    }
  }

  if (!result.z.IsZero()) {
    result.Reduce();
  }
  return result;
}

Point Secp256K1::MultiScalarMultiplication(const std::vector<Point> &points, const std::vector<Int> &scalars) {
  Point result;
  result.Clear();
  if (points.empty() || points.size() != scalars.size()) {
    return result;
  }

  size_t n = points.size();
  unsigned int window = ChoosePippengerWindow(n);
  uint32_t bucketCount = (1u << window) - 1;

  std::vector<Point> prepared;
  prepared.reserve(n);
  for (const auto &pt : points) {
    Point copy(pt);
    if (copy.z.IsZero()) {
      prepared.push_back(copy);
      continue;
    }
    if (!copy.z.IsOne()) {
      copy.Reduce();
    }
    prepared.push_back(copy);
  }

  std::vector<std::vector<uint32_t>> scalarDigits(n);
  size_t maxDigits = 0;
  Int chunkBase;
  chunkBase.SetInt32(1);
  chunkBase.ShiftL(window);
  uint32_t mask = (1u << window) - 1;
  for (size_t i = 0; i < n; ++i) {
    Int k(const_cast<Int *>(&scalars[i]));
    k.Mod(&order);
    std::vector<uint32_t> repr;
    while (!k.IsZero()) {
      Int mod(k);
      mod.Mod(&chunkBase);
      uint32_t digit = static_cast<uint32_t>(mod.bits64[0] & mask);
      repr.push_back(digit);
      if (digit != 0) {
        Int adjust;
        adjust.SetInt32(digit);
        k.Sub(&adjust);
      }
      k.ShiftR(window);
    }
    scalarDigits[i] = repr;
    if (repr.size() > maxDigits) {
      maxDigits = repr.size();
    }
  }

  Point running;
  running.Clear();
  for (int64_t pos = static_cast<int64_t>(maxDigits) - 1; pos >= 0; --pos) {
    for (unsigned int j = 0; j < window; ++j) {
      if (!result.z.IsZero()) {
        Point dbl = Double(result);
        result.Set(dbl);
      }
    }

    std::vector<Point> buckets(bucketCount);
    for (auto &bucket : buckets) {
      bucket.Clear();
    }

    for (size_t i = 0; i < n; ++i) {
      if (prepared[i].z.IsZero()) {
        continue;
      }
      uint32_t digit = pos < static_cast<int64_t>(scalarDigits[i].size()) ? scalarDigits[i][static_cast<size_t>(pos)] : 0;
      if (digit == 0) {
        continue;
      }
      size_t idx = static_cast<size_t>(digit - 1);
      if (idx >= buckets.size()) {
        continue;
      }
      if (buckets[idx].z.IsZero()) {
        buckets[idx].Set(prepared[i]);
      } else {
        Point addend(prepared[i]);
        Point tmp = Add2(buckets[idx], addend);
        buckets[idx].Set(tmp);
      }
    }

    running.Clear();
    for (int b = static_cast<int>(bucketCount) - 1; b >= 0; --b) {
      if (buckets[b].z.IsZero()) {
        continue;
      }
      if (running.z.IsZero()) {
        running.Set(buckets[b]);
      } else {
        Point tmp = Add(running, buckets[b]);
        running.Set(tmp);
      }
      if (result.z.IsZero()) {
        result.Set(running);
      } else {
        Point tmp = Add(result, running);
        result.Set(tmp);
      }
    }
  }

  if (!result.z.IsZero()) {
    result.Reduce();
  }
  return result;
}


#define KEYBUFFCOMP(buff,p) \
(buff)[0] = ((p).x.bits[7] >> 8) | ((uint32_t)(0x2 + (p).y.IsOdd()) << 24); \
(buff)[1] = ((p).x.bits[6] >> 8) | ((p).x.bits[7] <<24); \
(buff)[2] = ((p).x.bits[5] >> 8) | ((p).x.bits[6] <<24); \
(buff)[3] = ((p).x.bits[4] >> 8) | ((p).x.bits[5] <<24); \
(buff)[4] = ((p).x.bits[3] >> 8) | ((p).x.bits[4] <<24); \
(buff)[5] = ((p).x.bits[2] >> 8) | ((p).x.bits[3] <<24); \
(buff)[6] = ((p).x.bits[1] >> 8) | ((p).x.bits[2] <<24); \
(buff)[7] = ((p).x.bits[0] >> 8) | ((p).x.bits[1] <<24); \
(buff)[8] = 0x00800000 | ((p).x.bits[0] <<24); \
(buff)[9] = 0; \
(buff)[10] = 0; \
(buff)[11] = 0; \
(buff)[12] = 0; \
(buff)[13] = 0; \
(buff)[14] = 0; \
(buff)[15] = 0x108;

#define KEYBUFFUNCOMP(buff,p) \
(buff)[0] = ((p).x.bits[7] >> 8) | 0x04000000; \
(buff)[1] = ((p).x.bits[6] >> 8) | ((p).x.bits[7] <<24); \
(buff)[2] = ((p).x.bits[5] >> 8) | ((p).x.bits[6] <<24); \
(buff)[3] = ((p).x.bits[4] >> 8) | ((p).x.bits[5] <<24); \
(buff)[4] = ((p).x.bits[3] >> 8) | ((p).x.bits[4] <<24); \
(buff)[5] = ((p).x.bits[2] >> 8) | ((p).x.bits[3] <<24); \
(buff)[6] = ((p).x.bits[1] >> 8) | ((p).x.bits[2] <<24); \
(buff)[7] = ((p).x.bits[0] >> 8) | ((p).x.bits[1] <<24); \
(buff)[8] = ((p).y.bits[7] >> 8) | ((p).x.bits[0] <<24); \
(buff)[9] = ((p).y.bits[6] >> 8) | ((p).y.bits[7] <<24); \
(buff)[10] = ((p).y.bits[5] >> 8) | ((p).y.bits[6] <<24); \
(buff)[11] = ((p).y.bits[4] >> 8) | ((p).y.bits[5] <<24); \
(buff)[12] = ((p).y.bits[3] >> 8) | ((p).y.bits[4] <<24); \
(buff)[13] = ((p).y.bits[2] >> 8) | ((p).y.bits[3] <<24); \
(buff)[14] = ((p).y.bits[1] >> 8) | ((p).y.bits[2] <<24); \
(buff)[15] = ((p).y.bits[0] >> 8) | ((p).y.bits[1] <<24); \
(buff)[16] = 0x00800000 | ((p).y.bits[0] <<24); \
(buff)[17] = 0; \
(buff)[18] = 0; \
(buff)[19] = 0; \
(buff)[20] = 0; \
(buff)[21] = 0; \
(buff)[22] = 0; \
(buff)[23] = 0; \
(buff)[24] = 0; \
(buff)[25] = 0; \
(buff)[26] = 0; \
(buff)[27] = 0; \
(buff)[28] = 0; \
(buff)[29] = 0; \
(buff)[30] = 0; \
(buff)[31] = 0x208;

#define KEYBUFFSCRIPT(buff,h) \
(buff)[0] = 0x00140000 | (uint32_t)h[0] << 8 | (uint32_t)h[1]; \
(buff)[1] = (uint32_t)h[2] << 24 | (uint32_t)h[3] << 16 | (uint32_t)h[4] << 8 | (uint32_t)h[5];\
(buff)[2] = (uint32_t)h[6] << 24 | (uint32_t)h[7] << 16 | (uint32_t)h[8] << 8 | (uint32_t)h[9];\
(buff)[3] = (uint32_t)h[10] << 24 | (uint32_t)h[11] << 16 | (uint32_t)h[12] << 8 | (uint32_t)h[13];\
(buff)[4] = (uint32_t)h[14] << 24 | (uint32_t)h[15] << 16 | (uint32_t)h[16] << 8 | (uint32_t)h[17];\
(buff)[5] = (uint32_t)h[18] << 24 | (uint32_t)h[19] << 16 | 0x8000; \
(buff)[6] = 0; \
(buff)[7] = 0; \
(buff)[8] = 0; \
(buff)[9] = 0; \
(buff)[10] = 0; \
(buff)[11] = 0; \
(buff)[12] = 0; \
(buff)[13] = 0; \
(buff)[14] = 0; \
(buff)[15] = 0xB0;


void Secp256K1::GetHash160(int type,bool compressed,
  Point &k0,Point &k1,Point &k2,Point &k3,
  uint8_t *h0,uint8_t *h1,uint8_t *h2,uint8_t *h3) {

#ifdef WIN64
  __declspec(align(16)) unsigned char sh0[64];
  __declspec(align(16)) unsigned char sh1[64];
  __declspec(align(16)) unsigned char sh2[64];
  __declspec(align(16)) unsigned char sh3[64];
#else
  unsigned char sh0[64] __attribute__((aligned(16)));
  unsigned char sh1[64] __attribute__((aligned(16)));
  unsigned char sh2[64] __attribute__((aligned(16)));
  unsigned char sh3[64] __attribute__((aligned(16)));
#endif

  switch (type) {

  case P2PKH:
  case BECH32:
  {

    if (!compressed) {

      uint32_t b0[32];
      uint32_t b1[32];
      uint32_t b2[32];
      uint32_t b3[32];

      KEYBUFFUNCOMP(b0, k0);
      KEYBUFFUNCOMP(b1, k1);
      KEYBUFFUNCOMP(b2, k2);
      KEYBUFFUNCOMP(b3, k3);

      sha256_simd_2B(b0, b1, b2, b3, sh0, sh1, sh2, sh3);
      ripemd160_simd_32(sh0, sh1, sh2, sh3, h0, h1, h2, h3);

    } else {

      uint32_t b0[16];
      uint32_t b1[16];
      uint32_t b2[16];
      uint32_t b3[16];

      KEYBUFFCOMP(b0, k0);
      KEYBUFFCOMP(b1, k1);
      KEYBUFFCOMP(b2, k2);
      KEYBUFFCOMP(b3, k3);

      sha256_simd_1B(b0, b1, b2, b3, sh0, sh1, sh2, sh3);
      ripemd160_simd_32(sh0, sh1, sh2, sh3, h0, h1, h2, h3);

    }

  }
  break;

  case P2SH:
  {

    unsigned char kh0[20];
    unsigned char kh1[20];
    unsigned char kh2[20];
    unsigned char kh3[20];

    GetHash160(P2PKH,compressed,k0,k1,k2,k3,kh0,kh1,kh2,kh3);

    // Redeem Script (1 to 1 P2SH)
    uint32_t b0[16];
    uint32_t b1[16];
    uint32_t b2[16];
    uint32_t b3[16];

    KEYBUFFSCRIPT(b0, kh0);
    KEYBUFFSCRIPT(b1, kh1);
    KEYBUFFSCRIPT(b2, kh2);
    KEYBUFFSCRIPT(b3, kh3);

    sha256_simd_1B(b0, b1, b2, b3, sh0, sh1, sh2, sh3);
    ripemd160_simd_32(sh0, sh1, sh2, sh3, h0, h1, h2, h3);

  }
  break;

  }
}



void Secp256K1::GetHash160(int type, bool compressed, Point &pubKey, unsigned char *hash) {

  unsigned char shapk[64];

  switch (type) {

  case P2PKH:
  case BECH32:
  {
    unsigned char publicKeyBytes[128];

    if (!compressed) {

      // Full public key
      publicKeyBytes[0] = 0x4;
      pubKey.x.Get32Bytes(publicKeyBytes + 1);
      pubKey.y.Get32Bytes(publicKeyBytes + 33);
      sha256_65(publicKeyBytes, shapk);

    } else {

      // Compressed public key
      publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
      pubKey.x.Get32Bytes(publicKeyBytes + 1);
      sha256_33(publicKeyBytes, shapk);

    }

    ripemd160_32(shapk, hash);
  }
  break;

  case P2SH:
  {

    // Redeem Script (1 to 1 P2SH)
    unsigned char script[64];

    script[0] = 0x00;  // OP_0
    script[1] = 0x14;  // PUSH 20 bytes
    GetHash160(P2PKH, compressed, pubKey, script + 2);

    sha256(script, 22, shapk);
    ripemd160_32(shapk, hash);

  }
  break;

  }

}


#define KEYBUFFPREFIX(buff,k,fix) \
(buff)[0] = (k->bits[7] >> 8) | ((uint32_t)(fix) << 24); \
(buff)[1] = (k->bits[6] >> 8) | (k->bits[7] <<24); \
(buff)[2] = (k->bits[5] >> 8) | (k->bits[6] <<24); \
(buff)[3] = (k->bits[4] >> 8) | (k->bits[5] <<24); \
(buff)[4] = (k->bits[3] >> 8) | (k->bits[4] <<24); \
(buff)[5] = (k->bits[2] >> 8) | (k->bits[3] <<24); \
(buff)[6] = (k->bits[1] >> 8) | (k->bits[2] <<24); \
(buff)[7] = (k->bits[0] >> 8) | (k->bits[1] <<24); \
(buff)[8] = 0x00800000 | (k->bits[0] <<24); \
(buff)[9] = 0; \
(buff)[10] = 0; \
(buff)[11] = 0; \
(buff)[12] = 0; \
(buff)[13] = 0; \
(buff)[14] = 0; \
(buff)[15] = 0x108;



void Secp256K1::GetHash160_fromX(int type,unsigned char prefix,
  Int *k0,Int *k1,Int *k2,Int *k3,
  uint8_t *h0,uint8_t *h1,uint8_t *h2,uint8_t *h3) {

#ifdef WIN64
  __declspec(align(16)) unsigned char sh0[64];
  __declspec(align(16)) unsigned char sh1[64];
  __declspec(align(16)) unsigned char sh2[64];
  __declspec(align(16)) unsigned char sh3[64];
#else
  unsigned char sh0[64] __attribute__((aligned(16)));
  unsigned char sh1[64] __attribute__((aligned(16)));
  unsigned char sh2[64] __attribute__((aligned(16)));
  unsigned char sh3[64] __attribute__((aligned(16)));
#endif

  switch (type) {

  case P2PKH:
  {
      uint32_t b0[16];
      uint32_t b1[16];
      uint32_t b2[16];
      uint32_t b3[16];

      KEYBUFFPREFIX(b0, k0, prefix);
      KEYBUFFPREFIX(b1, k1, prefix);
      KEYBUFFPREFIX(b2, k2, prefix);
      KEYBUFFPREFIX(b3, k3, prefix);

      sha256_simd_1B(b0, b1, b2, b3, sh0, sh1, sh2, sh3);
      ripemd160_simd_32(sh0, sh1, sh2, sh3, h0, h1, h2, h3);
  }
  break;

  case P2SH:
  {
	fprintf(stderr,"[E] Fixme unsopported case");
	exit(0);
  }
  break;

  }
}

