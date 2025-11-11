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

#include <cstdio>
#include <cstring>
#include <algorithm>
#include <array>
#include <cctype>
#include <cassert>
#include <cstdlib>
#include <numeric>
#include <boost/multiprecision/cpp_int.hpp>
#include "SECP256k1.h"
#include "Point.h"
#include "../util.h"
#include "../hash/sha256.h"
#include "../hash/ripemd160.h"

namespace {
using boost::multiprecision::cpp_int;

int HexCharToInt(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return 10 + (c - 'a');
  }
  if (c >= 'A' && c <= 'F') {
    return 10 + (c - 'A');
  }
  return -1;
}

cpp_int HexToCpp(const char *hex) {
  cpp_int result = 0;
  while (*hex) {
    if (*hex == 'x' || *hex == 'X') {
      ++hex;
      continue;
    }
    int nibble = HexCharToInt(*hex++);
    if (nibble < 0) {
      continue;
    }
    result <<= 4;
    result += nibble;
  }
  return result;
}

cpp_int IntToCpp(const Int &value) {
  unsigned char bytes[32];
  Int tmp(const_cast<Int*>(&value));
  tmp.Get32Bytes(bytes);
  cpp_int result = 0;
  for (int i = 0; i < 32; ++i) {
    result <<= 8;
    result += bytes[i];
  }
  return result;
}

const cpp_int MINUS_B1 = HexToCpp("00000000000000000000000000000000E4437ED6010E88286F547FA90ABFE4C3");
const cpp_int MINUS_B2 = HexToCpp("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE8A280AC50774346DD765CDA83DB1562C");
const cpp_int G1_CONST = HexToCpp("3086D221A7D46BCDE86C90E49284EB153DAA8A1471E8CA7FE893209A45DBB031");
const cpp_int G2_CONST = HexToCpp("E4437ED6010E88286F547FA90ABFE4C4221208AC9DF506C61571B4AE8AC47F71");
const cpp_int ROUNDING_CONST = cpp_int(1) << 383;

} // namespace

Secp256K1::Secp256K1() {
}

void Secp256K1::Init() {
  basePrecompReady = false;
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
  beta.SetBase16("7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE");

  // Compute Generator table
  Point N(G);
  for(int i = 0; i < 32; i++) {
    GTable[i * 256] = N;
    N = DoubleDirect(N);
    for (int j = 1; j < 255; j++) {
      GTable[i * 256 + j] = N;
      N = AddDirect(N, GTable[i * 256]);
    }
    GTable[i * 256 + 255] = N; // Dummy point for check function
  }

  basePrecomp = BuildFixedBaseTable(G, BASE_WNAF_WINDOW);
  Point lambdaG = ApplyEndomorphism(G);
  basePrecompLambda = BuildFixedBaseTable(lambdaG, BASE_WNAF_WINDOW);
  basePrecompReady = true;

}

Secp256K1::~Secp256K1() {
}

Point Secp256K1::ComputePublicKey(Int *privKey) {
  Int k(privKey);
  k.Mod(&order);
  return ScalarBaseMultiplication(k);
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

Point Secp256K1::ApplyEndomorphism(const Point &p) {
  Point normalized(p);
  if (!normalized.z.IsOne() && !normalized.z.IsZero()) {
    normalized.Reduce();
  }
  Point result;
  result.Clear();
  result.x.ModMulK1(&normalized.x, &beta);
  result.y.Set(&normalized.y);
  result.z.SetInt32(1);
  return result;
}

std::vector<Point> Secp256K1::BuildFixedBaseTable(const Point &base, int window) {
  std::vector<Point> table;
  if (window < 2) {
    return table;
  }
  int entries = 1 << (window - 2);
  if (entries <= 0) {
    return table;
  }

  Point normalized(base);
  if (!normalized.z.IsOne() && !normalized.z.IsZero()) {
    normalized.Reduce();
  }

  table.reserve(entries);
  Point current(normalized);
  table.push_back(current);

  if (entries == 1) {
    return table;
  }

  Point doubled = DoubleDirect(normalized);
  for (int i = 1; i < entries; ++i) {
    current = AddDirect(current, doubled);
    table.push_back(current);
  }
  return table;
}

std::vector<int8_t> Secp256K1::ComputeWNAF(const cpp_int &scalar, int window) {
  std::vector<int8_t> wnaf;
  if (scalar == 0) {
    return wnaf;
  }
  cpp_int k = scalar;
  const int window_size = 1 << window;
  const int window_half = window_size >> 1;
  const cpp_int mask = cpp_int(window_size - 1);

  while (k != 0) {
    int8_t digit = 0;
    if ((k & 1) != 0) {
      long long remainder = (k & mask).convert_to<long long>();
      if (remainder > window_half) {
        remainder -= window_size;
      }
      digit = static_cast<int8_t>(remainder);
      k -= remainder;
    }
    wnaf.push_back(digit);
    k >>= 1;
  }
  return wnaf;
}

Point Secp256K1::EvaluateWNAF(const std::vector<int8_t> &wnaf, const std::vector<Point> &precomp) {
  Point result;
  result.Clear();
  bool initialized = false;
  for (int i = static_cast<int>(wnaf.size()) - 1; i >= 0; --i) {
    if (initialized) {
      result = Double(result);
    }
    int digit = wnaf[i];
    if (!digit) {
      continue;
    }
    int index = (std::abs(digit) - 1) >> 1;
    if (index < 0 || index >= static_cast<int>(precomp.size())) {
      continue;
    }
    Point addend(precomp[index]);
    if (digit < 0) {
      addend = Negation(addend);
    }
    if (initialized) {
      result = Add2(result, addend);
    } else {
      result = addend;
      initialized = true;
    }
  }
  if (!initialized) {
    result.Clear();
  } else {
    result.Reduce();
  }
  return result;
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

void Secp256K1::BatchNormalize(std::vector<Point> &points) {
  if (points.empty()) {
    return;
  }
  std::vector<Int> prefix(points.size());
  Int acc;
  acc.SetInt32(1);
  for (size_t i = 0; i < points.size(); ++i) {
    prefix[i].Set(&acc);
    if (!points[i].z.IsZero()) {
      acc.ModMulK1(&points[i].z);
    }
  }
  if (!acc.IsZero()) {
    acc.ModInv();
  }
  for (int i = static_cast<int>(points.size()) - 1; i >= 0; --i) {
    if (points[i].z.IsZero()) {
      continue;
    }
    Int zi(points[i].z);
    Int ziInv(acc);
    ziInv.ModMulK1(&prefix[i]);
    Int ziInv2;
    ziInv2.ModSquareK1(&ziInv);
    Int ziInv3(ziInv2);
    ziInv3.ModMulK1(&ziInv);
    points[i].x.ModMulK1(&ziInv2);
    points[i].y.ModMulK1(&ziInv3);
    points[i].z.SetInt32(1);
    acc.ModMulK1(&zi);
  }
}

Point Secp256K1::ScalarBaseMultiplication(const Int &scalar) {
  Int scalarCopy(const_cast<Int*>(&scalar));
  if (scalarCopy.IsZero()) {
    Point infinity;
    infinity.Clear();
    return infinity;
  }

  cpp_int n = IntToCpp(order);
  cpp_int k = IntToCpp(scalarCopy) % n;
  cpp_int lambda_cpp = IntToCpp(lambda);

  cpp_int c1 = (k * G1_CONST + ROUNDING_CONST) >> 384;
  cpp_int c2 = (k * G2_CONST + ROUNDING_CONST) >> 384;
  cpp_int r2 = (c1 * MINUS_B1 + c2 * MINUS_B2) % n;
  if (r2 < 0) {
    r2 += n;
  }
  cpp_int r1 = (k - r2 * lambda_cpp) % n;
  if (r1 < 0) {
    r1 += n;
  }

  cpp_int half_n = n >> 1;
  cpp_int r1_signed = r1;
  if (r1_signed > half_n) {
    r1_signed -= n;
  }
  cpp_int r2_signed = r2;
  if (r2_signed > half_n) {
    r2_signed -= n;
  }

  bool neg1 = r1_signed < 0;
  bool neg2 = r2_signed < 0;
  cpp_int abs1 = neg1 ? -r1_signed : r1_signed;
  cpp_int abs2 = neg2 ? -r2_signed : r2_signed;

  std::vector<int8_t> wnaf1 = ComputeWNAF(abs1, BASE_WNAF_WINDOW);
  std::vector<int8_t> wnaf2 = ComputeWNAF(abs2, BASE_WNAF_WINDOW);

  Point p1 = EvaluateWNAF(wnaf1, basePrecomp);
  Point p2 = EvaluateWNAF(wnaf2, basePrecompLambda);

  if (neg1 && !p1.isZero()) {
    p1 = Negation(p1);
  }
  if (neg2 && !p2.isZero()) {
    p2 = Negation(p2);
  }

  if (p1.isZero()) {
    if (p2.isZero()) {
      return p1;
    }
    return p2;
  }
  if (p2.isZero()) {
    return p1;
  }

  Point result = Add(p1, p2);
  result.Reduce();
  return result;
}

Point Secp256K1::ScalarMultiplication(Point &P,Int *scalar) {
  Int k(scalar);
  k.Mod(&order);
  if (k.IsZero()) {
    Point infinity;
    infinity.Clear();
    return infinity;
  }

  Point base(P);
  if (!base.z.IsOne() && !base.z.IsZero()) {
    base.Reduce();
  }

  std::vector<Point> table = BuildFixedBaseTable(base, BASE_WNAF_WINDOW);
  cpp_int k_cpp = IntToCpp(k);
  std::vector<int8_t> wnaf = ComputeWNAF(k_cpp, BASE_WNAF_WINDOW);
  return EvaluateWNAF(wnaf, table);
}

Point Secp256K1::StrausWNAF(const std::vector<Int> &scalars, const std::vector<Point> &points, int window) {
  std::vector<Point> bases(points.begin(), points.end());
  BatchNormalize(bases);

  size_t n = scalars.size();
  std::vector<std::vector<Point>> precomp(n);
  std::vector<std::vector<int8_t>> wnafs(n);
  size_t max_len = 0;

  for (size_t i = 0; i < n; ++i) {
    if (!bases[i].z.IsZero()) {
      precomp[i] = BuildFixedBaseTable(bases[i], window);
    }
    Int k(scalars[i]);
    k.Mod(&order);
    cpp_int scalar_cpp = IntToCpp(k);
    wnafs[i] = ComputeWNAF(scalar_cpp, window);
    if (wnafs[i].size() > max_len) {
      max_len = wnafs[i].size();
    }
  }

  Point result;
  result.Clear();
  bool initialized = false;
  for (int bit = static_cast<int>(max_len) - 1; bit >= 0; --bit) {
    if (initialized) {
      result = Double(result);
    }
    for (size_t i = 0; i < n; ++i) {
      if (bit >= static_cast<int>(wnafs[i].size())) {
        continue;
      }
      int digit = wnafs[i][bit];
      if (!digit) {
        continue;
      }
      int index = (std::abs(digit) - 1) >> 1;
      if (index < 0 || index >= static_cast<int>(precomp[i].size())) {
        continue;
      }
      Point addend(precomp[i][index]);
      if (digit < 0) {
        addend = Negation(addend);
      }
      if (initialized) {
        result = Add2(result, addend);
      } else {
        result = addend;
        initialized = true;
      }
    }
  }

  if (!initialized) {
    result.Clear();
  } else {
    result.Reduce();
  }
  return result;
}

Point Secp256K1::PippengerMultiScalar(const std::vector<Int> &scalars, const std::vector<Point> &points, int window) {
  size_t n = scalars.size();
  std::vector<Point> bases(points.begin(), points.end());
  BatchNormalize(bases);

  const int window_size = 1 << window;
  const int window_half = window_size >> 1;
  if (window_half <= 0) {
    return StrausWNAF(scalars, points, window);
  }

  std::vector<std::vector<Point>> multiples(n, std::vector<Point>(window_half));
  for (size_t i = 0; i < n; ++i) {
    if (bases[i].isZero()) {
      continue;
    }
    multiples[i][0] = bases[i];
    for (int j = 2; j <= window_half; ++j) {
      if (j == 2) {
        multiples[i][1] = DoubleDirect(bases[i]);
      } else {
        multiples[i][j - 1] = AddDirect(multiples[i][j - 2], bases[i]);
      }
    }
  }

  std::vector<std::vector<int32_t>> digits(n);
  size_t max_windows = 0;
  for (size_t i = 0; i < n; ++i) {
    Int k(scalars[i]);
    k.Mod(&order);
    cpp_int value = IntToCpp(k);
    std::vector<int32_t> repr;
    while (value != 0) {
      cpp_int mod = value & cpp_int(window_size - 1);
      int32_t digit = mod.convert_to<int32_t>();
      if (digit > window_half) {
        digit -= window_size;
      }
      repr.push_back(digit);
      value -= digit;
      value >>= window;
    }
    digits[i] = std::move(repr);
    if (digits[i].size() > max_windows) {
      max_windows = digits[i].size();
    }
  }

  Point result;
  result.Clear();
  bool initialized = false;

  for (int window_index = static_cast<int>(max_windows) - 1; window_index >= 0; --window_index) {
    if (initialized) {
      for (int d = 0; d < window; ++d) {
        result = Double(result);
      }
    }

    std::vector<Point> buckets(window_half);
    std::vector<bool> bucket_used(window_half, false);

    for (size_t i = 0; i < n; ++i) {
      if (window_index >= static_cast<int>(digits[i].size())) {
        continue;
      }
      int32_t digit = digits[i][window_index];
      if (digit == 0) {
        continue;
      }
      int idx = std::abs(digit);
      if (idx == 0 || idx > window_half || multiples[i].empty()) {
        continue;
      }
      Point addend(multiples[i][idx - 1]);
      if (digit < 0) {
        addend = Negation(addend);
      }
      if (!bucket_used[idx - 1]) {
        buckets[idx - 1] = addend;
        bucket_used[idx - 1] = true;
      } else {
        buckets[idx - 1] = AddDirect(buckets[idx - 1], addend);
      }
    }

    Point running;
    running.Clear();
    bool running_init = false;
    for (int idx = window_half - 1; idx >= 0; --idx) {
      if (!bucket_used[idx]) {
        continue;
      }
      if (running_init) {
        running = AddDirect(running, buckets[idx]);
      } else {
        running = buckets[idx];
        running_init = true;
      }
      if (initialized) {
        result = Add(result, running);
      } else {
        result = running;
        initialized = true;
      }
    }
  }

  if (!initialized) {
    result.Clear();
  } else {
    result.Reduce();
  }
  return result;
}

Point Secp256K1::MultiScalarMul(const std::vector<Int> &scalars, const std::vector<Point> &points) {
  if (scalars.size() != points.size() || scalars.empty()) {
    Point infinity;
    infinity.Clear();
    return infinity;
  }

  size_t n = scalars.size();
  if (n < 16) {
    return StrausWNAF(scalars, points, BASE_WNAF_WINDOW);
  }

  int window = (n >= 64) ? 6 : (n >= 32 ? 5 : 4);
  return PippengerMultiScalar(scalars, points, window);
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

