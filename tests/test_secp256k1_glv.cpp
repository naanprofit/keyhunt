#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "../secp256k1/SECP256k1.h"

namespace {

Point Normalize(Point point) {
  if (!point.z.IsZero() && !point.z.IsOne()) {
    point.Reduce();
  }
  return point;
}

bool PointsEqual(Point a, Point b) {
  bool zero_a = a.isZero();
  bool zero_b = b.isZero();
  if (zero_a || zero_b) {
    return zero_a == zero_b;
  }
  Point na = Normalize(a);
  Point nb = Normalize(b);
  return na.x.IsEqual(&nb.x) && na.y.IsEqual(&nb.y);
}

Point ScalarSum(Secp256K1 &ctx, const std::vector<Int> &scalars, const std::vector<Point> &points) {
  Point total;
  total.Clear();
  bool init = false;
  for (size_t i = 0; i < scalars.size(); ++i) {
    Int scalar_copy;
    scalar_copy.Set(const_cast<Int*>(&scalars[i]));
    Point base(points[i]);
    Point term = ctx.ScalarMultiplication(base, &scalar_copy);
    if (term.isZero()) {
      continue;
    }
    if (init) {
      total = ctx.Add(total, term);
    } else {
      total = term;
      init = true;
    }
  }
  if (!init) {
    total.Clear();
  } else {
    total.Reduce();
  }
  return total;
}

}  // namespace

int main() {
  Secp256K1 ctx;
  ctx.Init();

  std::vector<std::pair<std::string, Int>> scalar_tests;
  scalar_tests.emplace_back("k = 0", Int(0));
  scalar_tests.emplace_back("k = 1", Int(1));
  scalar_tests.emplace_back("k = 2", Int(2));
  scalar_tests.emplace_back("k = 7", Int(7));

  Int limit32;
  limit32.SetInt32(0x7fffffff);
  scalar_tests.emplace_back("k = 2^31 - 1", limit32);

  Int near_half(&ctx.order);
  near_half.ShiftR(1);
  scalar_tests.emplace_back("k = n / 2", near_half);

  Int near_order(&ctx.order);
  near_order.SubOne();
  scalar_tests.emplace_back("k = n - 1", near_order);

  Int order(&ctx.order);
  scalar_tests.emplace_back("k = n", order);

  Int order_plus_one(&ctx.order);
  order_plus_one.AddOne();
  scalar_tests.emplace_back("k = n + 1", order_plus_one);

  Int large_hex;
  large_hex.SetBase16("5F8A2D34398B3E1C6F4D2B1A09FFEEDCBA1234567890ABCDEF1234567890ABCD");
  scalar_tests.emplace_back("random 256-bit", large_hex);

  bool ok = true;
  for (auto &entry : scalar_tests) {
    const std::string &label = entry.first;
    Int &scalar = entry.second;
    Point glv = ctx.ScalarBaseMultiplication(scalar);
    Int canonical_scalar(&scalar);
    Point base_input(ctx.G);
    Point canonical = ctx.ScalarMultiplication(base_input, &canonical_scalar);
    if (!PointsEqual(glv, canonical)) {
      std::cerr << "[FAIL] ScalarBaseMultiplication mismatch for " << label << "\n";
      ok = false;
    }
  }

  std::vector<Int> multi_scalars;
  multi_scalars.emplace_back(Int(5));

  Int neg_three(&ctx.order);
  Int three(3);
  neg_three.Sub(&three);
  multi_scalars.push_back(neg_three);

  Int big_scalar;
  big_scalar.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000000000000000002A");
  multi_scalars.push_back(big_scalar);

  multi_scalars.emplace_back(Int(42));

  Point g(ctx.G);
  g = Normalize(g);
  Point g_double_input(g);
  Point g_double = ctx.Double(g_double_input);
  g_double = Normalize(g_double);

  Point g_triple_input(g_double);
  Point g_triple = ctx.Add(g_triple_input, g);
  g_triple = Normalize(g_triple);

  std::vector<Point> multi_points;
  multi_points.push_back(g);
  multi_points.push_back(g_double);
  multi_points.push_back(g_triple);
  multi_points.push_back(g);

  Point multi_glv = ctx.MultiScalarMul(multi_scalars, multi_points);
  Point expected = ScalarSum(ctx, multi_scalars, multi_points);
  if (!PointsEqual(multi_glv, expected)) {
    std::cerr << "[FAIL] MultiScalarMul mismatch" << std::endl;
    ok = false;
  }

  if (!ok) {
    return 1;
  }

  std::cout << "All GLV scalar multiplication tests passed" << std::endl;
  return 0;
}
