#include"he_crusk/he_crusk.hpp"

int main(){
  using Impl = he_wrapper_tmpl::ImplSeal<double>;

  const size_t poly_modulus_degree = 16384;
  std::vector<int> moduli_bits = {60, 60, 60, 60};
  const double default_scale = std::pow(2.0, 30);
  
  auto km = std::make_shared<Impl::KeyManager>();
  km->poly_degree(poly_modulus_degree);
  km->modulus_bits_list(moduli_bits);
  km->default_scale(default_scale);
  km->gen_params();
  km->gen_sk();
  km->gen_pk();


  
  auto op = std::make_shared<Impl::Operator>(km);

  Impl::RawVec x_vec(op->num_slots()), a0_vec(op->num_slots()), a1_vec(op->num_slots());

  std::mt19937_64 engine(340);;
  std::uniform_real_distribution<double> dist(-10.0, 10.0);
  std::transform(x_vec.begin(), x_vec.end(), x_vec.begin(),
                 [&](const auto& x){ return dist(engine); });
  std::transform(a1_vec.begin(), a1_vec.end(), a1_vec.begin(),
                 [&](const auto& x){ return dist(engine); });
  std::transform(a0_vec.begin(), a0_vec.end(), a0_vec.begin(),
                 [&](const auto& x){ return dist(engine); });
  
  Impl::Plaintext pt;
  
  he_crusk::HeCrusk hc(op);
  Impl::EncodingParams ep = op->get_initial_encoding_params();
  hc.add(he_crusk::RandomizedCiphertext("x", ep, 2, true, true), x_vec);
  hc.add(he_crusk::RandomizedCiphertext("a1", ep, 2, false, false), a1_vec);
  
  hc.add(he_crusk::RandomizedCiphertext("a0", ep, 3, false, false), a0_vec);

  hc.randomize(hc.get("x"));

  hc.get("a1").sbk.mul_sbk() = hc.get("x").sbk.gen_inverted_mul_sbk(*op);
  hc.randomize(hc.get("a1"));
  
  hc.get("a0").sbk.add_sbk() = hc.get("x").sbk.gen_negated_add_sbk(*op);
  op->mul(hc.get("a0").sbk.add_sbk(), hc.get("a1").randomized);
  hc.randomize(hc.get("a0"));
  

  Impl::Ciphertext out;
  op->mul(out, hc.get("a1").randomized, hc.get("x").randomized);
  op->add(out, hc.get("a0").randomized);

  Impl::RawVec result;
  op->decrypt_and_decode(result, out);

  Impl::RawVec gt;
  gt = a1_vec * x_vec;
  gt += a0_vec;

  std::cout << result << std::endl;
  std::cout << gt << std::endl;
  
  return 0;
}

