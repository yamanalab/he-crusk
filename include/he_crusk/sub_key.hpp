#pragma once

#include"he_wrapper_tmpl/he_wrapper_tmpl.hpp"

namespace he_crusk{
template<template<class> class Impl>
class SubKey{
public:
  using EncodingParams = he_wrapper_tmpl::EncodingParams<Impl>;
  using Plaintext = he_wrapper_tmpl::Plaintext<Impl>;
  using Ciphertext = he_wrapper_tmpl::Ciphertext<Impl>;
  using Operator = he_wrapper_tmpl::Operator<Impl>;

  SubKey(){}
  SubKey(const bool autogen_mul_sbk, const bool autogen_add_sbk)
    : autogen_mul_sbk_(autogen_mul_sbk), autogen_add_sbk_(autogen_add_sbk){}
  ~SubKey() noexcept = default;
  SubKey(const SubKey&) = default;
  SubKey(SubKey&&) noexcept = default;
  
  auto& mul_sbk() noexcept { return mul_sbk_; }
  const auto& mul_sbk() const noexcept { return mul_sbk_; }
  auto& add_sbk() noexcept { return add_sbk_; }
  const auto& add_sbk() const noexcept { return add_sbk_; }

  void generate(const Ciphertext& ref, const Operator& op){
    if( autogen_mul_sbk_ ){
      generate_mul_sbk(op, ref);
    }
    if( autogen_add_sbk_ ){
      generate_add_sbk(op, ref);
    }
    return;
  }

  void randomize(Ciphertext& out, const Ciphertext& in, const Operator& op){
    if( mul_sbk_.ptr() != nullptr ){
      op.mul(out, in, mul_sbk_);
      if( add_sbk_.ptr() != nullptr ){
        op.add(out, add_sbk_);
      }
    }else if( add_sbk_.ptr() != nullptr ){
      op.add(out, in, add_sbk_);
    }else{
      op.copy(out, in);
    }
  }

  Plaintext gen_inverted_mul_sbk(const Operator& op) const {
    Plaintext out;
    op.invert(out, mul_sbk_);
    return out;
  }

  Ciphertext gen_negated_add_sbk(const Operator& op) const {
    Ciphertext out;
    op.negate(out, add_sbk_);
    return out;
  }
  
private:
  template<class Iterator>
  void generate_random_vector(Iterator begin, Iterator end,
                              const uint64_t min, const uint64_t max){
    std::uniform_int_distribution<uint64_t> dist(min, max);
    std::generate(begin, end, [&](){
      return dist(engine_);
    });
  }
      
  void generate_add_sbk(const Operator& op, const Ciphertext& ref){
    const size_t size = ref.ref().size();
    const size_t num_moduli = ref.num_moduli();
    const size_t n = op.key_manager().poly_degree();
    std::vector<uint64_t> vec(size * num_moduli * n, 0);
    auto itr = vec.begin();
    for( size_t i = 0; i < num_moduli; ++i ){
      generate_random_vector(itr, itr + n, 0, op.key_manager().get_modulus(i) - 1);
      itr += n;
    }
    
    EncodingParams ep;
    ep.configure(ref);
    // ランダムベクトルを設定する
    add_sbk_.reallocate(op.key_manager());
    add_sbk_.set_data(std::move(vec), op.key_manager(), ep);
    
  }

  void generate_mul_sbk(const Operator& op, const Ciphertext& ref){
    const size_t num_moduli = ref.num_moduli();
    const size_t n = op.key_manager().poly_degree();
    // ランダムベクトルの生成
    std::vector<uint64_t> vec(1 * num_moduli * n, 0);
    auto itr = vec.begin();
    for( size_t i = 0; i < num_moduli; ++i ){
      generate_random_vector(itr, itr + n, 1, op.key_manager().get_modulus(i) - 1);
      itr += n;
    }
    
    EncodingParams ep;
    ep.configure(ref);
    // ランダム化する際にscaling factorを変更しないため，1.0に設定する．
    ep.scale = 1.0;
    // ランダムベクトルを設定する
    mul_sbk_.reallocate(op.key_manager());
    mul_sbk_.set_data(std::move(vec), op.key_manager(), ep);
  }

  
  const unsigned int seed_ = std::random_device{}();
  
  std::mt19937_64 engine_;

  bool autogen_mul_sbk_;
  
  Plaintext mul_sbk_;

  bool autogen_add_sbk_;

  Ciphertext add_sbk_;
  
  
};


}  // namespace he_crusk

