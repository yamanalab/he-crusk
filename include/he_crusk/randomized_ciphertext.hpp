#pragma once

#include"he_crusk/sub_key.hpp"

namespace he_crusk{
template<template<class> class Impl>
struct RandomizedCiphertext{
  using EncodingParams = he_wrapper_tmpl::EncodingParams<Impl>;
  using Plaintext = he_wrapper_tmpl::Plaintext<Impl>;
  using Ciphertext = he_wrapper_tmpl::Ciphertext<Impl>;

  RandomizedCiphertext(const std::string& name, const EncodingParams& ep, const size_t size,
                       const bool autogen_mul_sbk, const bool autogen_add_sbk)
    : name(name), ep(ep), size(size),
      sbk(autogen_mul_sbk, autogen_add_sbk){}
  ~RandomizedCiphertext() = default;
  RandomizedCiphertext(const RandomizedCiphertext&) = default;
  RandomizedCiphertext(RandomizedCiphertext&&) noexcept = default;

  RandomizedCiphertext& operator=(const RandomizedCiphertext&) = default;
  RandomizedCiphertext& operator=(RandomizedCiphertext&&) noexcept = default;
  
  std::string name;

  EncodingParams ep;
  size_t size;

  Plaintext pt;

  
  Ciphertext original;

  Ciphertext randomized;
  
  SubKey<Impl> sbk;
  



};

}  // namespace he_crusk


