#pragma once

#include"he_crusk/randomized_ciphertext.hpp"
#include"he_crusk/sub_key.hpp"

namespace he_crusk{
template<template<class> class Impl>
class HeCrusk{
public:
  using Operator = he_wrapper_tmpl::Operator<Impl>;
  using Plaintext = he_wrapper_tmpl::Plaintext<Impl>;
  using Ciphertext = he_wrapper_tmpl::Ciphertext<Impl>;

  HeCrusk(std::shared_ptr<Operator> op) : op_(op){}
  ~HeCrusk() = default;
  HeCrusk(const HeCrusk&) = default;
  HeCrusk(HeCrusk&&) noexcept = default;
  
  auto& op(){ return *op_; }
  const auto& op() const { return *op_; }
  const auto& name2id(const std::string& name) const { return name2id_.at(name); }
  auto& get(const std::string& name){ return data_.at(name2id(name)); }
  const auto& get(const std::string& name) const { return data_.at(name2id(name)); }
  

  template<class MsgType>
  void add(RandomizedCiphertext<Impl>&& rc,
           const he_wrapper_tmpl::RawVec<MsgType>& msg){
    auto& x = data_.emplace_back(std::move(rc));
    name2id_[x.name] = data_.size() - 1;

    op().encode(x.pt, msg, x.ep);
    encrypt(x);
    
    x.sbk.generate(x.original, *op_);
    
  }

  void randomize(RandomizedCiphertext<Impl>& rc){
    rc.sbk.randomize(rc.randomized, rc.original, op());
  }
  
private:
  void encrypt(RandomizedCiphertext<Impl>& rc){
    if( rc.size < 2){
      throw std::invalid_argument("Invalid target ciphertext size.");
    }

    op().encrypt(rc.original, rc.pt);

    if( rc.size == rc.original.size() ){
      return;
    }
    
    he_wrapper_tmpl::EncodingParams<Impl> ep;
    ep.configure(rc.original);
    Ciphertext encrypted_one;
    he_wrapper_tmpl::RawVec<double> one(std::vector<double>(op().num_slots(), 1.0));
    Plaintext encoded_one;
    op().encode(encoded_one, one, ep);
    while( rc.original.size() < rc.size ){
      op().encrypt(encrypted_one, encoded_one);
      op().mul(rc.original, encrypted_one);
    }

  }

  std::shared_ptr<Operator> op_;

  std::unordered_map<std::string, int> name2id_;
  
  std::vector<RandomizedCiphertext<Impl>> data_;
  
  

};



}  // namespace he_crusk
