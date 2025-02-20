#pragma once

#include<algorithm>
#include<cassert>
#include<filesystem>
#include<fstream>
#include<numeric>

#include"util/error.hpp"

namespace he_wrapper_tmpl{
template<template<class> class Impl>
class Operator{
public:
  enum class OpType{
    add,
    sub,
    mul,
  };
  
  Operator(std::shared_ptr<KeyManager<Impl>> km);
  virtual ~Operator() = default;
  Operator(const Operator&) = delete;
  Operator(Operator&&) noexcept = default;
  
  
  ////////////////////////////////////////
  // Getter/Setter
  ////////////////////////////////////////
  auto& key_manager(){ return *key_manager_; }
  const auto& key_manager() const { return *key_manager_; }
  size_t num_slots() const { return key_manager().num_slots(); }

  EncodingParams<Impl> get_initial_encoding_params() const;
  ////////////////////////////////////////

  
  ////////////////////////////////////////
  // Operation execution
  ////////////////////////////////////////
  template<OpType op_type>
  static const std::string& get_op_name(){ return OpExecutor<op_type>::op_name; }

  template<OpType op_type>
  struct OpExecutor{
    static const std::string op_name;
    template<class ...Args>
    static void exec(const Operator& op, Args&&... args);
  };
  
  template<OpType op_type, class ...Args>
  void exec(Args&&... args){
    OpExecutor<op_type>::exec(*this, std::forward<Args>(args)...);
  }
  ////////////////////////////////////////


  ////////////////////////////////////////
  // Memory management
  ////////////////////////////////////////
  template<class T>
  void allocate(T& out) const {
    out.allocate(key_manager());
  }

  template<class T>
  void allocate(T& out, const int level) const {
    out.allocate(key_manager(), level);
  }
  
  template<class T>
  void allocate(T& out, const int level, const double scale) const {
    out.allocate(key_manager(), level, scale);
  }

  template<class T>
  void reallocate(T& out, const int level) const {
    out.reallocate(key_manager(), level);
  }

  template<class T>
  void reallocate(T& out, const int level, const double scale) const {
    out.reallocate(key_manager(), level, scale);
  }

  template<class T>
  void deallocate(T& out) const {
    out.deallocate(key_manager());
  }

  /**
   * ScalarPlaintext, Plaintext, Ciphertextのdata_をnullptrにする．
   */
  template<class T>
  void unlink(T& out) const {
    out.unlink();
  }
  ////////////////////////////////////////

  
  ////////////////////////////////////////
  // Encode/Decode and Encrypt/Decrypt
  ////////////////////////////////////////
  template<class MsgType>
  void encode(Plaintext<Impl>& out,
              const RawVec<MsgType>& in,
              const double scale) const;
  
  template<class MsgType>
  void encode(Plaintext<Impl>& out,
              const RawVec<MsgType>& in,
              const EncodingParams<Impl>& params) const;

  template<class MsgType>
  void encode(Plaintext<Impl>& out,
              const RawVec<MsgType>& in) const {
    encode(out, in, key_manager().default_scale());
  }

  template<class MsgType>
  Plaintext<Impl> encode(const RawVec<MsgType>& in,
                         const EncodingParams<Impl>& params) const {
    Plaintext<Impl> out;
    encode(out, in, params);
    return out;
  }
  
  template<class MsgType>
  void decode(RawVec<MsgType>& out,
              const Plaintext<Impl>& in) const;

  template<class MsgType>
  RawVec<MsgType> decode(const Plaintext<Impl>& in) const {
    RawVec<MsgType> out;
    decode(out, in);
    return out;
  }

  void encrypt(Ciphertext<Impl>& out,
               const Plaintext<Impl>& in) const;

  void encrypt(Ciphertext<Impl>& out,
               const Plaintext<Impl>& in,
               const size_t size) const;
    
  Ciphertext<Impl> encrypt(const Plaintext<Impl>& in) const {
    Ciphertext<Impl> out;
    encrypt(out, in);
    return out;
  }

  template<class MsgType>
  void encode_and_encrypt(Ciphertext<Impl>& out,
                          const RawVec<MsgType>& in) const {
    encrypt(out, encode(in));
  }

  template<class MsgType>
  void encode_and_encrypt(Ciphertext<Impl>& out, const RawVec<MsgType>& in,
                          const EncodingParams<Impl>& params) const {
    encrypt(out, encode(in, params));
  }

  template<class MsgType>
  Ciphertext<Impl> encode_and_encrypt(const RawVec<MsgType>& in,
                                      const EncodingParams<Impl>& params) const {
    return encrypt(encode(in, params));
  }
  
  void decrypt(Plaintext<Impl>& out,
               const Ciphertext<Impl>& in);

  Plaintext<Impl> decrypt(const Ciphertext<Impl>& in){
    Plaintext<Impl> out;
    decrypt(out, in);
    return out;
  }
  
  template<class MsgType>
  void decrypt_and_decode(RawVec<MsgType>& out,
                          const Ciphertext<Impl>& in){
    decode(out, decrypt(in));
  }

  template<class MsgType>
  RawVec<MsgType> decrypt_and_decode(const Ciphertext<Impl>& in){
    return decode<MsgType>(decrypt(in));
  }
  ////////////////////////////////////////

  
  ////////////////////////////////////////
  // Move
  ////////////////////////////////////////
  void move(Plaintext<Impl>& out,
            Plaintext<Impl>& in) const {
    allocate(out, -1, 0.0);
    out.ref() = std::move(in.ref());
  }

  void move(Plaintext<Impl>& out,
            Plaintext<Impl>&& in) const {
    allocate(out, -1, 0.0);
    out.ref() = std::move(in.ref());
  }

  void move(Ciphertext<Impl>& out,
            Ciphertext<Impl>& in) const {
    allocate(out, -1, 0.0);
    out.ref() = std::move(in.ref());
  }

  void move(Ciphertext<Impl>& out,
            Ciphertext<Impl>&& in) const {
    allocate(out, -1, 0.0);
    out.ref() = std::move(in.ref());
  }
  ////////////////////////////////////////

  
  ////////////////////////////////////////
  // Copy
  ////////////////////////////////////////
  void copy(Plaintext<Impl>& out,
            const Plaintext<Impl>& in) const {
    check_ptr(in, "in");
    if( out.ptr() == in.ptr() ){ return; }
    allocate(out, -1, 0.0);
    out.ref() = in.cref();
  }

  void copy(Ciphertext<Impl>& out,
            const Ciphertext<Impl>& in) const {
    check_ptr(in, "in");
    if( out.ptr() == in.ptr() ){ return; }
    allocate(out, -1, 0.0);
    out.ref() = in.cref();
  }
  ////////////////////////////////////////


  ////////////////////////////////////////
  // Load & Save
  ////////////////////////////////////////
  void load(Plaintext<Impl>& out,
            const std::filesystem::path& path) const;
  
  void load(Ciphertext<Impl>& out,
            const std::filesystem::path& path) const;
  
  void save(const Plaintext<Impl>& in,
            const std::filesystem::path& path) const;

  void save(const Ciphertext<Impl>& in,
            const std::filesystem::path& path) const;

  void save_with_sym_encryption(const Plaintext<Impl>& in,
                                const std::filesystem::path& path) const;
  ////////////////////////////////////////


  void check_ptr() const { return; }

  template<class Head, class ...Tails>
  void check_ptr(const Head& head, const std::string& name, const Tails&... tails) const {
    if( head.ptr() == nullptr ){
      throw std::runtime_error(name + " is nullptr.");
    }
    check_ptr(tails...);
  }


  
  void negate(Ciphertext<Impl>& out,
              const Ciphertext<Impl>& in) const;
  
  void invert(Plaintext<Impl>& out,
              const Plaintext<Impl>& in) const;



  void add(Plaintext<Impl>& out,
           const Plaintext<Impl>& in) const;

  void add(Ciphertext<Impl>& out,
           const Plaintext<Impl>& in) const;

  void add(Ciphertext<Impl>& out,
           const Ciphertext<Impl>& in1,
           const Plaintext<Impl>& in2) const;

  void add(Ciphertext<Impl>& out,
           const Ciphertext<Impl>& in) const;
  
  void add(Ciphertext<Impl>& out,
           const Ciphertext<Impl>& in1,
           const Ciphertext<Impl>& in2) const;


  
  void sub(Ciphertext<Impl>& out,
           const Plaintext<Impl>& in) const;
  
  void sub(Ciphertext<Impl>& out,
           const Ciphertext<Impl>& in1,
           const Plaintext<Impl>& in2) const;
  
  void sub(Ciphertext<Impl>& out,
           const Ciphertext<Impl>& in) const;
  
  void sub(Ciphertext<Impl>& out,
           const Ciphertext<Impl>& in1,
           const Ciphertext<Impl>& in2) const;  
  
  

  void mul(Plaintext<Impl>& out,
           const Plaintext<Impl>& in) const;

  void mul(Ciphertext<Impl>& out,
           const Plaintext<Impl>& in) const;
  
  void mul(Ciphertext<Impl>& out,
           const Ciphertext<Impl>& in1,
           const Plaintext<Impl>& in2) const;
  
  void mul(Ciphertext<Impl>& out,
           const Ciphertext<Impl>& in) const;
  
  void mul(Ciphertext<Impl>& out,
           const Ciphertext<Impl>& in1,
           const Ciphertext<Impl>& in2) const;

  template<class MsgType>
  void mul(Plaintext<Impl>& out,
           const RawScalar<MsgType>& in_numerator,
           const RawScalar<MsgType>& in_denominator,
           const EncodingParams<Impl>& ep) const;
    
  template<class MsgType>
  void mul(Ciphertext<Impl>& out,
           const RawScalar<MsgType>& in_numerator,
           const RawScalar<MsgType>& in_denominator,
           const EncodingParams<Impl>& ep) const;

  template<class MsgType>
  void mul(Ciphertext<Impl>& out,
           const MsgType& in_numerator,
           const MsgType& in_denominator,
           const EncodingParams<Impl>& ep) const {
    mul(out, RawScalar<MsgType>(in_numerator), RawScalar<MsgType>(in_denominator), ep);
  }


  
  void square(Ciphertext<Impl>& out) const;
  
  void square(Ciphertext<Impl>& out,
              const Ciphertext<Impl>& in) const;


  
  void relinearize(Ciphertext<Impl>& out) const;
  
  void relinearize(Ciphertext<Impl>& out,
                   const Ciphertext<Impl>& in) const;


  void rescale(Plaintext<Impl>& out) const;
  
  void rescale(Ciphertext<Impl>& out) const;
  
  void rescale(Ciphertext<Impl>& out,
               const Ciphertext<Impl>& in) const;

  
  void mod_down(Plaintext<Impl>& out, const int n) const;
  
  void mod_down(Plaintext<Impl>& out,
                const Plaintext<Impl>& in, const int n) const;
  
  void mod_down(Ciphertext<Impl>& out, const int n) const;
  
  void mod_down(Ciphertext<Impl>& out,
                const Ciphertext<Impl>& in, const int n) const;


  
  /// SEAL等と同じ回転方向（shift_count > 0で左回転）
  void rotate(Ciphertext<Impl>& out, const int shift_count) const;
  
  void rotate(Ciphertext<Impl>& out,
              const Ciphertext<Impl>& in, const int shift_count) const;


  
  void bootstrap(Ciphertext<Impl>& out) const;
  
  void bootstrap(Ciphertext<Impl>& out,
                 const Ciphertext<Impl>& in) const {
    allocate(out, -1, 0.0);
    copy(out, in);
    bootstrap(out);
  }

  /**
   * 複数の暗号文に対する総和や総積の一部分を実行するための関数
   */
  template<OpType op_type, class Type>
  void accumulate(Type& out,
                  const Type& in) const {
    if( out.ptr() == nullptr ){
      copy(out, in);
    }else{
      if constexpr( op_type == OpType::add ){
        add(out, in);
      }else if constexpr( op_type == OpType::sub ){
        sub(out, in);
      }else if constexpr( op_type == OpType::mul ){
        mul(out, in);
      }else{
        util::throw_not_implemented_error(__FILE__, __LINE__, __func__);
      }
    }
  }

  void rotate_and_sum(Ciphertext<Impl>& out,
                      const size_t target_slot_id,
                      const std::vector<int>& rotate_steps) const;

  void rotate_and_sum(Ciphertext<Impl>& out, const Ciphertext<Impl>& in,
                      const size_t target_slot_id,
                      const std::vector<int>& rotate_steps) const;
  
    
  template<class T, class U>
  void adjust_level(T& out, U& in) const;
  
  template<class T, class U>
  void adjust_scale(T& out, U& in) const;
  

private:
  std::shared_ptr<KeyManager<Impl>> key_manager_;
  
  
};




}  // namespace he_wrapper_tmpl
