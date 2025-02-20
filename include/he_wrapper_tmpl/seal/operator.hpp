#pragma once

#include"util/error.hpp"

#include"operator_modified_seal.hpp"

namespace he_wrapper_tmpl{
template<>
inline Operator<ImplSeal>::Operator(std::shared_ptr<KeyManager<ImplSeal>> km)
  : key_manager_(std::move(km)){
  std::cout << "This operator computes over SEAL." << std::endl;
}

template<>
inline EncodingParams<ImplSeal> Operator<ImplSeal>::get_initial_encoding_params() const {
  EncodingParams<ImplSeal> ep;
  ep.scale = key_manager().default_scale();
  ep.parms_id = key_manager().context().first_parms_id();
  return ep;
}

template<>
template<class MsgType>
void Operator<ImplSeal>::encode(Plaintext<ImplSeal>& out,
                                const RawVec<MsgType>& in,
                                const double scale) const {
  allocate(out, -1, 0.0);
  key_manager().encoder().encode(in.cref(), scale, out.ref());
}

template<>
template<class MsgType>
void Operator<ImplSeal>::encode(Plaintext<ImplSeal>& out,
                                const RawVec<MsgType>& in,
                                const EncodingParams<ImplSeal>& params) const {
  allocate(out, -1, 0.0);
  key_manager().encoder().encode(in.cref(), params.parms_id, params.scale, out.ref());
}

template<>
template<class MsgType>
void Operator<ImplSeal>::decode(RawVec<MsgType>& out,
                                const Plaintext<ImplSeal>& in) const {
  key_manager().encoder().decode(in.cref(), out.ref());
}

template<>
inline void Operator<ImplSeal>::encrypt(Ciphertext<ImplSeal>& out,
                                        const Plaintext<ImplSeal>& in) const {
  allocate(out, -1, 0.0);
  key_manager().encryptor().encrypt(in.cref(), out.ref());
}

template<>
inline void Operator<ImplSeal>::decrypt(Plaintext<ImplSeal>& out,
                                        const Ciphertext<ImplSeal>& in){
  allocate(out, -1, 0.0);
  key_manager().decryptor().decrypt(in.cref(), out.ref());
}

template<>
inline void Operator<ImplSeal>::load(Plaintext<ImplSeal>& out,
                                     const std::filesystem::path& path) const {
  std::ifstream ifs(path, std::ios::binary);
  allocate(out, -1, 0.0);
  out.ref().load(key_manager().context(), ifs);
}

template<>
inline void Operator<ImplSeal>::load(Ciphertext<ImplSeal>& out,
                                     const std::filesystem::path& path) const {
  std::ifstream ifs(path, std::ios::binary);
  allocate(out, -1, 0.0);
  out.ref().load(key_manager().context(), ifs);
}
  
template<>
inline void Operator<ImplSeal>::save(const Plaintext<ImplSeal>& in,
                                     const std::filesystem::path& path) const {
  std::ofstream ofs(path, std::ios::binary);
  in.cref().save(ofs);
}

template<>
inline void Operator<ImplSeal>::save(const Ciphertext<ImplSeal>& in,
                                     const std::filesystem::path& path) const {
  std::ofstream ofs(path, std::ios::binary);
  in.cref().save(ofs);
}

template<>
inline void Operator<ImplSeal>::save_with_sym_encryption(const Plaintext<ImplSeal>& in,
                                                         const std::filesystem::path& path) const {
  std::ofstream ofs(path, std::ios::binary);
  key_manager().encryptor().encrypt_symmetric(in.cref()).save(ofs);
}


template<>
inline void Operator<ImplSeal>::negate(Ciphertext<ImplSeal>& out,
                                       const Ciphertext<ImplSeal>& in) const {
  copy(out, in);
  const int size = out.size();
  const int n = key_manager().poly_degree();
  const int moduli_count = out.cref().coeff_modulus_size();
  const auto& moduli = key_manager().context().get_context_data(out.cref().parms_id())->parms().coeff_modulus();
  auto itr = out.ref().data();
  for( int k = 0; k < size; ++k ){
    for( int i = 0; i < moduli_count; ++i ){
      const auto q = moduli.at(i).value();
      std::transform(itr, itr + n, itr,
                     [&](uint64_t v){ return (v == 0 ? 0 : q - v); });
      itr += n;
    }
  }

}

template<>
inline void Operator<ImplSeal>::invert(Plaintext<ImplSeal>& out,
                                       const Plaintext<ImplSeal>& in) const {
  copy(out, in);
  const int n = key_manager().poly_degree();
  const int moduli_count = out.cref().coeff_count() / n;
  const auto& moduli = key_manager().context().get_context_data(out.cref().parms_id())->parms().coeff_modulus();
  auto itr = out.ref().data();
  for( int i = 0; i < moduli_count; ++i ){
    const auto q = moduli.at(i).value();
    std::transform(itr, itr + n, itr, [&](uint64_t v){
      uint64_t inv_v;
      seal::util::try_invert_uint_mod(v, q, inv_v);
      return inv_v;
    });
    itr += n;
  }
}


template<>
inline void Operator<ImplSeal>::add(Ciphertext<ImplSeal>& out,
                                    const Plaintext<ImplSeal>& in) const {
  check_ptr(out, "out", in, "in");
  key_manager().evaluator().add_plain_inplace(out.ref(), in.cref());
}

template<>
inline void Operator<ImplSeal>::add(Ciphertext<ImplSeal>& out,
                                    const Ciphertext<ImplSeal>& in1,
                                    const Plaintext<ImplSeal>& in2) const {
  if( out.ptr() == in1.ptr() ){
    add(out, in2);
  }else{
    allocate(out, -1, 0.0);
    check_ptr(out, "out", in1, "in1", in2, "in2");
    key_manager().evaluator().add_plain(in1.cref(), in2.cref(), out.ref());
  }
}

template<>
inline void Operator<ImplSeal>::add(Ciphertext<ImplSeal>& out,
                                    const Ciphertext<ImplSeal>& in) const {
  check_ptr(out, "out", in, "in");
  key_manager().evaluator().add_inplace(out.ref(), in.cref());
}

template<>
inline void Operator<ImplSeal>::add(Ciphertext<ImplSeal>& out,
                                    const Ciphertext<ImplSeal>& in1,
                                    const Ciphertext<ImplSeal>& in2) const {
  if( out.ptr() == in1.ptr() ){
    add(out, in2);
  }else if( out.ptr() == in2.ptr() ){
    add(out, in1);
  }else{
    allocate(out, -1, 0.0);
    check_ptr(out, "out", in1, "in1", in2, "in2");
    key_manager().evaluator().add(in1.cref(), in2.cref(), out.ref());
  }
}



template<>
inline void Operator<ImplSeal>::sub(Ciphertext<ImplSeal>& out,
                                    const Plaintext<ImplSeal>& in) const {
  check_ptr(out, "out", in, "in");
  key_manager().evaluator().sub_plain_inplace(out.ref(), in.cref());
}
  
template<>
inline void Operator<ImplSeal>::sub(Ciphertext<ImplSeal>& out,
                                    const Ciphertext<ImplSeal>& in1,
                                    const Plaintext<ImplSeal>& in2) const {
  if( out.ptr() == in1.ptr() ){
    sub(out, in2);
  }else{
    allocate(out, -1, 0.0);
    check_ptr(out, "out", in1, "in1", in2, "in2");
    key_manager().evaluator().sub_plain(in1.cref(), in2.cref(), out.ref());
  }
}

template<>
inline void Operator<ImplSeal>::sub(Ciphertext<ImplSeal>& out,
                                    const Ciphertext<ImplSeal>& in) const {
  check_ptr(out, "out", in, "in");
  key_manager().evaluator().sub_inplace(out.ref(), in.cref());
}

template<>
inline void Operator<ImplSeal>::sub(Ciphertext<ImplSeal>& out,
                                    const Ciphertext<ImplSeal>& in1,
                                    const Ciphertext<ImplSeal>& in2) const {
  if( out.ptr() == in1.ptr() ){
    sub(out, in2);
  }else if( out.ptr() == in2.ptr() ){
    sub(out, in1);
  }else{
    allocate(out, -1, 0.0);
    check_ptr(out, "out", in1, "in1", in2, "in2");
    key_manager().evaluator().sub(in1.cref(), in2.cref(), out.ref());
  }
}

template<>
inline void Operator<ImplSeal>::mul(Ciphertext<ImplSeal>& out,
                                    const Plaintext<ImplSeal>& in) const {
  check_ptr(out, "out", in, "in");
  key_manager().evaluator().multiply_plain_inplace(out.ref(), in.cref());
}
  
template<>
inline void Operator<ImplSeal>::mul(Ciphertext<ImplSeal>& out,
                                    const Ciphertext<ImplSeal>& in1,
                                    const Plaintext<ImplSeal>& in2) const {
  if( out.ptr() == in1.ptr() ){
    mul(out, in2);
  }else{
    allocate(out, -1, 0.0);
    check_ptr(out, "out", in1, "in1", in2, "in2");
    key_manager().evaluator().multiply_plain(in1.cref(), in2.cref(), out.ref());
  }
}

template<>
inline void Operator<ImplSeal>::mul(Ciphertext<ImplSeal>& out,
                                    const Ciphertext<ImplSeal>& in) const {
  check_ptr(out, "out", in, "in");
  key_manager().evaluator().multiply_inplace(out.ref(), in.cref());
}

template<>
inline void Operator<ImplSeal>::mul(Ciphertext<ImplSeal>& out,
                                    const Ciphertext<ImplSeal>& in1,
                                    const Ciphertext<ImplSeal>& in2) const {
  if( out.ptr() == in1.ptr() ){
    mul(out, in2);
  }else if( out.ptr() == in2.ptr() ){
    mul(out, in1);
  }else{
    allocate(out, -1, 0.0);
    check_ptr(out, "out", in1, "in1", in2, "in2");
    key_manager().evaluator().multiply(in1.cref(), in2.cref(), out.ref());
  }
}



template<>
inline void Operator<ImplSeal>::square(Ciphertext<ImplSeal>& out) const {
  check_ptr(out, "out");
  key_manager().evaluator().square_inplace(out.ref());
}

template<>
inline void Operator<ImplSeal>::square(Ciphertext<ImplSeal>& out,
                                       const Ciphertext<ImplSeal>& in) const {
  if( out.ptr() == in.ptr() ){
    square(out);
  }else{
    allocate(out, -1, 0.0);
    check_ptr(out, "out", in, "in");
    key_manager().evaluator().square(in.cref(), out.ref());
  }
}


template<>
inline void Operator<ImplSeal>::relinearize(Ciphertext<ImplSeal>& out) const {
  check_ptr(out, "out");
  key_manager().evaluator().relinearize_inplace(out.ref(), key_manager().rlk());
}

template<>
inline void Operator<ImplSeal>::relinearize(Ciphertext<ImplSeal>& out,
                                            const Ciphertext<ImplSeal>& in) const {
  if( out.ptr() == in.ptr() ){
    relinearize(out);
  }else{
    allocate(out, -1, 0.0);
    check_ptr(out, "out", in, "in");
    key_manager().evaluator().relinearize(in.cref(), key_manager().rlk(), out.ref());
  }
}

template<>
inline void Operator<ImplSeal>::rescale(Plaintext<ImplSeal>& out) const {
  check_ptr(out, "out");
  util::throw_not_implemented_error(__FILE__, __LINE__, __func__);
}


template<>
inline void Operator<ImplSeal>::rescale(Ciphertext<ImplSeal>& out) const {
  check_ptr(out, "out");
  key_manager().evaluator().rescale_to_next_inplace(out.ref());
}

template<>
inline void Operator<ImplSeal>::rescale(Ciphertext<ImplSeal>& out,
                                        const Ciphertext<ImplSeal>& in) const {
  allocate(out, -1, 0.0);
  check_ptr(out, "out", in, "in");
  key_manager().evaluator().rescale_to_next(in.cref(), out.ref());
}


  
template<>
inline void Operator<ImplSeal>::mod_down(Plaintext<ImplSeal>& out, const int n) const {
  check_ptr(out, "out");
  for( int i = 0; i < n; ++i ){
    key_manager().evaluator().mod_switch_to_next_inplace(out.ref());
  }
}

template<>
inline void Operator<ImplSeal>::mod_down(Plaintext<ImplSeal>& out,
                                         const Plaintext<ImplSeal>& in, const int n) const {
  check_ptr(in, "in");
  if( out.ptr() != in.ptr() ){ copy(out, in); }
  mod_down(out, n);
}

template<>
inline void Operator<ImplSeal>::mod_down(Ciphertext<ImplSeal>& out, const int n) const {
  check_ptr(out, "out");
  for( int i = 0; i < n; ++i ){
    key_manager().evaluator().mod_switch_to_next_inplace(out.ref());
  }
}

template<>
inline void Operator<ImplSeal>::mod_down(Ciphertext<ImplSeal>& out,
                                         const Ciphertext<ImplSeal>& in, const int n) const {
  check_ptr(in, "in");
  if( out.ptr() != in.ptr() ){ copy(out, in); }
  mod_down(out, n);
}


template<>
inline void Operator<ImplSeal>::rotate(Ciphertext<ImplSeal>& out,
                                       const int shift_count) const {
  check_ptr(out, "out");
  if( shift_count == 0 ){ return; }
  key_manager().evaluator().rotate_vector_inplace(
      out.ref(), shift_count, key_manager().glk()
  );
}
  
template<>
inline void Operator<ImplSeal>::rotate(Ciphertext<ImplSeal>& out,
                                       const Ciphertext<ImplSeal>& in,
                                       const int shift_count) const {
  if( out.ptr() == in.ptr() ){
    rotate(out, shift_count);
  }else{
    check_ptr(in, "in");
    if( shift_count == 0 ){
      copy(out, in);
    }else{
      allocate(out, -1, 0.0);
      check_ptr(out, "out");
      key_manager().evaluator().rotate_vector(in.cref(), shift_count,
                                              key_manager().glk(), out.ref());
    }
  }
}



template<>
inline void Operator<ImplSeal>::bootstrap(Ciphertext<ImplSeal>& out) const {
  throw std::logic_error("Bootstrapping is not supported.");
}





template<>
inline void Operator<ImplSeal>::rotate_and_sum(Ciphertext<ImplSeal>& out,
                                               const size_t target_slot_id,
                                               const std::vector<int>& rotate_steps) const {
  // rotate_stepsの一部もしくは全ての回転方向を考慮してもtarget_slot_idに
  // 結果を入れられない場合は，最後にrotateする必要があり，それを表すフラグ．
  const bool require_additional_rotate = target_slot_id
    != (std::accumulate(
            rotate_steps.cbegin(), rotate_steps.cend(), size_t{0},
            [](const size_t acc, const int step){
              assert(step > 0);
              return acc | static_cast<size_t>(step);
            }
        ) & target_slot_id);

  Ciphertext<ImplSeal> tmp;
  for( const int step : rotate_steps ){
    rotate(tmp, out, ((step & target_slot_id) == 0 ? step : -step));
    add(out, tmp);
  }

  if( require_additional_rotate ){
    rotate(out, -static_cast<int>(target_slot_id));
  }
}

template<>
inline void Operator<ImplSeal>::rotate_and_sum(Ciphertext<ImplSeal>& out,
                                               const Ciphertext<ImplSeal>& in,
                                               const size_t target_slot_id,
                                               const std::vector<int>& rotate_steps) const {
  if( out.ptr() == in.ptr() ){
    rotate_and_sum(out, target_slot_id, rotate_steps);
  }else{
    copy(out, in);
    rotate_and_sum(out, target_slot_id, rotate_steps);
  }
}

template<>
template<class T, class U>
void Operator<ImplSeal>::adjust_level(T& out, U& in) const {
  check_ptr(out, "out", in, "in");
  while( out.ref().parms_id() != in.cref().parms_id() ){
    mod_down(out, 1);
  }
}

template<>
template<class T, class U>
void Operator<ImplSeal>::adjust_scale(T& out, U& in) const {
  check_ptr(out, "out", in, "in");
  out.ref().scale() = in.cref().scale();
}




}  // namespace he_wrapper_tmpl


