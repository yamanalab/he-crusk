/*
 * Modified version of Microsoft SEAL (native/src/seal/evaluator.cpp)
 * Original work Copyright (c) Microsoft Corporation
 * Modified by Takuya Suzuki (at Yamana Laboratory, Waseda University) in 2025
 *
 * Licensed under the MIT License (see LICENSE file for details).
 */

#include "seal/evaluator.h"
#include "seal/util/common.h"
#include "seal/util/galois.h"
#include "seal/util/numth.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
#include "seal/util/scalingvariant.h"
#include "seal/util/uintarith.h"
#include <algorithm>
#include <cmath>
#include <functional>

namespace seal{
template <typename T, typename S>
SEAL_NODISCARD inline bool are_same_scale(const T &value1, const S &value2) noexcept
{
  return util::are_close<double>(value1.scale(), value2.scale());
}

SEAL_NODISCARD inline bool is_scale_within_bounds(
    double scale, const SEALContext::ContextData &context_data) noexcept
{
  int scale_bit_count_bound = 0;
  switch (context_data.parms().scheme())
    {
      case scheme_type::bfv:
      case scheme_type::bgv:
        scale_bit_count_bound = context_data.parms().plain_modulus().bit_count();
        break;
      case scheme_type::ckks:
        scale_bit_count_bound = context_data.total_coeff_modulus_bit_count();
        break;
      default:
        // Unsupported scheme; check will fail
        scale_bit_count_bound = -1;
    };

  return !(scale <= 0 || (static_cast<int>(log2(scale)) >= scale_bit_count_bound));
}

}  // namespace seal




namespace he_wrapper_tmpl{

template<>
inline void Operator<ImplSeal>::add(Plaintext<ImplSeal>& out,
                                    const Plaintext<ImplSeal>& in) const {
  check_ptr(out, "out", in, "in");
  using namespace std;
  using namespace seal;
  using namespace seal::util;
  if( out.cref().parms_id() != in.cref().parms_id() ){
    throw invalid_argument("out and in parameter mismatch");
  }

  auto &context_data = *key_manager().context().get_context_data(out.cref().parms_id());
  auto &parms = context_data.parms();
  auto &coeff_modulus = parms.coeff_modulus();
  size_t coeff_count = parms.poly_modulus_degree();
  size_t coeff_modulus_size = coeff_modulus.size();

  // CKKS方式のみサポートしている
  RNSIter out_iter(out.ref().data(), coeff_count);
  ConstRNSIter in_iter(in.cref().data(), coeff_count);
  add_poly_coeffmod(out_iter, in_iter, coeff_modulus_size, coeff_modulus, out_iter);
}



template<>
inline void Operator<ImplSeal>::mul(Plaintext<ImplSeal>& out,
                                    const Plaintext<ImplSeal>& in) const {
  auto &context_data = *(key_manager().context().get_context_data(out.cref().parms_id()));
  auto &parms = context_data.parms();
  auto &coeff_modulus = parms.coeff_modulus();
  size_t coeff_count = parms.poly_modulus_degree();
  size_t coeff_modulus_size = coeff_modulus.size();

  seal::util::RNSIter out_iter(out.ref().data(), coeff_count);
  seal::util::ConstRNSIter in_iter(in.cref().data(), coeff_count);
  dyadic_product_coeffmod(out_iter, in_iter, coeff_modulus_size, coeff_modulus, out_iter);

  out.ref().scale() *= in.cref().scale();
    
  if( !seal::is_scale_within_bounds(out.cref().scale(), context_data) ){
    throw std::invalid_argument("scale out of bounds");
  }

}

template<>
template<class MsgType>
void Operator<ImplSeal>::mul(Plaintext<ImplSeal>& out,
                             const RawScalar<MsgType>& in_numerator,
                             const RawScalar<MsgType>& in_denominator,
                             const EncodingParams<ImplSeal>& ep) const {
  check_ptr(out, "out");

  auto context_data_ptr = key_manager().context().get_context_data(out.cref().parms_id());
  if( !context_data_ptr ){
    throw std::invalid_argument("parms_id is not valid for encryption parameters");
  }

  const auto& context_data = *context_data_ptr;
  const auto& parms = context_data.parms();
  const auto& coeff_modulus = parms.coeff_modulus();
  const size_t coeff_modulus_size = coeff_modulus.size();
  const size_t coeff_count = parms.poly_modulus_degree();

  if( !::seal::util::product_fits_in(coeff_modulus_size, coeff_count) ){
    throw std::logic_error("invalid parameters");
  }

  if( ep.scale <= 0
      || (static_cast<int>(log2(ep.scale)) >= context_data.total_coeff_modulus_bit_count()) ){
    throw std::invalid_argument("scale out of bounds");
  }

  auto encode_value = [&](const RawScalar<MsgType>& in){
    double value = in.cref() * ep.scale;
    
    int coeff_bit_count = static_cast<int>(log2(fabs(value))) + 2;
    if( coeff_bit_count >= context_data.total_coeff_modulus_bit_count() ){
      throw std::invalid_argument("encoded value is too large");
    }
    
    double coeffd = round(value);
    bool is_negative = std::signbit(coeffd);
    coeffd = fabs(coeffd);

    return std::make_tuple(coeffd, is_negative, coeff_bit_count);
  };

  auto [coeffd_numerator, is_negative_numerator, coeff_bit_count_numerator] = encode_value(in_numerator);
  auto [coeffd_denominator, is_negative_denominator, coeff_bit_count_denominator] = encode_value(in_denominator);
  
  // CKKS方式のみサポートしている
  auto eval_mul = [&](auto&& calc_encoded_scalar){
    ::seal::util::RNSIter out_iter(out.ref().data(), coeff_count);
    ::seal::util::PtrIter<const ::seal::Modulus*> modulus_iter = coeff_modulus.data();
    SEAL_ITERATE(::seal::util::iter(out_iter, modulus_iter), coeff_modulus_size, [&](auto I){
      const ::seal::Modulus& modulus = get<1>(I);
      auto [encoded_scalar, is_negative] = calc_encoded_scalar(modulus);
      if( is_negative ){
        encoded_scalar = ::seal::util::negate_uint_mod(encoded_scalar, modulus);
      }
      ::seal::util::multiply_poly_scalar_coeffmod(get<0>(I), coeff_count, encoded_scalar, modulus, get<0>(I));
    });
  };

  if( coeff_bit_count_numerator <= 64 && coeff_bit_count_denominator ){
    uint64_t coeffu_numerator = static_cast<uint64_t>(fabs(coeffd_numerator));
    uint64_t coeffu_denominator = static_cast<uint64_t>(fabs(coeffd_denominator));
    eval_mul([coeffu_numerator, is_negative_numerator, coeffu_denominator, is_negative_denominator](const auto& modulus){
      uint64_t numerator = ::seal::util::barrett_reduce_64(coeffu_numerator, modulus);
      uint64_t denominator = ::seal::util::barrett_reduce_64(coeffu_denominator, modulus);
      seal::util::try_invert_uint_mod(denominator, modulus.value(), denominator);
      
      return std::make_tuple(
          multiply_uint_mod(numerator, denominator, modulus),
          is_negative_numerator ^ is_negative_denominator
      );
    });
  }else{
    util::throw_not_implemented_error(__FILE__, __LINE__, __func__);
  }

  out.scale() *= ep.scale;
  
}

template<>
template<class MsgType>
void Operator<ImplSeal>::mul(Ciphertext<ImplSeal>& out,
                             const RawScalar<MsgType>& in_numerator,
                             const RawScalar<MsgType>& in_denominator,
                             const EncodingParams<ImplSeal>& ep) const {
  check_ptr(out, "out");

  auto context_data_ptr = key_manager().context().get_context_data(out.cref().parms_id());
  if( !context_data_ptr ){
    throw std::invalid_argument("parms_id is not valid for encryption parameters");
  }

  const auto& context_data = *context_data_ptr;
  const auto& parms = context_data.parms();
  const auto& coeff_modulus = parms.coeff_modulus();
  const size_t coeff_modulus_size = coeff_modulus.size();
  const size_t coeff_count = parms.poly_modulus_degree();

  if( !::seal::util::product_fits_in(coeff_modulus_size, coeff_count) ){
    throw std::logic_error("invalid parameters");
  }

  if( ep.scale <= 0
      || (static_cast<int>(log2(ep.scale)) >= context_data.total_coeff_modulus_bit_count()) ){
    throw std::invalid_argument("scale out of bounds");
  }

  auto encode_value = [&](const RawScalar<MsgType>& in){
    double value = in.cref() * ep.scale;
    
    int coeff_bit_count = static_cast<int>(log2(fabs(value))) + 2;
    if( coeff_bit_count >= context_data.total_coeff_modulus_bit_count() ){
      throw std::invalid_argument("encoded value is too large");
    }
    
    double coeffd = round(value);
    bool is_negative = std::signbit(coeffd);
    coeffd = fabs(coeffd);

    return std::make_tuple(coeffd, is_negative, coeff_bit_count);
  };

  auto [coeffd_numerator, is_negative_numerator, coeff_bit_count_numerator] = encode_value(in_numerator);
  auto [coeffd_denominator, is_negative_denominator, coeff_bit_count_denominator] = encode_value(in_denominator);
  
  // CKKS方式のみサポートしている
  auto eval_mul = [&](auto&& calc_encoded_scalar){
    ::seal::util::PtrIter<const ::seal::Modulus*> modulus_iter = coeff_modulus.data();
    SEAL_ITERATE(::seal::util::iter(out.ref()), out.size(), [&](auto J) {
      SEAL_ITERATE(::seal::util::iter(J, modulus_iter), coeff_modulus_size, [&](auto I){
        const ::seal::Modulus& modulus = get<1>(I);
        auto [encoded_scalar, is_negative] = calc_encoded_scalar(modulus);
        if( is_negative ){
          encoded_scalar = ::seal::util::negate_uint_mod(encoded_scalar, modulus);
        }
        ::seal::util::multiply_poly_scalar_coeffmod(get<0>(I), coeff_count, encoded_scalar, modulus, get<0>(I));
      });
    });
  };

  if( coeff_bit_count_numerator <= 64 && coeff_bit_count_denominator ){
    uint64_t coeffu_numerator = static_cast<uint64_t>(fabs(coeffd_numerator));
    uint64_t coeffu_denominator = static_cast<uint64_t>(fabs(coeffd_denominator));
    eval_mul([coeffu_numerator, is_negative_numerator, coeffu_denominator, is_negative_denominator](const auto& modulus){
      uint64_t numerator = ::seal::util::barrett_reduce_64(coeffu_numerator, modulus);
      uint64_t denominator = ::seal::util::barrett_reduce_64(coeffu_denominator, modulus);
      seal::util::try_invert_uint_mod(denominator, modulus.value(), denominator);
      
      return std::make_tuple(
          ::seal::util::multiply_uint_mod(numerator, denominator, modulus),
          is_negative_numerator ^ is_negative_denominator
      );
    });
  }else{
    util::throw_not_implemented_error(__FILE__, __LINE__, __func__);
  }

  out.scale() *= ep.scale;

}

}  // namespace he_wrapper_tmpl

