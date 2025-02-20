#pragma once

#include"he_wrapper_tmpl/base/base.hpp"

#include"seal/seal.h"

namespace he_wrapper_tmpl{
template<class MsgType>
struct ImplSeal{
  using RawScalar = ::he_wrapper::RawScalar<MsgType>;
  using RawVec = ::he_wrapper::RawVec<MsgType>;

  using KeyManager = ::he_wrapper_tmpl::KeyManager<ImplSeal>;
  
  using Plaintext = ::he_wrapper_tmpl::Plaintext<ImplSeal>;
  using Ciphertext = ::he_wrapper_tmpl::Ciphertext<ImplSeal>;

  using EncodingParams = ::he_wrapper_tmpl::EncodingParams<ImplSeal>;
  using EncodingParamsList = std::vector<EncodingParams>;
  using Operator = ::he_wrapper_tmpl::Operator<ImplSeal>;
  
};

}  // namespace he_wrapper_tmpl


#include"he_wrapper_tmpl/seal/key_manager.hpp"
#include"he_wrapper_tmpl/seal/encoding_params.hpp"
#include"he_wrapper_tmpl/seal/plaintext.hpp"
#include"he_wrapper_tmpl/seal/ciphertext.hpp"
#include"he_wrapper_tmpl/seal/operator.hpp"

#include"he_wrapper_tmpl/seal/encoding_params_func_def.hpp"


