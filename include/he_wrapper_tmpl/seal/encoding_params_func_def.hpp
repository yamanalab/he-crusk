#pragma once

namespace he_wrapper_tmpl{
inline EncodingParams<ImplSeal>& EncodingParams<ImplSeal>::configure(const Plaintext<ImplSeal>& in){
  scale = in.cref().scale();
  parms_id = in.cref().parms_id();
  return *this;
}

inline EncodingParams<ImplSeal>& EncodingParams<ImplSeal>::configure(const Ciphertext<ImplSeal>& in){
  scale = in.cref().scale();
  parms_id = in.cref().parms_id();
  return *this;
}

inline EncodingParams<ImplSeal>& EncodingParams<ImplSeal>::set_scale(const double in){
  scale = in;
  return *this;
}

}  // namespace he_wrapper_tmpl

