#pragma once


namespace he_wrapper_tmpl{
template<>
struct EncodingParams<ImplSeal>{
  EncodingParams() = default;
  ~EncodingParams() = default;
  EncodingParams(const Plaintext<ImplSeal>& in){ configure(in); }
  EncodingParams(const Ciphertext<ImplSeal>& in){ configure(in); }
  EncodingParams(const EncodingParams&) = default;
  EncodingParams(EncodingParams&&) noexcept = default;

  EncodingParams& operator=(const EncodingParams&) = default;
  EncodingParams& operator=(EncodingParams&&) = default;

  EncodingParams<ImplSeal>& configure(const Plaintext<ImplSeal>& in);
  EncodingParams<ImplSeal>& configure(const Ciphertext<ImplSeal>& in);

  EncodingParams<ImplSeal>& set_scale(const double in);
  
  /// エンコードをスキップするかどうかのフラグ
  bool skip_encode = false;

  double scale = 0.0;
  
  ::seal::parms_id_type parms_id;
  
};



}  // namespace he_wrapper_tmpl

