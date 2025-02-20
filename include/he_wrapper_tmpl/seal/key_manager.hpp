#pragma once

#include<memory>

namespace he_wrapper_tmpl{
template<>
class KeyManager<ImplSeal>{
public:
  KeyManager(){}
  virtual ~KeyManager() = default;
  KeyManager(const KeyManager&) = delete;
  KeyManager(KeyManager&&) noexcept = default;

#define SETTER_AND_GETTER(name, Type)                 \
  auto& name(const Type& in) noexcept {               \
    name##_ = in;                                     \
    return *this;                                     \
  }                                                   \
  const Type& name() const noexcept {                 \
    return name##_;                                   \
  }
  
  SETTER_AND_GETTER(poly_degree, int)
  SETTER_AND_GETTER(modulus_bits_list, std::vector<int>)
  SETTER_AND_GETTER(max_level, int)
  SETTER_AND_GETTER(default_scale, double)
  SETTER_AND_GETTER(logq0, int)
  SETTER_AND_GETTER(rotate_steps, std::vector<int>)
  
  int num_slots() const { return encoder_->slot_count(); }
  
  [[deprecated]]
  auto& modulus_bits_list() noexcept { return modulus_bits_list_; }

  void gen_params(){
    params_ = std::make_unique<::seal::EncryptionParameters>(::seal::scheme_type::ckks);
    params_->set_poly_modulus_degree(poly_degree_);
    params_->set_coeff_modulus(::seal::CoeffModulus::Create(poly_degree_, modulus_bits_list_));
  
    context_ = std::make_unique<::seal::SEALContext>(*params_);
    key_gen_ = std::make_unique<::seal::KeyGenerator>(*context_);

    encoder_ = std::make_unique<::seal::CKKSEncoder>(*context_);
  }

  uint64_t get_modulus(const size_t i) const {
    return params_->coeff_modulus().at(i).value();
  }

  void gen_sk(){
    sk_ = std::make_unique<::seal::SecretKey>(key_gen_->secret_key());
    gen_decryptor();
  }
  void gen_pk(){
    pk_ = std::make_unique<::seal::PublicKey>();
    key_gen_->create_public_key(*pk_);
    gen_encryptor();
    gen_evaluator();
  }
  void gen_rlk(){
    rlk_ = std::make_unique<::seal::RelinKeys>();
    key_gen_->create_relin_keys(*rlk_);
  }
  void gen_glk(){
    glk_ = std::make_unique<::seal::GaloisKeys>();
    if( rotate_steps_.empty() ){
      key_gen_->create_galois_keys(*glk_);
    }else{
      key_gen_->create_galois_keys(rotate_steps_, *glk_);
    }
  }
  void gen_bsk(){
    throw std::logic_error("Bootstrapping is not supported.");
  }

  void load_sk(){ return; }
  void load_pk(){ return; }
  void load_rlk(){ return; }
  void load_glk(){ return; }
  void load_bsk(){ return; }

  void save_sk(){ return; }
  void save_pk(){ return; }
  void save_rlk(){ return; }
  void save_glk(){ return; }
  void save_bsk(){ return; }
  
  void set_sk_to_encryptor(){
    encryptor_->set_secret_key(*sk_);
  }

  
#define ENABLE(name)          \
  auto& enable_##name(){      \
    status_##name##_ = true;  \
    return *this;             \
  }
  ENABLE(sk)
  ENABLE(pk)
  ENABLE(sk_encryption)
  ENABLE(rlk)
  ENABLE(glk)
  ENABLE(bsk)
#undef ENABLE

  auto& enable_glk(const std::vector<int>& rs){
    rotate_steps_ = rs;
    return enable_glk();
  }

#define DISABLE(name)          \
  auto& disable_##name(){      \
    status_##name##_ = false;  \
    return *this;              \
  }
  DISABLE(sk)
  DISABLE(pk)
  DISABLE(sk_encryption)
  DISABLE(rlk)
  DISABLE(glk)
  DISABLE(bsk)
#undef DISABLE
  
  void gen_keys(){
    if( status_sk_ ){ gen_sk(); }
    if( status_pk_ ){ gen_pk(); }
    if( status_sk_encryption_ ){ set_sk_to_encryptor(); }
    if( status_rlk_ ){ gen_rlk(); }
    if( status_glk_ ){ gen_glk(); }
    if( status_bsk_ ){ gen_bsk(); }
  }

  void load_keys(){
    if( status_sk_ ){ load_sk(); }
    if( status_pk_ ){ load_pk(); }
    if( status_sk_encryption_ ){ set_sk_to_encryptor(); }
    if( status_rlk_ ){ load_rlk(); }
    if( status_glk_ ){ load_glk(); }
    if( status_bsk_ ){ load_bsk(); }
  }

  void save_keys(){
    if( status_sk_ ){ save_sk(); }
    if( status_pk_ ){ save_pk(); }
    if( status_rlk_ ){ save_rlk(); }
    if( status_glk_ ){ save_glk(); }
    if( status_bsk_ ){ save_bsk(); }
  }

  const auto& rlk() const { return *rlk_; }
  const auto& glk() const { return *glk_; }
  
  const auto& context() const { return *context_; }
  const auto& encoder() const { return *encoder_; }
  const auto& encryptor() const { return *encryptor_; }
  const auto& evaluator() const { return *evaluator_; }
  auto& decryptor(){ return *decryptor_; }

  
 
private:
  void gen_encryptor(){
    encryptor_ = std::make_unique<::seal::Encryptor>(*context_, *pk_);
  }

  void gen_evaluator(){
    evaluator_ = std::make_unique<::seal::Evaluator>(*context_);
  }

  void gen_decryptor(){
    decryptor_ = std::make_unique<::seal::Decryptor>(*context_, *sk_);
  }

  int poly_degree_ = 0;

  int num_slots_ = 0;

  std::vector<int> modulus_bits_list_;
  
  int max_level_ = 0;

  double default_scale_ = 0.0;

  int logq0_ = 0;
  
  bool status_sk_ = false;
  bool status_pk_ = false;
  bool status_sk_encryption_ = false;
  bool status_rlk_ = false;
  bool status_glk_ = false;
  bool status_bsk_ = false;

  std::vector<int> rotate_steps_;
  
  std::unique_ptr<::seal::EncryptionParameters> params_;

  std::unique_ptr<::seal::SEALContext> context_;

  std::unique_ptr<::seal::KeyGenerator> key_gen_;
  
  std::unique_ptr<::seal::SecretKey> sk_;

  std::unique_ptr<::seal::PublicKey> pk_;

  std::unique_ptr<::seal::RelinKeys> rlk_;

  std::unique_ptr<::seal::GaloisKeys> glk_;

  std::unique_ptr<::seal::CKKSEncoder> encoder_;

  std::unique_ptr<::seal::Encryptor> encryptor_;
  
  std::unique_ptr<::seal::Evaluator> evaluator_;

  std::unique_ptr<::seal::Decryptor> decryptor_;
  
};


}  // namespace he_wrapper_tmpl

