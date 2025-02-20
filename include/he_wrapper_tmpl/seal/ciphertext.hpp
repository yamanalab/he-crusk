#pragma once

namespace he_wrapper_tmpl{
template<>
class Ciphertext<ImplSeal>{
public:
  using DataType = ::seal::Ciphertext;
  
  Ciphertext(){}
  Ciphertext(const KeyManager<ImplSeal>& km){ allocate(km); }
  virtual ~Ciphertext() = default;
  Ciphertext(const Ciphertext&) = default;
  Ciphertext(Ciphertext&&) noexcept = default;

  Ciphertext& operator=(const Ciphertext&) = default;
  Ciphertext& operator=(Ciphertext&&) = default;

  auto& ptr() noexcept { return data_; }
  const auto& ptr() const noexcept { return data_; }
  auto& ref() noexcept { return *data_; }
  const auto& ref() const noexcept { return *data_; }
  const auto& cref() const noexcept { return *data_; }
  
  size_t size() const { return cref().size(); }
  int level() const { return cref().coeff_modulus_size() - 1; }
  int num_moduli() const { return cref().coeff_modulus_size(); }
  void scale(const double s){ ref().scale() = s; }
  double& scale(){ return ref().scale(); }
  double scale() const { return cref().scale(); }

  /// @note 現状，levelは反映されるようには実装していない
  void allocate(const KeyManager<ImplSeal>& km, const int level, const double scale){
    if( data_ != nullptr ){ return; }
    data_ = std::make_shared<::seal::Ciphertext>();
    this->scale() = scale;
  }

  void allocate(const KeyManager<ImplSeal>& km){
    allocate(km, km.max_level(), km.default_scale());
  }

  void allocate(const KeyManager<ImplSeal>& km, const int level){
    allocate(km, level, km.default_scale());
  }

  void reallocate(const KeyManager<ImplSeal>& km, const int level, const double scale){
    deallocate(km);
    allocate(km, level, scale);
  }

  void reallocate(const KeyManager<ImplSeal>& km){
    reallocate(km, km.max_level(), km.default_scale());
  }

  void reallocate(const KeyManager<ImplSeal>& km, const int level){
    reallocate(km, level, km.default_scale());
  }

  void deallocate(){
    data_ = nullptr;
  }

  void deallocate(const KeyManager<ImplSeal>& km){
    deallocate();
  }

  void unlink(){
    data_ = nullptr;
  }

  void set_data(std::vector<uint64_t>&& vec, const KeyManager<ImplSeal>& km,
                const EncodingParams<ImplSeal>& ep){
    const auto& moduli = km.context().get_context_data(ep.parms_id)->parms().coeff_modulus();
    const size_t t = km.poly_degree() * moduli.size();
    const size_t size = vec.size() / t;
    if( size * t != vec.size() ){
      throw std::invalid_argument("Invalid size of vector for Ciphertext.");
    }
    scale() = ep.scale;
    data_->resize(km.context(), ep.parms_id, size);
    std::copy(vec.begin(), vec.end(), data_->data());
    data_->is_ntt_form() = true;
  }
  
private:
  std::shared_ptr<DataType> data_ = nullptr;

};



}  // namespace he_wrapper_tmpl

