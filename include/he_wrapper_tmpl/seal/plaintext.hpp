#pragma once

namespace he_wrapper_tmpl{
template<>
class Plaintext<ImplSeal>{
public:
  using DataType = ::seal::Plaintext;

  Plaintext(){}
  Plaintext(const KeyManager<ImplSeal>& km)
    : poly_degree_(km.poly_degree()){ allocate(km); }
  virtual ~Plaintext() = default;
  Plaintext(const Plaintext&) = default;
  Plaintext(Plaintext&&) noexcept = default;

  Plaintext& operator=(const Plaintext&) = default;
  Plaintext& operator=(Plaintext&&) = default;

  bool operator==(const Plaintext&) const = default;
  
  auto& ptr() noexcept { return data_; }
  const auto& ptr() const noexcept { return data_; }
  auto& ref(){ return *data_; }
  const auto& ref() const { return *data_; }
  const auto& cref() const { return *data_; }
  [[deprecated]]
  int level() const noexcept { return cref().coeff_count() / poly_degree_ - 1; }
  int num_moduli() const noexcept { return cref().coeff_count() / poly_degree_; }
  void scale(const double s){ ref().scale() = s; }
  double& scale() noexcept { return ref().scale(); }
  double scale() const noexcept { return cref().scale(); }
  
  /// @note 現状，levelは反映されるようには実装していない
  void allocate(const KeyManager<ImplSeal>& km, const int level, const double scale){
    if( data_ == nullptr ){
      data_ = std::make_shared<::seal::Plaintext>();
    }
    this->scale() = scale;
  }

  void allocate(const KeyManager<ImplSeal>& km){
    allocate(km, km.max_level(), km.default_scale());
  }

  void allocate(const KeyManager<ImplSeal>& km, const int level){
    allocate(km, level, km.default_scale());
  }
  
  void reallocate(const KeyManager<ImplSeal>& km,
                  const int level, const double scale){
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
    if( t != vec.size() ){
      throw std::invalid_argument("Invalid size of vector for Ciphertext.");
    }
    scale() = ep.scale;
    data_->parms_id() = seal::parms_id_zero;
    data_->resize(vec.size());
    data_->parms_id() = ep.parms_id;
    std::copy(vec.begin(), vec.end(), data_->data());
  }

  
private:
  int poly_degree_ = 0;
  
  std::shared_ptr<DataType> data_ = nullptr;

};



}  // namespace he_wrapper_tmpl

