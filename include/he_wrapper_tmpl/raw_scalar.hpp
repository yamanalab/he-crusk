#pragma once

namespace he_wrapper{
template<class T>
class RawScalar{
public:
  RawScalar() = default;
  RawScalar(const T in) : data_(in){}
  ~RawScalar() = default;
  RawScalar(const RawScalar&) = default;
  RawScalar(RawScalar&&) noexcept = default;

  RawScalar& operator=(const RawScalar&) = default;
  RawScalar& operator=(RawScalar&&) = default;
  
  auto& ref() noexcept { return data_; }
  const auto& ref() const noexcept { return data_; }
  const auto& cref() const noexcept { return data_; }
  
private:
  T data_;

};


}  // namespace he_wrapper

