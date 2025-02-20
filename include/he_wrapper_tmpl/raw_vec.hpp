#pragma once

#include<cmath>
#include<ostream>
#include<vector>

namespace he_wrapper{
template<class T>
class RawVec{
public:
  using Type = T;
  
  RawVec() = default;
  RawVec(const int num_slots) : data_(num_slots){}
  RawVec(const std::vector<T>& in) : data_(in){}
  RawVec(std::vector<T>&& in) : data_(std::move(in)){}
  ~RawVec() = default;
  RawVec(const RawVec&) = default;
  RawVec(RawVec&&) noexcept = default;
  
  RawVec& operator=(const RawVec&) = default;
  RawVec& operator=(RawVec&&) = default;

  
  RawVec& operator+=(const T& in){
    std::transform(cbegin(), cend(), begin(),
                   [&](const T& x){ return x + in; });
    return *this;
  }

  RawVec& operator-=(const T& in){
    std::transform(cbegin(), cend(), begin(),
                   [&](const T& x){ return x - in; });
    return *this;
  }

  RawVec& operator*=(const T& in){
    std::transform(cbegin(), cend(), begin(),
                   [&](const T& x){ return x * in; });
    return *this;
  }
  
  RawVec& operator+=(const RawVec& in){
    std::transform(cbegin(), cend(), in.cbegin(), begin(),
                   [](const T& x1, const T& x2){ return x1 + x2; });
    return *this;
  }
  RawVec& operator-=(const RawVec& in){
    std::transform(cbegin(), cend(), in.cbegin(), begin(),
                   [](const T& x1, const T& x2){ return x1 - x2; });
    return *this;
  }
  RawVec& operator*=(const RawVec& in){
    std::transform(cbegin(), cend(), in.cbegin(), begin(),
                   [](const T& x1, const T& x2){ return x1 * x2; });
    return *this;
  }
  RawVec& operator/=(const RawVec& in){
    std::transform(cbegin(), cend(), in.cbegin(), begin(),
                   [](const T& x1, const T& x2){
                     // 0.0 / 0.0は1.0とする．
                     return (x1 == 0.0 ? 0.0 : x1 / x2);
                   }
    );
    return *this;
  }
  
  auto& ref() noexcept { return data_; }
  const auto& ref() const noexcept { return data_; }
  const auto& cref() const noexcept { return data_; }

  auto begin(){ return data_.begin(); }
  auto begin() const { return data_.begin(); }
  auto cbegin() const { return data_.cbegin(); }
  auto end(){ return data_.end(); }
  auto end() const { return data_.end(); }
  auto cend() const { return data_.cend(); }
  
  T& at(const int i){ return data_.at(i); }
  const T& at(const int i) const { return data_.at(i); }

  size_t size() const noexcept { return data_.size(); }
  
  void resize(const int num_slots){
    if( static_cast<int>(data_.size()) == num_slots ){ return; }
    data_.resize(num_slots);
  }

  void resize(const int num_slots, const T& value){
    if( static_cast<int>(data_.size()) == num_slots ){ return; }
    data_.resize(num_slots, value);
  }

  void clear(){
    data_.clear();
  }
  
  template<class U>
  RawVec pow(const U& e) const {
    RawVec out(data_.size());
    std::transform(cbegin(), cend(), out.begin(), [&](const T& b){ return std::pow(b, e); });
    return out;
  }

  std::ostream& print(std::ostream& stream, const size_t num_elem,
                      const bool skip_zero=false, const std::string& prefix_msg="",
                      const size_t n_per_line=65536) const;
  
private:
  std::vector<T> data_;

};

template<class T>
std::ostream& RawVec<T>::print(std::ostream& stream, const size_t num_elem,
                               const bool skip_zero, const std::string& prefix_msg,
                               const size_t n_per_line) const {
  const size_t n = cref().size();
  size_t count = 0;

  auto print_one = [&](const size_t i, const std::string& prefix, const std::string& suffix){
    if( !skip_zero || at(i) != 0.0 ){
      stream << prefix << at(i) << "[" << i << "]" << suffix;
      if( ++count >= n_per_line ){
        stream << std::endl;
        count = 0;
      }
    }
  };

  if( !prefix_msg.empty() ){
    stream << prefix_msg << ": ";
  }
  
  if( num_elem * 2 >= n ){
    print_one(0, "", "");
    for( size_t i = 1; i < n; ++i ){
      print_one(i, ", ", "");
    }
  }else{
    for( size_t i = 0; i < num_elem; ++i ){
      print_one(i, "", ", ");
    }
    stream << "...";
    for( size_t i = n - num_elem; i < n; ++i ){
      print_one(i, ", ", "");
    }
  }
  return stream;
}


}  // namespace he_wrapper


template<class T>
he_wrapper::RawVec<T> operator-(const he_wrapper::RawVec<T>& lhs,
                                const T rhs){
  he_wrapper::RawVec<T> out = lhs;
  out -= rhs;
  return out;
}

template<class T>
he_wrapper::RawVec<T> operator-(const T lhs,
                                const he_wrapper::RawVec<T>& rhs){
  he_wrapper::RawVec<T> out = rhs;
  out -= lhs;
  out *= T(-1);
  return out;
}


template<class T>
he_wrapper::RawVec<T> operator*(const he_wrapper::RawVec<T>& lhs,
                                const T rhs){
  he_wrapper::RawVec<T> out = lhs;
  out *= rhs;
  return out;
}

template<class T>
he_wrapper::RawVec<T> operator*(const T lhs,
                                const he_wrapper::RawVec<T>& rhs){
  he_wrapper::RawVec<T> out = rhs;
  out *= lhs;
  return out;
}


template<class T>
he_wrapper::RawVec<T> operator+(const he_wrapper::RawVec<T>& lhs,
                                const he_wrapper::RawVec<T>& rhs){
  he_wrapper::RawVec<T> out = lhs;
  out += rhs;
  return out;
}

template<class T>
he_wrapper::RawVec<T> operator-(const he_wrapper::RawVec<T>& lhs,
                                const he_wrapper::RawVec<T>& rhs){
  he_wrapper::RawVec<T> out = lhs;
  out -= rhs;
  return out;
}


template<class T>
he_wrapper::RawVec<T> operator*(const he_wrapper::RawVec<T>& lhs,
                                const he_wrapper::RawVec<T>& rhs){
  he_wrapper::RawVec<T> out = lhs;
  out *= rhs;
  return out;
}



template<class T>
std::ostream& operator<<(std::ostream& stream,
                         const he_wrapper::RawVec<T>& in){
  return in.print(stream, 32);
}


