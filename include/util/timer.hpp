#pragma once

#include<chrono>
#include<numeric>
#include<unordered_map>
#include<vector>

namespace util{
template<class Precision>
class TimerTmpl{
public:
  using Clock = std::chrono::high_resolution_clock;
  using TimePoint = Clock::time_point;

  template<class T=Precision>
  auto diff(const size_t s, const size_t e) const {
    return std::chrono::duration_cast<T>(tp_list_.at(e) - tp_list_.at(s));
  }

  template<class T=Precision>
  auto diff() const {
    return diff<T>(0, tp_list_.size()-1);
  }
  
  void add(){
    tp_list_.emplace_back(Clock::now());
  }

  void clear(){
    tp_list_.clear();
  }

private:
  std::vector<TimePoint> tp_list_;
  
  
  
};

template<class Precision>
class TimerSetTmpl{
public:
  struct TimerList{
    const auto& at(const size_t i) const { return list.at(i); }
    
    double get_average() const {
      return std::transform_reduce(
          list.cbegin(), list.cend(), Precision{0},
          [&](const auto& x1, const auto& x2){ return x1 + x2; },
          [&](const auto& x){ return x.diff(); }
      ).count() / list.size();
    }

    double get_average(const int si, const int ei) const {
      return std::transform_reduce(
          list.cbegin(), list.cend(), Precision{0},
          [&](const auto& x1, const auto& x2){ return x1 + x2; },
          [&](const auto& x){ return x.diff(si, ei); }
      ).count() / list.size();
    }
    
    std::vector<TimerTmpl<Precision>> list;
  };


  const auto& name() const noexcept { return name_; }
  const auto& data() const noexcept { return data_; }
  
  void set(const std::string& name){
    if( name2data_.count(name) == 0 ){
      name2data_.emplace(name, data_.size());
      name_.emplace_back(name);
      data_.emplace_back();
    }
    id_ = name2data_.at(name);
  }
  
  void emplace(){
    data_.at(id_).list.emplace_back();
  }

  template<class Func>
  void emplace(Func&& func){
    data_.at(id_).list.emplace_back();
    add();
    func();
    add();
  }

  void resize(const size_t n){
    data_.at(id_).list.resize(n);
  }
  
  void add(){
    data_.at(id_).list.back().add();
  }

  void add(const size_t i){
    data_.at(id_).list.at(i).add();
  }

  void clear(){
    id_ = 0;
    name2data_.clear();
    name_.clear();
    data_.clear();
  }
  
  const auto& get(const std::string& name) const {
    return data_.at(name2data_.at(name));
  }

  template<class F>
  void apply(F&& func){
    const size_t n = name_.size();
    for( size_t i = 0; i < n; ++i ){
      func(name_.at(i), data_.at(i));
    }
  }

  

private:
  /// 現在のターゲット
  size_t id_ = 0;
  
  std::unordered_map<std::string, size_t> name2data_;

  std::vector<std::string> name_;

  std::vector<TimerList> data_;
  


};

using Timer = TimerTmpl<std::chrono::microseconds>;
using TimerSet = TimerSetTmpl<std::chrono::microseconds>;

}  // namespace util

