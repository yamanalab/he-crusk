#pragma once

#include<ranges>
#include<sstream>
#include<string>
#include<string_view>
#include<vector>

namespace util{
inline std::vector<int> parse_int_list(const std::string& s){
  std::vector<int> out;
  std::istringstream iss(s);

  for( std::string buf; std::getline(iss, buf, ','); ){
    std::vector<int> t;
    std::istringstream iss2(buf);
    for( std::string buf2; std::getline(iss2, buf2, 'x'); ){
      t.emplace_back(std::stoi(buf2));
    }
    switch( t.size() ){
      case 1:
        out.emplace_back(std::stoi(buf));
        break;
      case 2:
        std::fill_n(std::back_inserter(out), t.at(1), t.at(0));
        break;
      default:
        throw std::invalid_argument("Invalid input: " + buf);
    }
  }
  
  return out;
}

template<class T>
T cast(const std::string& s){ return s; }

template<>
inline bool cast<bool>(const std::string& in){
  if( in == "0" ){ return false; }
  std::string lc = in;
  std::transform(in.cbegin(), in.cend(), lc.begin(),
                 [&](const auto c){ return std::tolower(c); });
  if( lc == "false" ){ return false; }
  return true;
}

template<>
inline int cast<int>(const std::string& in){ return std::stoi(in); }

template<>
inline uint32_t cast<uint32_t>(const std::string& in){ return static_cast<uint32_t>(std::stoul(in)); }

template<>
inline double cast<double>(const std::string& in){ return std::stod(in); }

/// inをdlmtでmax_split回（0なら制限なし）だけ先頭から分割する
template<class T=std::string>
std::vector<T> parse_list(const std::string& in,
                          const char dlmt=',',
                          const size_t max_split=0){
  std::vector<T> out, tmp;
  
  auto splitstr = [dlmt](){
    return std::views::split(std::views::single(dlmt))
      | std::views::transform([](auto v){
        auto cv = v | std::views::common;
        return std::string{cv.begin(), cv.end()};
      });
  };

  for( const auto& elem : std::string_view(in) | splitstr() ){
    tmp.emplace_back(cast<T>(elem));
  }

  if( max_split == 0 ){
    return tmp;
  }

  const size_t n = tmp.size();
  
  for( size_t i = 0; i <= max_split; ++i ){
    if( i >= n ){
      return out;
    }
    out.emplace_back(std::move(tmp.at(i)));
  }
  
  for( size_t i = max_split+1; i < n; ++i ){
    out.back() += dlmt;
    out.back() += tmp.at(i);
  }
  
  return out;
}

}  // namespace util

