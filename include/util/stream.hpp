#pragma once

#include<ostream>
#include<vector>

namespace util{
template<class T>
std::ostream& print_vector(const T& begin, const T& end, std::ostream& stream=std::cout){
  if( begin == end ){ return stream; }
  stream << *begin;
  std::for_each(begin+1, end, [&](const auto& x){ stream << ", " << x; });
  return stream;
}

template<class T>
std::ostream& print_vector(const std::vector<T>& in, std::ostream& stream=std::cout){
  return print_vector(in.cbegin(), in.cend(), stream);
}

}  // namespace util

