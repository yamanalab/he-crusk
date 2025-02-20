#pragma once

#include<iostream>
#include<sstream>
#include<string>

namespace util{
/**
 * @note how to use: throw_not_implemented_error(__FILE__, __LINE__, __func__);
 */
inline void throw_not_implemented_error(
    const auto& file, const auto& line, const auto& func
){
  const std::string err_msg = [&](){
    std::ostringstream oss;
    oss << func << "() is not implemented @ " << file << ":" << line;
    return oss.str();
  }();
  std::cerr << err_msg << std::endl;
  throw std::logic_error(err_msg);
}

}  // namespace util

