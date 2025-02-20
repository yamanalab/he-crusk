#pragma once

#include"he_wrapper_tmpl/raw_scalar.hpp"
#include"he_wrapper_tmpl/raw_vec.hpp"

namespace he_wrapper_tmpl{
template<class T>
using RawScalar = he_wrapper::RawScalar<T>;

template<class T>
using RawVec = he_wrapper::RawVec<T>;


template<template<class> class Impl>
class EncodingParams;

template<template<class> class Impl>
class EncodingParamsList;

template<template<class> class Impl>
class KeyManager;

template<template<class> class Impl>
class ScalarPlaintext;

template<template<class> class Impl>
class Plaintext;

template<template<class> class Impl>
class SymCiphertext;

template<template<class> class Impl>
class Ciphertext;

enum class OpType : int {
  npp,
  allocate,
  reallocate,
  deallocate,
  copy,
  encode,
  decode,
  encrypt,
  decrypt,
  add,
  sub,
  mul,
  square,
  relinearize,
  rescale,
  mod_down,
  rotate,
  bootstrap,
  rotate_and_sum,
  invalid,
};

}  // namespace he_wrapper_tmpl

#include"he_wrapper_tmpl/base/operator.hpp"

