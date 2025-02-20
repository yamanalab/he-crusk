#pragma once

#include<concepts>

namespace util{
template<class Func, class ...Args>
concept MultiForExecutable = std::invocable<Func, Args...>
  && std::conjunction<std::is_integral<Args>...>::value
  && std::conjunction<std::is_same<Args, std::remove_reference_t<Args>>...>::value;


template<class Func, std::integral ...I>
requires MultiForExecutable<Func, I...>
__attribute__((always_inline)) inline void multi_for_impl(Func&& func, I... indices){
  func(indices...);
}

template<std::integral T, std::integral ...Ts, class Func, std::integral ...I>
requires MultiForExecutable<Func, I..., T, Ts...>
__attribute__((always_inline)) inline void multi_for_impl(T size, Ts... sizes, Func&& func, I... indices){
  for( T i = 0; i < size; ++i ){
    multi_for_impl<Ts...>(sizes..., std::forward<Func>(func), indices..., i);
  }
}

template<std::integral ...Ts, class Func>
requires MultiForExecutable<Func, Ts...>
__attribute__((always_inline)) inline void multi_for(Func&& func, const Ts... sizes){
  multi_for_impl<Ts...>(sizes..., std::forward<Func>(func));
}


template<class Func, std::integral T1, std::integral T2, std::integral T3>
__attribute__((always_inline)) inline void multi_for_parallel(
    Func&& func, const int num_threads, const T1 n1, const T2 n2, const T3 n3
){
#pragma omp parallel for collapse(3) if(num_threads>1) num_threads(num_threads)
  for( T1 i1 = 0; i1 < n1; ++i1 ){
    for( T2 i2 = 0; i2 < n2; ++i2 ){
      for( T3 i3 = 0; i3 < n3; ++i3 ){
        func(i1, i2, i3);
      }
    }
  }
}

template<class Func, std::integral T1, std::integral T2,
         std::integral T3, std::integral T4>
__attribute__((always_inline)) inline void multi_for_parallel(
    Func&& func, const int num_threads,
    const T1 n1, const T2 n2, const T3 n3, const T4 n4
){
#pragma omp parallel for collapse(4) if(num_threads>1) num_threads(num_threads)
  for( T1 i1 = 0; i1 < n1; ++i1 ){
    for( T2 i2 = 0; i2 < n2; ++i2 ){
      for( T3 i3 = 0; i3 < n3; ++i3 ){
        for( T4 i4 = 0; i4 < n4; ++i4 ){
          func(i1, i2, i3, i4);
        }
      }
    }
  }
}

template<class Func, std::integral T1, std::integral T2,
         std::integral T3, std::integral T4, std::integral T5>
__attribute__((always_inline)) inline void multi_for_parallel(
    Func&& func, const int num_threads,
    const T1 n1, const T2 n2, const T3 n3, const T4 n4, const T5 n5
){
#pragma omp parallel for collapse(5) if(num_threads>1) num_threads(num_threads)
  for( T1 i1 = 0; i1 < n1; ++i1 ){
    for( T2 i2 = 0; i2 < n2; ++i2 ){
      for( T3 i3 = 0; i3 < n3; ++i3 ){
        for( T4 i4 = 0; i4 < n4; ++i4 ){
          for( T4 i5 = 0; i5 < n5; ++i5 ){
            func(i1, i2, i3, i4, i5);
          }
        }
      }
    }
  }
}


template<class Func, std::integral ...I>
requires MultiForExecutable<Func, I...>
__attribute__((always_inline)) inline void multi_for_with_step_impl(Func&& func, I... indices){
  func(indices...);
}

template<std::integral Sz, std::integral St, std::integral ...Ts, class Func, std::integral ...I>
__attribute__((always_inline)) inline void multi_for_with_step_impl(
    Sz size, St step, Ts... sizes_or_steps, Func&& func, I... indices
){
  for( Sz i = 0; i < size; i+=step ){
    multi_for_with_step_impl<Ts...>(sizes_or_steps..., std::forward<Func>(func), indices..., i);
  }
}

template<std::integral ...Ts, class Func>
__attribute__((always_inline)) inline void multi_for_with_step(Func&& func, const Ts... sizes_or_steps){
  multi_for_with_step_impl<Ts...>(sizes_or_steps..., std::forward<Func>(func));
}



}  // namespace util
