#include"he_crusk/he_crusk.hpp"

#include"util/timer.hpp"

using Impl = he_wrapper_tmpl::ImplSeal<double>;

template<int degree>
class Executor{
public:
  struct Data{
    Data(const size_t n, const size_t N)
      : vec(n, Impl::RawVec(N)){}
    ~Data() = default;
    Data(const Data&) = delete;
    Data(Data&&) noexcept = default;

    std::vector<Impl::RawVec> vec;
    
  };

  static std::string varname(const int i) noexcept { return "a" + std::to_string(i); }
  

  Executor(std::vector<std::shared_ptr<Impl::Operator>>&& op_list, const size_t n_trial,
           const std::string& mode)
    : op_list(op_list), n_trial(n_trial), mode(mode){}

  
  void encrypt_for_baseline(std::vector<std::vector<Impl::Ciphertext>>& out,
                            const std::vector<Impl::EncodingParams>& ep){
    auto encrypt = [&](const auto& input, const auto& op){
      std::vector<Impl::Ciphertext> encrypted(name2id.size());

      timer.set("encrypt (baseline) (variable)");
      const auto id = name2id.at("x");
      timer.emplace([&](){
        op->encode_and_encrypt(encrypted.at(id), input.vec.at(id), ep.at(id));
      });

      timer.set("encrypt (baseline) (constant)");
      timer.emplace([&](){
        for( const auto& [name, id] : name2id ){
          if( name == "x" ){ continue; }
          op->encode_and_encrypt(encrypted.at(id), input.vec.at(id), ep.at(id));
        }
      });
    
      return encrypted;
    };
    
    std::transform(inputs.cbegin(), inputs.cend(), op_list.cbegin(),
                   std::back_inserter(out), encrypt);
  }
  

  Executor<degree>& run();

  void print_max_diff(const auto& target, const auto& groundtruth,
                      const std::string& name){
    std::cout << "max diff (" << name << "): " << [&](){
      auto& d = (groundtruth - target).ref();
      std::for_each(d.begin(), d.end(), [&](auto& t){ t = std::abs(t); });
      return *std::max_element(d.cbegin(), d.cend());
    }() << std::endl;
  }
  
  auto& print_timer() const {
    auto print = [&](const std::string& name){
      std::cout << name << std::endl;
      const auto& tl = timer.get(name);
      for( size_t i = 0; i < n_trial; ++i ){
        std::cout << i << ": " << tl.at(i).diff().count() << " [us]" << std::endl;
      }
    };

    if( mode == "HE-CRUSK" || mode == "both" ){
      print("encrypt and randomize (variable)");
      print("encrypt and randomize (constant)");
      print("exec (HE-CRUSK)");
      print("decrypt (HE-CRUSK)");
    }
    
    if( mode == "baseline" || mode == "both" ){
      print("encrypt (baseline) (variable)");
      print("encrypt (baseline) (constant)");
      print("exec (baseline)");
      print("decrypt (baseline)");
    }
    
    return *this;
  }



  std::vector<std::shared_ptr<Impl::Operator>> op_list;
  
  size_t n_trial;

  // 暗号文名
  std::unordered_map<std::string, int> name2id = [&](){
    std::unordered_map<std::string, int> out;
    for( size_t i = 0; i < degree+1; ++i ){
      out["a" + std::to_string(i)] = i;
    }
    out["x"] = degree+1;
    return out;
  }();
  
  std::vector<Data> inputs;
  
  std::vector<he_crusk::HeCrusk<he_wrapper_tmpl::ImplSeal>> hcs;

  std::vector<Impl::Ciphertext> results;

  std::vector<std::vector<Impl::Ciphertext>> cts_baseline;
  
  std::vector<Impl::Ciphertext> results_baseline;
  
  util::TimerSet timer;

  std::string mode;
  
private:
  void randomize();
  
  void exec();

  template<class FuncCalcEp, class FuncExecWithHE, class FuncExecWithoutHE>
  void exec_baseline_template(FuncCalcEp&& func_calc_ep,
                              FuncExecWithHE&& func_exec_with_he,
                              FuncExecWithoutHE&& func_exec_without_he);
  
  void exec_baseline(){
    util::throw_not_implemented_error(__FILE__, __LINE__, __func__);
  }

};


template<int degree>
void Executor<degree>::randomize(){
  // 二項係数のメモ化
  // degreeに依存するため，degreeごとに一度のみ生成するようにする．
  static auto get_coeff = [&](const int j, const int i){
    static std::vector<std::vector<double>> c = [](){
      std::cout << "Generate for degree=" << degree << std::endl;
      std::vector<std::vector<double>> c(degree+1);
      for( int j = 1; j <= degree; ++j ){
        const int n = j / 2;
        c.at(j).resize(n + 1, 1.0);
        for( int i = 1; i <= n; ++i ){
          const int k = (i <= (j - 1) / 2 ? i : (j - 1) - i);
          c.at(j).at(i) = c.at(j-1).at(i-1) + c.at(j-1).at(k);
        }
      }
      return c;
    }();

    return (i <= j / 2 ? c.at(j).at(i) : c.at(j).at(j-i));
  };

  
  // 多項式関数の出力はランダム化されていないことを前提とする．
  std::transform(
      inputs.cbegin(), inputs.cend(), op_list.begin(), std::back_inserter(hcs),
      [&](const auto& input, const auto op){
        Impl::EncodingParams ep = op->get_initial_encoding_params();
        he_crusk::HeCrusk<he_wrapper_tmpl::ImplSeal> hc(op);
        
        timer.set("encrypt and randomize (variable)");
        timer.emplace([&](){
          hc.add(he_crusk::RandomizedCiphertext("x", ep, 2, true, true),
                 input.vec.at(name2id.at("x")));
          hc.randomize(hc.get("x"));
        });
    
        timer.set("encrypt and randomize (constant)");
        timer.emplace([&](){
          Impl::Plaintext tmp_pt;
          Impl::Ciphertext tmp_ct;
          std::vector<Impl::Ciphertext> tmp_ask(degree+1);
          Impl::Plaintext inv_msk = hc.get("x").sbk.gen_inverted_mul_sbk(*op);

          for( size_t i = 0; i <= degree; ++i ){
            std::string name = varname(i);
            hc.add(he_crusk::RandomizedCiphertext(name, ep, degree+2-i, false, false),
                   input.vec.at(name2id.at(name)));
          }

          // mul sub-keyの設定
          for( int i = 1; i <= degree; ++i ){
            op->template accumulate<Impl::Operator::OpType::mul>(tmp_pt, inv_msk);
            op->copy(hc.get(varname(i)).sbk.mul_sbk(), tmp_pt);
          }

          // add sub-keyの設定およびランダム化
          const Impl::Ciphertext ask = hc.get("x").sbk.add_sbk();
          for( int i = degree; i >= 0; --i ){
            auto& hcdata = hc.get(varname(i));
            Impl::Ciphertext& target = hcdata.sbk.add_sbk();

            for( int j = i + 1; j <= degree; ++j ){
              op->copy(tmp_ct, ask);
              const auto ep = Impl::EncodingParams(tmp_ct).set_scale(1.0);
              // 前回イテレーション時にかけた二項係数の値の逆元もかけて補正する
              op->mul(tmp_ct, get_coeff(j, i), get_coeff(j, i + 1), ep);
              op->mul(tmp_ask.at(j), tmp_ct);

              op->template accumulate<Impl::Operator::OpType::add>(target, tmp_ask.at(j));
            }
            if( target.ptr() != nullptr ){            
              op->negate(target, target);
            }
        
            hc.randomize(hcdata);
            op->copy(tmp_ask.at(i), hcdata.randomized);
          }
        });
    
        return hc;
      }
  );
}


template<int degree>
void Executor<degree>::exec(){
  timer.set("exec (HE-CRUSK)");

  Impl::Ciphertext tmp;

  for( size_t i = 0; i < n_trial; ++i ){
    auto& hc = hcs.at(i);
    const auto& op = hc.op();
    timer.emplace();
    timer.add();
    op.copy(results.at(i), hc.get(varname(degree)).randomized);
    for( size_t j = degree; j > 0; --j ){
      op.mul(results.at(i), hc.get("x").randomized);
      op.add(results.at(i), hc.get(varname(j-1)).randomized);
    }
    timer.add();
  }

  std::vector<Impl::RawVec> rs(n_trial);
  std::vector<Impl::RawVec> gt(n_trial);
  
  timer.set("decrypt (HE-CRUSK)");
  for( size_t i = 0; i < n_trial; ++i ){
    auto& hc = hcs.at(i);
    auto& op = hc.op();
    timer.emplace();
    timer.add();
    op.decrypt_and_decode(rs.at(i), results.at(i));
    timer.add();

    const auto& input = inputs.at(i);
    gt.at(i) = input.vec.at(name2id.at(varname(degree)));
    for( size_t j = degree; j > 0; --j ){
      gt.at(i) *= input.vec.at(name2id.at("x"));
      gt.at(i) += input.vec.at(name2id.at(varname(j-1)));
    }

    print_max_diff(rs.at(i), gt.at(i), "HE-CRUSK");
  }
  
  return;
}


/**
 * 暗号化（ベースライン）
 */
template<int degree>
template<class FuncCalcEp, class FuncExecWithHE, class FuncExecWithoutHE>
void Executor<degree>::exec_baseline_template(FuncCalcEp&& func_calc_ep,
                                              FuncExecWithHE&& func_exec_with_he,
                                              FuncExecWithoutHE&& func_exec_without_he){
  const size_t n = name2id.size();
  
  std::vector<Impl::EncodingParams> ep(n, op_list.at(0)->get_initial_encoding_params());
  func_calc_ep(
      [&](const std::string& name) -> auto& {
        return ep.at(name2id.at(name));
      },
      [&](const std::string& name) -> auto& {
        return inputs.at(0).vec.at(name2id.at(name));
      },
      op_list.at(0)
  );
  
  std::vector<std::vector<Impl::Ciphertext>> cts_list;
  encrypt_for_baseline(cts_list, ep);

  timer.set("exec (baseline)");
  for( size_t i = 0; i < n_trial; ++i ){
    timer.emplace([&](){
      func_exec_with_he(results_baseline.at(i),
                        [&](const std::string& name){
                          return cts_list.at(i).at(name2id.at(name));
                        },
                        op_list.at(i));
    });
  }

  timer.set("decrypt (baseline)");
  std::vector<Impl::RawVec> rs(n_trial);
  for( size_t i = 0; i < n_trial; ++i ){
    const auto& op = op_list.at(i);
    timer.emplace(
        [&](){ op->decrypt_and_decode(rs.at(i), results_baseline.at(i)); }
    );
  }
  
  std::vector<Impl::RawVec> gt(n_trial);
  for( size_t i = 0; i < n_trial; ++i ){
    func_exec_without_he(gt.at(i),
                         [&](const std::string& name){
                           return inputs.at(i).vec.at(name2id.at(name));
                         });

    print_max_diff(rs.at(i), gt.at(i), "baseline");
  }
}



template<>
void Executor<2>::exec_baseline(){
  auto calc_encoding_params = [&](auto&& ep,
                                  auto&& input,
                                  const auto& op){
    Impl::Ciphertext tmp, tmp2;
    op->encode_and_encrypt(tmp, input("x"), ep("x"));
    ep("x").configure(tmp);
    ep("a1").configure(tmp);
    op->square(tmp);
    op->relinearize(tmp);
    op->rescale(tmp);
    ep("a2").configure(tmp).set_scale(ep("x").scale);
    op->encode_and_encrypt(tmp2, input("a2"), ep("a2"));
    op->mul(tmp, tmp2);
    ep("a0").configure(tmp);
  };
  
  auto exec_with_he = [&](Impl::Ciphertext& out,
                          auto&& cts,
                          const auto& op){
    op->add(out, cts("x"), cts("a1"));
    op->square(out);
    op->relinearize(out);
    op->rescale(out);
    op->mul(out, cts("a2"));
    op->add(out, cts("a0"));
    // 計算量の観点から，relinearizationとrescalingは行わない．
  };

  auto exec_without_he = [&](auto& out, auto&& input){
    out = input("x") + input("a1");
    out *= out;
    out *= input("a2");
    out += input("a0");
  };

  exec_baseline_template(calc_encoding_params,
                         exec_with_he,
                         exec_without_he);
}

template<>
void Executor<3>::exec_baseline(){
  auto calc_encoding_params = [&](auto&& ep,
                                  auto&& input,
                                  const auto& op){
    Impl::Ciphertext tmp, x, a3, a2, x2, a1, a1x, a0;
    op->encode_and_encrypt(x, input("x"), ep("x"));
    ep("x").configure(x);
    ep("a3").configure(x);
    op->encode_and_encrypt(a3, input("a3"), ep("a3"));
    op->mul(tmp, a3, x);
    op->relinearize(tmp);
    op->rescale(tmp);
    ep("a2").configure(tmp);
    
    op->encode_and_encrypt(a2, input("a2"), ep("a2"));
    op->add(tmp, a2);
    
    op->square(x2, x);
    op->relinearize(x2);
    op->rescale(x2);

    op->mul(tmp, x2);

    ep("a1").configure(x2).set_scale(tmp.scale() / ep("x").scale);
    op->encode_and_encrypt(a1, input("a1"), ep("a1"));
    op->mod_down(x, 1);
    op->mul(a1x, a1, x);
    op->add(tmp, a1x);
    op->relinearize(tmp);
    op->rescale(tmp);
    
    ep("a0").configure(tmp);
    op->encode_and_encrypt(a0, input("a0"), ep("a0"));
    op->add(tmp, a0);
  };
  
  auto exec_with_he = [&](Impl::Ciphertext& out,
                          auto&& cts,
                          const auto& op){
    Impl::Ciphertext tmp;
    
    op->mul(out, cts("a3"), cts("x"));
    op->relinearize(out);
    op->rescale(out);
    op->add(out, cts("a2"));

    op->square(tmp, cts("x"));
    op->relinearize(tmp);
    op->rescale(tmp);

    op->mul(out, tmp);

    op->mod_down(tmp, cts("x"), 1);
    op->mul(tmp, cts("a1"));
    op->add(out, tmp);
    op->relinearize(out);
    op->rescale(out);

    op->add(out, cts("a0"));
    // 計算量の観点から，relinearizationとrescalingは行わない
  };

  auto exec_without_he = [&](auto& out, auto&& in){
    out = (in("a3") * in("x") + in("a2")) * (in("x") * in("x")) + in("a1") * in("x") + in("a0");
  };

  exec_baseline_template(calc_encoding_params,
                         exec_with_he,
                         exec_without_he);
}

template<>
void Executor<7>::exec_baseline(){
  auto calc_encoding_params = [&](auto&& ep,
                                  auto&& input,
                                  const auto& op){
    Impl::Ciphertext tmp, tmp2, x, x2, x4, a7, a6, a5, a4, a3, a2, a1, a0, a7x, a3x;
    op->encode_and_encrypt(x, input("x"), ep("x"));
    ep("x").configure(x);
    ep("a7").configure(x);
    op->encode_and_encrypt(a7, input("a7"), ep("a7"));
    op->mul(a7x, x, a7);
    op->relinearize(a7x);
    op->rescale(a7x);

    ep("a6").configure(a7x);
    op->encode_and_encrypt(a6, input("a6"), ep("a6"));
    op->add(a7x, a6);
    
    op->square(x2, x);
    op->relinearize(x2);
    op->rescale(x2);

    op->square(x4, x2);
    op->relinearize(x4);
    op->rescale(x4);

    ep("a5").configure(x2);
    op->encode_and_encrypt(a5, input("a5"), ep("a5"));
    op->add(tmp, x2, a5);

    op->mul(tmp, a7x);
    op->relinearize(tmp);
    op->rescale(tmp);

    ep("a4").configure(tmp);
    op->encode_and_encrypt(a4, input("a4"), ep("a4"));
    op->add(tmp, a4);

    op->mul(tmp, x4);

    
    op->mod_down(x2, 1);
    ep("a1").configure(x2);
    op->encode_and_encrypt(a1, input("a1"), ep("a1"));
    op->add(x2, a1);
    
    op->mod_down(x, 1);
    op->rescale(tmp2, x);
    ep("a3").configure(x).set_scale(tmp.scale() / x2.scale() / tmp2.scale());
    op->encode_and_encrypt(a3, input("a3"), ep("a3"));
    op->mul(a3x, x, a3);
    op->relinearize(a3x);
    op->rescale(a3x);
    ep("a2").configure(a3x);
    op->encode_and_encrypt(a2, input("a2"), ep("a2"));
    op->add(a3x, a2);

    op->mul(a3x, x2);

    op->add(tmp, a3x);
    ep("a0").configure(tmp);
    op->encode_and_encrypt(a0, input("a0"), ep("a0"));
    op->add(tmp, a0);
    
  };
  
  auto exec_with_he = [&](Impl::Ciphertext& out,
                          auto&& cts,
                          const auto& op){
    Impl::Ciphertext x2, x4, a7x, a3x;
    op->mul(a7x, cts("x"), cts("a7"));
    op->relinearize(a7x);
    op->rescale(a7x);

    op->add(a7x, cts("a6"));
    
    op->square(x2, cts("x"));
    op->relinearize(x2);
    op->rescale(x2);

    op->square(x4, x2);
    op->relinearize(x4);
    op->rescale(x4);

    op->add(out, x2, cts("a5"));

    op->mul(out, a7x);
    op->relinearize(out);
    op->rescale(out);

    op->add(out, cts("a4"));

    op->mul(out, x4);

    
    op->mod_down(x2, 1);
    op->add(x2, cts("a1"));
    
    op->mod_down(a3x, cts("x"), 1);
    op->mul(a3x, cts("a3"));
    op->relinearize(a3x);
    op->rescale(a3x);
    op->add(a3x, cts("a2"));

    op->mul(a3x, x2);

    op->add(out, a3x);
    op->add(out, cts("a0"));
  };

  auto exec_without_he = [&](auto& out, auto&& in){
    auto x2 = in("x") * in("x");
    auto x4 = x2 * x2;
    out = ((in("a7") * in("x") + in("a6")) * (x2 + in("a5")) + in("a4")) * x4;
    out += (in("x") + in("a2")) * (x2 + in("a1"));
    out += in("a0");
  };

  exec_baseline_template(calc_encoding_params,
                         exec_with_he,
                         exec_without_he);
}





template<int degree>
Executor<degree>& Executor<degree>::run(){
  inputs.clear();
  hcs.clear();
  timer.clear();

  Impl::EncodingParams ep = op_list.at(0)->get_initial_encoding_params();
  
  // データ生成
  std::mt19937_64 engine(std::random_device{}());
  std::uniform_real_distribution<double> dist(-1.0, 1.0);
  const double abs_threshold = 0.000001;
  auto gen_data = [&](){
    Data d(degree+2, op_list.at(0)->num_slots());
    for( size_t i = 0; i < degree + 2; ++i ){
      std::generate(d.vec.at(i).begin(), d.vec.at(i).end(),
                    [&](){
                      double r = 0.0;
                      while( std::abs(r = dist(engine)) < abs_threshold ){}
                      return r;
                    });
    }
    return d;
  };
  std::generate_n(std::back_inserter(inputs), n_trial, gen_data);

  // ランダム化および実行
  if( mode == "HE-CRUSK" || mode == "both" ){
    results.clear();
    results.resize(n_trial);
    randomize();
    exec();
  }
  
  // 暗号化および実行（ベースライン）
  if( mode == "baseline" || mode == "both" ){
    results_baseline.clear();
    results_baseline.resize(n_trial);
    exec_baseline();
  }

  return *this;
}


int main(int argc, char* argv[]){
  const size_t n_trial = std::stoi(argv[1]);
  const size_t degree = std::stoi(argv[2]);
  const std::string mode = argv[3];

  const size_t poly_modulus_degree = std::stoi(argv[4]);
  const size_t default_scale_bit = std::stoi(argv[5]);
  const double default_scale = std::pow(2.0, default_scale_bit);
  const size_t modulus_bit = std::stoi(argv[6]);
  const int num_moduli = std::stoi(argv[7]);

  const std::vector<int> moduli_bits = [&](){
    std::vector<int> out(num_moduli+1, modulus_bit);
    out.front() = 60;
    out.back() = 60;
    return out;
  }();

  auto gen_op = [&](){
    auto km = std::make_shared<Impl::KeyManager>();
    km->poly_degree(poly_modulus_degree);
    km->modulus_bits_list(moduli_bits);
    km->default_scale(default_scale);
    km->gen_params();
    km->gen_sk();
    km->gen_pk();
    if( mode == "baseline" || mode == "both" ){
      km->gen_rlk();
    }
    
    auto op = std::make_shared<Impl::Operator>(km);
    return op;
  };

  std::vector<std::shared_ptr<Impl::Operator>> op_list;
  std::generate_n(std::back_inserter(op_list), n_trial, gen_op);
  // 全体で共通の鍵を使う場合
  // std::fill_n(std::back_inserter(op_list), n_trial, gen_op);

  switch( degree ){
    case 2:
      Executor<2>(std::move(op_list), n_trial, mode)
        .run()
        .print_timer();
      break;
    case 3:
      {
        Executor<3> e(std::move(op_list), n_trial, mode);
        e.run();
        e.print_timer();
        break;
      }
    case 7:
      {
        Executor<7> e(std::move(op_list), n_trial, mode);
        e.run();
        e.print_timer();
        break;
      }

    default:
      util::throw_not_implemented_error(__FILE__, __LINE__, __func__);
      break;
  }

  
  return 0;
}

