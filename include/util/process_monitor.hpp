#pragma once

#include<iostream>
#include<memory>

namespace util{
struct ProcessInfo;

class ProcessMonitor{
public:
  ProcessMonitor();
  ~ProcessMonitor() = default;
  ProcessMonitor(const ProcessMonitor&) = delete;
  ProcessMonitor(ProcessMonitor&&) = default;

  std::ostream& show_vmrss(std::ostream& stream) const;
  
private:
  std::shared_ptr<ProcessInfo> info_;

};


}  // namespace util

