#include"util/process_monitor.hpp"

#include<sys/types.h>
#include<unistd.h>

#include<fstream>

namespace util{
struct ProcessInfo{
  ProcessInfo() : pid(getpid()){}

  
  pid_t pid;
  
};

ProcessMonitor::ProcessMonitor()
  : info_(std::make_shared<ProcessInfo>()){}

std::ostream& ProcessMonitor::show_vmrss(std::ostream& stream) const {
  const std::string filepath = "/proc/" + std::to_string(info_->pid) + "/status";
  std::ifstream ifs(filepath);

  std::string buf;
  while( std::getline(ifs, buf) ){
    if( buf.substr(0, 6) == "VmRSS:" ){
      stream << buf;
    }
  }

  return stream;
}



}  // namespace util

