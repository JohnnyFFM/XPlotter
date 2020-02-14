#include "CpuInfo.h"
#include <algorithm>
#include <intrin.h>
#include <limits.h>

using namespace std;

class CPUID {
  uint32_t regs[4];

public:
  explicit CPUID(unsigned funcId, unsigned subFuncId) {
    __cpuidex((int *)regs, (int)funcId, (int)subFuncId);
  }

  const uint32_t &EAX() const { return regs[0]; }
  const uint32_t &EBX() const { return regs[1]; }
  const uint32_t &ECX() const { return regs[2]; }
  const uint32_t &EDX() const { return regs[3]; }
};

CpuInfo::CpuInfo() {
  CPUID cpuID0(0, 0);
  uint32_t HFS = cpuID0.EAX();
  _vendor += string((const char *)&cpuID0.EBX(), 4);
  _vendor += string((const char *)&cpuID0.EDX(), 4);
  _vendor += string((const char *)&cpuID0.ECX(), 4);
  CPUID cpuID1(1, 0);
  _hasSSE = cpuID1.EDX() & SSE_POS;
  _hasSSE2 = cpuID1.EDX() & SSE2_POS;
  _hasSSE3 = cpuID1.ECX() & SSE3_POS;
  _hasSSE41 = cpuID1.ECX() & SSE41_POS;
  _hasSSE42 = cpuID1.ECX() & SSE41_POS;
  _hasAVX = cpuID1.ECX() & AVX_POS;
  CPUID cpuID7(7, 0);
  _hasAVX2 = cpuID7.EBX() & AVX2_POS;

  string upVId = _vendor;
  for_each(upVId.begin(), upVId.end(), [](char &in) { in = ::toupper(in); });

  // Get processor brand string
  // This seems to be working for both Intel & AMD vendors
  for (int i = 0x80000002; i < 0x80000005; ++i) {
    CPUID cpuID(i, 0);
    _model += string((const char *)&cpuID.EAX(), 4);
    _model += string((const char *)&cpuID.EBX(), 4);
    _model += string((const char *)&cpuID.ECX(), 4);
    _model += string((const char *)&cpuID.EDX(), 4);
  }
}