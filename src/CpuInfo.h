#include <string>

class CpuInfo {
 public:
  explicit CpuInfo();
  std::string vendor() const { return _vendor; }
  std::string model() const { return _model; }
  bool hasSSE() const { return _hasSSE; }
  bool hasSSE2() const { return _hasSSE2; }
  bool hasSSE3() const { return _hasSSE3; }
  bool hasSSE41() const { return _hasSSE41; }
  bool hasSSE42() const { return _hasSSE42; }
  bool hasAVX() const { return _hasAVX; }
  bool hasAVX2() const { return _hasAVX2; }

 private:
  // Bit positions for data extractions
  static const uint32_t SSE_POS = 0x02000000;
  static const uint32_t SSE2_POS = 0x04000000;
  static const uint32_t SSE3_POS = 0x00000001;
  static const uint32_t SSE41_POS = 0x00080000;
  static const uint32_t SSE42_POS = 0x00100000;
  static const uint32_t AVX_POS = 0x10000000;
  static const uint32_t AVX2_POS = 0x00000020;

  static const uint32_t MAX_INTEL_TOP_LVL = 4;

  // Attributes
  std::string _vendor;
  std::string _model;
  bool _hasSSE;
  bool _hasSSE2;
  bool _hasSSE3;
  bool _hasSSE41;
  bool _hasSSE42;
  bool _hasAVX;
  bool _hasAVX2;
};