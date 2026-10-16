{
  stdenv,
  cmake,
  python3,
  gtest,
  zydisSrc,
  zycoreSrc,
  bindingSource,
}:
let
  upstreamTests = stdenv.mkDerivation {
    pname = "stackable-zydis-upstream-tests";
    version = "4.1.1";
    src = zydisSrc;
    nativeBuildInputs = [
      cmake
      python3
    ];
    buildInputs = [ gtest ];
    cmakeFlags = [
      "-DZYAN_ZYCORE_PATH=${zycoreSrc}"
      "-DZYAN_SYSTEM_ZYCORE=OFF"
      "-DZYDIS_BUILD_DOXYGEN=OFF"
      "-DZYCORE_BUILD_TESTS=ON"
    ];
    doCheck = true;
    checkPhase = ''
      runHook preCheck
      cmake --build . --target TestString TestVector TestArgParse -j2
      ctest --output-on-failure --no-tests=error
      runHook postCheck
    '';
    installPhase = ''
      mkdir -p "$out"
      cp Testing/Temporary/LastTest.log "$out/LastTest.log"
    '';
  };
in
stdenv.mkDerivation {
  pname = "stackable-strict-decoder";
  version = "4.1.1";
  src = zydisSrc;
  nativeBuildInputs = [
    cmake
    python3
    upstreamTests
  ];
  cmakeFlags = [
    "-DCMAKE_BUILD_TYPE=Release"
    "-DCMAKE_POSITION_INDEPENDENT_CODE=ON"
    "-DCMAKE_C_VISIBILITY_PRESET=hidden"
    "-DZYAN_ZYCORE_PATH=${zycoreSrc}"
    "-DZYAN_SYSTEM_ZYCORE=OFF"
    "-DZYAN_NO_LIBC=ON"
    "-DZYDIS_BUILD_SHARED_LIB=OFF"
    "-DZYCORE_BUILD_SHARED_LIB=OFF"
    "-DZYDIS_MINIMAL_MODE=OFF"
    "-DZYDIS_FEATURE_ENCODER=OFF"
    "-DZYDIS_FEATURE_FORMATTER=OFF"
    "-DZYDIS_FEATURE_AVX512=ON"
    "-DZYDIS_BUILD_TOOLS=OFF"
    "-DZYDIS_BUILD_EXAMPLES=OFF"
    "-DZYDIS_BUILD_DOXYGEN=OFF"
    "-DZYCORE_BUILD_TESTS=OFF"
    "-DZYCORE_BUILD_EXAMPLES=OFF"
  ];
  postInstall = ''
    mkdir -p "$out/src"
    cp "${bindingSource}" "$out/src/strict_decoder_binding.nim"
    test -f "$out/lib/libZydis.a"
    test -f "$out/include/Zydis/Decoder.h"
    # NO_LIBC uses Zycore headers without linking a second archive. Ship
    # the exact declared header tree for downstream Zydis includes.
    cp -r "${zycoreSrc}/include/Zycore" "$out/include/"
    test -f "$out/include/Zycore/Defines.h"
    mkdir -p "$out/share/licenses/zydis" "$out/share/licenses/zycore"
    cp "$src/LICENSE" "$out/share/licenses/zydis/LICENSE"
    cp "${zycoreSrc}/LICENSE" "$out/share/licenses/zycore/LICENSE"
  '';
  passthru.sourceRevisions = {
    zydis = "a2278f1d254e492f6a6b39f6cb5d1f5d515659dc";
    zycore = "0b2432ced0884fd152b471d97ecf0258ff4d859f";
  };
}
