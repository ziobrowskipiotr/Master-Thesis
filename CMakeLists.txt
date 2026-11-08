cmake_minimum_required(VERSION 3.20)

# Automatyczny wybór Clang/Clang++ jako domyślnego kompilatora projektu
if(NOT DEFINED ENV{CC} AND NOT DEFINED CMAKE_C_COMPILER)
    find_program(CLANG_C clang)
    if(CLANG_C)
        set(CMAKE_C_COMPILER "${CLANG_C}" CACHE STRING "C compiler" FORCE)
    endif()
endif()
if(NOT DEFINED ENV{CXX} AND NOT DEFINED CMAKE_CXX_COMPILER)
    find_program(CLANG_CXX clang++)
    if(CLANG_CXX)
        set(CMAKE_CXX_COMPILER "${CLANG_CXX}" CACHE STRING "C++ compiler" FORCE)
    endif()
endif()

project(MemorySafetyThesis 
        VERSION 1.0.0 
        DESCRIPTION "Ocena wpływu mechanizmów bezpieczeństwa pamięci na wydajność w ARM64" 
        LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_EXTENSIONS OFF)

if (NOT CMAKE_C_COMPILER_ID MATCHES "Clang" OR NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "Ten projekt wymaga kompilatora LLVM/Clang do poprawnej obsługi mechanizmów bezpieczeństwa pamięci. Przerwanie konfiguracji.")
endif()

add_compile_options(-march=armv8.5-a -O3 -Wall -Wextra -falign-functions=16)
add_link_options(-march=armv8.5-a -fuse-ld=lld)
add_compile_definitions(_GNU_SOURCE _POSIX_C_SOURCE=200809L)
include_directories(${CMAKE_SOURCE_DIR}/common)

# ==============================================================================
# BUFOROWANIE KOMPILACJI (CCACHE) - PRZYSPIESZENIE BUILDÓW
# ==============================================================================
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    message(STATUS "Znaleziono ccache: ${CCACHE_PROGRAM} -> włączono buforowanie kompilacji!")
    set(CMAKE_C_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
endif()

# ==============================================================================
# DEFINICJE FLAG BEZPIECZEŃSTWA (CANONICAL NAMING)
# ==============================================================================
set(FLAG_LTO "-flto=thin -fvisibility=hidden")
set(FLAG_CFI "-flto=thin -fvisibility=hidden -fsanitize=cfi -fsanitize-trap=cfi")
set(FLAG_PAC "-mbranch-protection=pac-ret")
set(FLAG_BTI "-mbranch-protection=bti -Wl,-z,now")
set(FLAG_PAC_BTI "-mbranch-protection=pac-ret+bti -Wl,-z,now")

set(FLAG_ASAN "-fsanitize=address")
# HWASan na Linuksie z jawnym tagowaniem zmiennych globalnych:
set(FLAG_HWASAN "-fsanitize=hwaddress -mllvm -hwasan-globals=1")

# Na Linuksie glibc sprzętowe MTE chroni stos przez memtag-stack oraz stertę przez zintegrowany alokator Scudo:
set(FLAG_MTE_SYNC "-march=armv8.5-a+memtag -fsanitize=memtag-stack -fsanitize-memtag-mode=sync -fsanitize=scudo -DFORCE_MTE_SYNC")
set(FLAG_MTE_ASYNC "-march=armv8.5-a+memtag -fsanitize=memtag-stack -fsanitize-memtag-mode=async -fsanitize=scudo -DFORCE_MTE_ASYNC")

# Alokator Scudo (ochrona sterty z zachowaniem spójności MTE/TBI na ARM64, bez ochrony stosu):
set(FLAG_SCUDO "-march=armv8.5-a+memtag -fsanitize=scudo -DUSE_SCUDO")
set(FLAG_CANARY "-fstack-protector-all")

# Profile synergiczne / łączone:
set(FLAG_CFI_PAC_BTI "-flto=thin -fvisibility=hidden -fsanitize=cfi -fsanitize-trap=cfi -mbranch-protection=pac-ret+bti -Wl,-z,now")
set(FLAG_CFI_PAC_BTI_MTE "-flto=thin -fvisibility=hidden -fsanitize=cfi -fsanitize-trap=cfi -mbranch-protection=pac-ret+bti -Wl,-z,now -march=armv8.5-a+memtag -fsanitize=memtag-stack -fsanitize-memtag-mode=sync -fsanitize=scudo -DFORCE_MTE_SYNC")
set(FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS "-flto=thin -fvisibility=hidden -fsanitize=cfi -fsanitize-trap=cfi -mbranch-protection=pac-ret+bti -Wl,-z,now -march=armv8.5-a+memtag -fsanitize=memtag-stack -fsanitize-memtag-mode=sync -fsanitize=scudo -D_FORTIFY_SOURCE=3 -fsanitize=bounds -fsanitize-trap=bounds -DFORCE_MTE_SYNC")

# ==============================================================================
# POMOCNICZA FUNKCJA TWORZĄCA TARGETY
# ==============================================================================
function(add_security_variant TARGET_NAME SOURCE_FILE BUG_DEFINE SECURITY_FLAGS)
    add_executable(${TARGET_NAME} ${SOURCE_FILE})
    if (NOT "${BUG_DEFINE}" STREQUAL "NONE")
        target_compile_definitions(${TARGET_NAME} PRIVATE ${BUG_DEFINE})
    endif()
    if (NOT "${SECURITY_FLAGS}" STREQUAL "NONE")
        separate_arguments(FLAG_LIST UNIX_COMMAND "${SECURITY_FLAGS}")
        
        set(COMPILE_FLAG_LIST "")
        set(LINK_FLAG_LIST "")
        foreach(f ${FLAG_LIST})
            if (f MATCHES "^-Wl,")
                list(APPEND LINK_FLAG_LIST ${f})
            elseif (f MATCHES "^-D")
                list(APPEND COMPILE_FLAG_LIST ${f})
            else()
                list(APPEND COMPILE_FLAG_LIST ${f})
                # Filtrujemy opcje, ktorych linker Clanga nie przyjmuje na Linuksie (np. -fsanitize=memtag*, -mllvm)
                if (NOT f MATCHES "-fsanitize=memtag" AND NOT f MATCHES "-fsanitize-memtag" AND NOT f MATCHES "-mllvm" AND NOT f MATCHES "-hwasan-globals")
                    list(APPEND LINK_FLAG_LIST ${f})
                endif()
            endif()
        endforeach()
        if (COMPILE_FLAG_LIST)
            target_compile_options(${TARGET_NAME} PRIVATE ${COMPILE_FLAG_LIST})
        endif()
        if (LINK_FLAG_LIST)
            target_link_options(${TARGET_NAME} PRIVATE ${LINK_FLAG_LIST})
        endif()
    endif()
endfunction()

# ==============================================================================
# DISPATCHER (D)
# ==============================================================================
function(add_disp_variant TARGET_NAME BUG_DEFINE SECURITY_FLAGS)
    add_security_variant(${TARGET_NAME} apps/dispatcher/dispatcher.cpp "${BUG_DEFINE}" "${SECURITY_FLAGS}")
endfunction()

# D0: Testy wydajnościowe i poprawności (Baseline / Benign)
add_disp_variant(disp_D0_base NONE "NONE")
add_disp_variant(disp_D0_lto NONE "${FLAG_LTO}")
add_disp_variant(disp_D0_pac NONE "${FLAG_PAC}")
add_disp_variant(disp_D0_bti NONE "${FLAG_BTI}")
add_disp_variant(disp_D0_cfi NONE "${FLAG_CFI}")
add_disp_variant(disp_D0_pac_bti NONE "${FLAG_PAC_BTI}")
add_disp_variant(disp_D0_canary NONE "${FLAG_CANARY}")
add_disp_variant(disp_D0_asan NONE "${FLAG_ASAN}")
add_disp_variant(disp_D0_cfi_pac_bti NONE "${FLAG_CFI_PAC_BTI}")
add_disp_variant(disp_D0_cfi_pac_bti_mte NONE "${FLAG_CFI_PAC_BTI_MTE}")
add_disp_variant(disp_D0_cfi_pac_bti_mte_fortify_bounds NONE "${FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS}")

# D1: Atak na adres powrotu x30 na stosie (Stack Smashing / ROP precursor)
add_disp_variant(disp_D1_base BUG_D1 "NONE")
add_disp_variant(disp_D1_pac BUG_D1 "${FLAG_PAC}")
add_disp_variant(disp_D1_bti BUG_D1 "${FLAG_BTI}")
add_disp_variant(disp_D1_pac_bti BUG_D1 "${FLAG_PAC_BTI}")
add_disp_variant(disp_D1_canary BUG_D1 "${FLAG_CANARY}")
add_disp_variant(disp_D1_asan BUG_D1 "${FLAG_ASAN}")
add_disp_variant(disp_D1_cfi_pac_bti BUG_D1 "${FLAG_CFI_PAC_BTI}")
add_disp_variant(disp_D1_cfi_pac_bti_mte BUG_D1 "${FLAG_CFI_PAC_BTI_MTE}")
add_disp_variant(disp_D1_cfi_pac_bti_mte_fortify_bounds BUG_D1 "${FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS}")

# D2: Atak na pośredni wskaźnik funkcji - niezgodna sygnatura (Forward-Edge CFI)
add_disp_variant(disp_D2_base BUG_D2 "NONE")
add_disp_variant(disp_D2_lto BUG_D2 "${FLAG_LTO}")
add_disp_variant(disp_D2_cfi BUG_D2 "${FLAG_CFI}")
add_disp_variant(disp_D2_bti BUG_D2 "${FLAG_BTI}")
add_disp_variant(disp_D2_pac_bti BUG_D2 "${FLAG_PAC_BTI}")
add_disp_variant(disp_D2_cfi_pac_bti BUG_D2 "${FLAG_CFI_PAC_BTI}")
add_disp_variant(disp_D2_cfi_pac_bti_mte BUG_D2 "${FLAG_CFI_PAC_BTI_MTE}")
add_disp_variant(disp_D2_cfi_pac_bti_mte_fortify_bounds BUG_D2 "${FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS}")

# D2_BYPASS: Atak na wskaźnik funkcji ze ZGODNĄ sygnaturą typu (Granica ochrony CFI)
add_disp_variant(disp_D2_bypass_base BUG_D2_BYPASS "NONE")
add_disp_variant(disp_D2_bypass_lto BUG_D2_BYPASS "${FLAG_LTO}")
add_disp_variant(disp_D2_bypass_cfi BUG_D2_BYPASS "${FLAG_CFI}")

# D3: Atak na wirtualną tablicę metod (Vtable Hijack / Type Confusion)
add_disp_variant(disp_D3_base BUG_D3 "NONE")
add_disp_variant(disp_D3_lto BUG_D3 "${FLAG_LTO}")
add_disp_variant(disp_D3_cfi BUG_D3 "${FLAG_CFI}")
add_disp_variant(disp_D3_cfi_pac_bti BUG_D3 "${FLAG_CFI_PAC_BTI}")
add_disp_variant(disp_D3_cfi_pac_bti_mte BUG_D3 "${FLAG_CFI_PAC_BTI_MTE}")
add_disp_variant(disp_D3_cfi_pac_bti_mte_fortify_bounds BUG_D3 "${FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS}")

# D4: Skok pośredni z pominięciem instrukcji lądowiska BTI (Branch Target Identification)
add_disp_variant(disp_D4_base BUG_D4 "NONE")
add_disp_variant(disp_D4_pac BUG_D4 "${FLAG_PAC}")
add_disp_variant(disp_D4_bti BUG_D4 "${FLAG_BTI}")
add_disp_variant(disp_D4_pac_bti BUG_D4 "${FLAG_PAC_BTI}")
add_disp_variant(disp_D4_cfi BUG_D4 "${FLAG_CFI}")
add_disp_variant(disp_D4_lto BUG_D4 "${FLAG_LTO}")
add_disp_variant(disp_D4_cfi_pac_bti BUG_D4 "${FLAG_CFI_PAC_BTI}")
add_disp_variant(disp_D4_cfi_pac_bti_mte BUG_D4 "${FLAG_CFI_PAC_BTI_MTE}")
add_disp_variant(disp_D4_cfi_pac_bti_mte_fortify_bounds BUG_D4 "${FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS}")

# ==============================================================================
# KEY-VALUE STORE (M)
# ==============================================================================
function(add_kv_variant TARGET_NAME BUG_DEFINE SECURITY_FLAGS)
    add_security_variant(${TARGET_NAME} apps/key_value_store/key_value_store.cpp "${BUG_DEFINE}" "${SECURITY_FLAGS}")
endfunction()

add_kv_variant(kv_M0_base NONE "NONE")
add_kv_variant(kv_M0_asan NONE "${FLAG_ASAN}")
add_kv_variant(kv_M0_hwasan NONE "${FLAG_HWASAN}")
add_kv_variant(kv_M0_mte_sync NONE "${FLAG_MTE_SYNC}")
add_kv_variant(kv_M0_mte_async NONE "${FLAG_MTE_ASYNC}")
add_kv_variant(kv_M0_scudo NONE "${FLAG_SCUDO}")
add_kv_variant(kv_M0_canary NONE "${FLAG_CANARY}")
add_kv_variant(kv_M0_cfi_pac_bti_mte NONE "${FLAG_CFI_PAC_BTI_MTE}")
add_kv_variant(kv_M0_cfi_pac_bti_mte_fortify_bounds NONE "${FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS}")

# M1: Heap Use-After-Free (temporalny błąd sterty)
add_kv_variant(kv_M1_base BUG_M1 "NONE")
add_kv_variant(kv_M1_asan BUG_M1 "${FLAG_ASAN}")
add_kv_variant(kv_M1_hwasan BUG_M1 "${FLAG_HWASAN}")
add_kv_variant(kv_M1_mte_sync BUG_M1 "${FLAG_MTE_SYNC}")
add_kv_variant(kv_M1_mte_async BUG_M1 "${FLAG_MTE_ASYNC}")
add_kv_variant(kv_M1_scudo BUG_M1 "${FLAG_SCUDO}")
add_kv_variant(kv_M1_canary BUG_M1 "${FLAG_CANARY}")
add_kv_variant(kv_M1_cfi_pac_bti_mte BUG_M1 "${FLAG_CFI_PAC_BTI_MTE}")
add_kv_variant(kv_M1_cfi_pac_bti_mte_fortify_bounds BUG_M1 "${FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS}")

# M2: Heap Double-Free (temporalny błąd sterty)
add_kv_variant(kv_M2_base BUG_M2 "NONE")
add_kv_variant(kv_M2_asan BUG_M2 "${FLAG_ASAN}")
add_kv_variant(kv_M2_hwasan BUG_M2 "${FLAG_HWASAN}")
add_kv_variant(kv_M2_scudo BUG_M2 "${FLAG_SCUDO}")
add_kv_variant(kv_M2_mte_sync BUG_M2 "${FLAG_MTE_SYNC}")
add_kv_variant(kv_M2_mte_async BUG_M2 "${FLAG_MTE_ASYNC}")
add_kv_variant(kv_M2_canary BUG_M2 "${FLAG_CANARY}")
add_kv_variant(kv_M2_cfi_pac_bti_mte BUG_M2 "${FLAG_CFI_PAC_BTI_MTE}")
add_kv_variant(kv_M2_cfi_pac_bti_mte_fortify_bounds BUG_M2 "${FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS}")

# M3: Stack Use-After-Scope (temporalny błąd stosu)
add_kv_variant(kv_M3_base BUG_M3 "NONE")
add_kv_variant(kv_M3_asan BUG_M3 "${FLAG_ASAN}")
add_kv_variant(kv_M3_hwasan BUG_M3 "${FLAG_HWASAN}")
add_kv_variant(kv_M3_scudo BUG_M3 "${FLAG_SCUDO}")
add_kv_variant(kv_M3_mte_sync BUG_M3 "${FLAG_MTE_SYNC}")
add_kv_variant(kv_M3_mte_async BUG_M3 "${FLAG_MTE_ASYNC}")
add_kv_variant(kv_M3_canary BUG_M3 "${FLAG_CANARY}")
add_kv_variant(kv_M3_cfi_pac_bti_mte BUG_M3 "${FLAG_CFI_PAC_BTI_MTE}")
add_kv_variant(kv_M3_cfi_pac_bti_mte_fortify_bounds BUG_M3 "${FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS}")

# ==============================================================================
# PARSER REKORDÓW (P)
# ==============================================================================
function(add_parser_variant TARGET_NAME BUG_DEFINE SECURITY_FLAGS)
    add_security_variant(${TARGET_NAME} apps/parser/parser.c "${BUG_DEFINE}" "${SECURITY_FLAGS}")
endfunction()

add_parser_variant(parser_P0_base NONE "NONE")
add_parser_variant(parser_P0_asan NONE "${FLAG_ASAN}")
add_parser_variant(parser_P0_hwasan NONE "${FLAG_HWASAN}")
add_parser_variant(parser_P0_mte_sync NONE "${FLAG_MTE_SYNC}")
add_parser_variant(parser_P0_mte_async NONE "${FLAG_MTE_ASYNC}")
add_parser_variant(parser_P0_canary NONE "${FLAG_CANARY}")
add_parser_variant(parser_P0_scudo NONE "${FLAG_SCUDO}")
add_parser_variant(parser_P0_cfi_pac_bti_mte NONE "${FLAG_CFI_PAC_BTI_MTE}")
add_parser_variant(parser_P0_cfi_pac_bti_mte_fortify_bounds NONE "${FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS}")

# P1: Heap Buffer Overflow
add_parser_variant(parser_P1_base BUG_P1 "NONE")
add_parser_variant(parser_P1_asan BUG_P1 "${FLAG_ASAN}")
add_parser_variant(parser_P1_hwasan BUG_P1 "${FLAG_HWASAN}")
add_parser_variant(parser_P1_mte_sync BUG_P1 "${FLAG_MTE_SYNC}")
add_parser_variant(parser_P1_mte_async BUG_P1 "${FLAG_MTE_ASYNC}")
add_parser_variant(parser_P1_canary BUG_P1 "${FLAG_CANARY}")
add_parser_variant(parser_P1_scudo BUG_P1 "${FLAG_SCUDO}")
add_parser_variant(parser_P1_cfi_pac_bti_mte BUG_P1 "${FLAG_CFI_PAC_BTI_MTE}")
add_parser_variant(parser_P1_cfi_pac_bti_mte_fortify_bounds BUG_P1 "${FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS}")

# P2: Stack Buffer Overflow
add_parser_variant(parser_P2_base BUG_P2 "NONE")
add_parser_variant(parser_P2_asan BUG_P2 "${FLAG_ASAN}")
add_parser_variant(parser_P2_hwasan BUG_P2 "${FLAG_HWASAN}")
add_parser_variant(parser_P2_mte_sync BUG_P2 "${FLAG_MTE_SYNC}")
add_parser_variant(parser_P2_mte_async BUG_P2 "${FLAG_MTE_ASYNC}")
add_parser_variant(parser_P2_canary BUG_P2 "${FLAG_CANARY}")
add_parser_variant(parser_P2_cfi_pac_bti_mte BUG_P2 "${FLAG_CFI_PAC_BTI_MTE}")
add_parser_variant(parser_P2_cfi_pac_bti_mte_fortify_bounds BUG_P2 "${FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS}")

# P3: Global Buffer Overflow
add_parser_variant(parser_P3_base BUG_P3 "NONE")
add_parser_variant(parser_P3_asan BUG_P3 "${FLAG_ASAN}")
add_parser_variant(parser_P3_hwasan BUG_P3 "${FLAG_HWASAN}")
add_parser_variant(parser_P3_mte_sync BUG_P3 "${FLAG_MTE_SYNC}")
add_parser_variant(parser_P3_mte_async BUG_P3 "${FLAG_MTE_ASYNC}")
add_parser_variant(parser_P3_canary BUG_P3 "${FLAG_CANARY}")
add_parser_variant(parser_P3_scudo BUG_P3 "${FLAG_SCUDO}")
add_parser_variant(parser_P3_cfi_pac_bti_mte BUG_P3 "${FLAG_CFI_PAC_BTI_MTE}")
add_parser_variant(parser_P3_cfi_pac_bti_mte_fortify_bounds BUG_P3 "${FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS}")

# P4: Heap Out-of-Bounds Read
add_parser_variant(parser_P4_base BUG_P4 "NONE")
add_parser_variant(parser_P4_asan BUG_P4 "${FLAG_ASAN}")
add_parser_variant(parser_P4_hwasan BUG_P4 "${FLAG_HWASAN}")
add_parser_variant(parser_P4_mte_sync BUG_P4 "${FLAG_MTE_SYNC}")
add_parser_variant(parser_P4_mte_async BUG_P4 "${FLAG_MTE_ASYNC}")
add_parser_variant(parser_P4_canary BUG_P4 "${FLAG_CANARY}")
add_parser_variant(parser_P4_scudo BUG_P4 "${FLAG_SCUDO}")
add_parser_variant(parser_P4_cfi_pac_bti_mte BUG_P4 "${FLAG_CFI_PAC_BTI_MTE}")
add_parser_variant(parser_P4_cfi_pac_bti_mte_fortify_bounds BUG_P4 "${FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS}")

# P5: Sub-granule Overflow (alokacja 8B, nadpisanie 4B wewnątrz kafelka 16B MTE)
add_parser_variant(parser_P5_base BUG_P5 "NONE")
add_parser_variant(parser_P5_asan BUG_P5 "${FLAG_ASAN}")
add_parser_variant(parser_P5_hwasan BUG_P5 "${FLAG_HWASAN}")
add_parser_variant(parser_P5_mte_sync BUG_P5 "${FLAG_MTE_SYNC}")
add_parser_variant(parser_P5_mte_async BUG_P5 "${FLAG_MTE_ASYNC}")
add_parser_variant(parser_P5_canary BUG_P5 "${FLAG_CANARY}")
add_parser_variant(parser_P5_scudo BUG_P5 "${FLAG_SCUDO}")
add_parser_variant(parser_P5_cfi_pac_bti_mte BUG_P5 "${FLAG_CFI_PAC_BTI_MTE}")
add_parser_variant(parser_P5_cfi_pac_bti_mte_fortify_bounds BUG_P5 "${FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS}")

# P6: Stack Data-Oriented Programming (DOP - flaga is_admin na stosie)
add_parser_variant(parser_P6_base BUG_P6 "NONE")
add_parser_variant(parser_P6_asan BUG_P6 "${FLAG_ASAN}")
add_parser_variant(parser_P6_hwasan BUG_P6 "${FLAG_HWASAN}")
add_parser_variant(parser_P6_mte_sync BUG_P6 "${FLAG_MTE_SYNC}")
add_parser_variant(parser_P6_mte_async BUG_P6 "${FLAG_MTE_ASYNC}")
add_parser_variant(parser_P6_canary BUG_P6 "${FLAG_CANARY}")
add_parser_variant(parser_P6_cfi_pac_bti_mte BUG_P6 "${FLAG_CFI_PAC_BTI_MTE}")
add_parser_variant(parser_P6_cfi_pac_bti_mte_fortify_bounds BUG_P6 "${FLAG_CFI_PAC_BTI_MTE_FORTIFY_BOUNDS}")
