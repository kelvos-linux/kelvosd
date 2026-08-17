cmake_minimum_required(VERSION 3.16)
project(kelvosd C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find libbpf and jansson via pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)
pkg_check_modules(JANSSON REQUIRED IMPORTED_TARGET jansson)

# Loader executable
add_executable(loader src/loader.c src/config.c)

target_include_directories(loader PRIVATE
    ${LIBBPF_INCLUDE_DIRS}
    ${JANSSON_INCLUDE_DIRS}
)

target_link_libraries(loader
    ${LIBBPF_LIBRARIES}
    ${JANSSON_LIBRARIES}
)

# BPF compilation
find_program(CLANG_BPF clang REQUIRED)

set(BPF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/bpf/xdp_prog.c)
set(BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/xdp_prog.o)

add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND ${CLANG_BPF} -O2 -g -target bpf -D__TARGET_ARCH_x86_64 -c ${BPF_SRC} -o ${BPF_OBJ}
    DEPENDS ${BPF_SRC}
    COMMENT "Compiling BPF program xdp_prog.c -> xdp_prog.o"
)

add_custom_target(bpf_prog ALL DEPENDS ${BPF_OBJ})
add_dependencies(loader bpf_prog)

# Optional: copy config to build dir for easier testing
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/config/kelvos_config.toml
    ${CMAKE_CURRENT_BINARY_DIR}/kelvos_config.toml
    COPYONLY
)