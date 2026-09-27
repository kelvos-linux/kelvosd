cmake_minimum_required(VERSION 3.16)
project(kelvosd NONE)

# BPF compilation
find_program(CLANG_BPF clang REQUIRED)

set(BPF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/ebpf/src/xdp_prog.c)
set(BPF_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/ebpf/src/packet.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ebpf/src/policy.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ebpf/src/flow.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ebpf/src/xdp_engine.c
)
set(BPF_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/ebpf/include/flow.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ebpf/include/kelvosd_types.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ebpf/include/maps.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ebpf/include/packet.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ebpf/include/policy.h
    ${CMAKE_CURRENT_SOURCE_DIR}/ebpf/include/xdp_engine.h
)
set(BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/xdp_prog.o)

add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND ${CLANG_BPF}
            -O2
            -g
            -target bpf
            -D__TARGET_ARCH_x86_64
            -I/usr/include/x86_64-linux-gnu
                -I${CMAKE_CURRENT_SOURCE_DIR}/ebpf/include
            -c ${BPF_SRC}
            -o ${BPF_OBJ}
            DEPENDS ${BPF_SRC} ${BPF_SOURCES} ${BPF_HEADERS}
            COMMENT "Compiling BPF program ebpf/src/xdp_prog.c -> xdp_prog.o"
)

add_custom_target(bpf_prog ALL DEPENDS ${BPF_OBJ})

# Optional: copy config to build dir for easier testing
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/config/kelvos_config.toml
    ${CMAKE_CURRENT_BINARY_DIR}/kelvos_config.toml
    COPYONLY
)