cmake_minimum_required(VERSION 3.15)
project(pcap2para VERSION 1.0 LANGUAGES CXX)

# 启用现代CMake政策
cmake_policy(SET CMP0144 NEW)

# C++20标准配置
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 编译输出目录统一
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# MSVC特定配置
if(MSVC)
    add_compile_options(
        /Zc:__cplusplus
        /permissive-
        /Zc:ternary
        /utf-8
        /W4
        /wd4251
    )
    
    add_definitions(
        -D_CRT_SECURE_NO_WARNINGS 
        -D_SILENCE_CXX20_FORMAT_DEPRECATION_WARNING
        -D_NOMINMAX
        -DWIN32_LEAN_AND_MEAN
        -DUNICODE
        -D_UNICODE
    )
endif()

# ========== 1. Boost库配置（已验证可用） ==========
set(BOOST_ROOT "C:/Boost/boost_1_81_0")
set(Boost_DIR "${BOOST_ROOT}/lib64-msvc-14.3/cmake/Boost-1.81.0")

# 强制检查Boost配置文件是否存在
if(NOT EXISTS "${Boost_DIR}/BoostConfig.cmake")
    message(FATAL_ERROR "❌ 未找到Boost配置文件！\n  预期路径: ${Boost_DIR}/BoostConfig.cmake")
endif()
message(STATUS "🔍 手动指定Boost配置文件路径: ${Boost_DIR}")

# 查找Boost（指定regex组件，强制使用CONFIG模式）
find_package(Boost CONFIG REQUIRED COMPONENTS regex)
if(Boost_FOUND)
    message(STATUS "✅ Boost找到，版本: ${Boost_VERSION}")
    message(STATUS "✅ Boost包含目录: ${Boost_INCLUDE_DIRS}")
    message(STATUS "✅ Boost库目录: ${Boost_LIBRARY_DIRS}")
else()
    message(FATAL_ERROR "❌ Boost库查找失败，请检查Boost_DIR配置")
endif()

# ========== 2. Npcap SDK配置（核心修复：硬编码路径，避免环境变量解析错误） ==========
# 直接使用你提供的Npcap SDK根路径（100%匹配）
set(NPcap_SDK_ROOT "C:/Program Files/Npcap/SDK")

# 强制检查Npcap SDK是否存在
if(NOT EXISTS "${NPcap_SDK_ROOT}/Include/pcap.h")
    message(FATAL_ERROR "❌ 未找到Npcap SDK头文件！\n  预期路径: ${NPcap_SDK_ROOT}/Include/pcap.h\n  请确认Npcap SDK安装路径正确")
endif()
if(NOT EXISTS "${NPcap_SDK_ROOT}/Lib/x64/wpcap.lib")
    message(FATAL_ERROR "❌ 未找到Npcap 64位库文件！\n  预期路径: ${NPcap_SDK_ROOT}/Lib/x64/wpcap.lib")
endif()

# 添加Npcap头文件和库路径
include_directories(${NPcap_SDK_ROOT}/Include)
link_directories(${NPcap_SDK_ROOT}/Lib/x64)  # 直接指向你提供的x64库目录
message(STATUS "✅ Npcap SDK路径: ${NPcap_SDK_ROOT}")
message(STATUS "✅ Npcap 64位库路径: ${NPcap_SDK_ROOT}/Lib/x64")

# ========== 3. PcapPlusPlus库配置 ==========
if(DEFINED ENV{PcapPlusPlus_ROOT})
    set(PcapPlusPlus_ROOT $ENV{PcapPlusPlus_ROOT})
else()
    set(PcapPlusPlus_ROOT "C:/Users/z1395/network_trace_system/pcapplusplus")
endif()

# 查找头文件
find_path(PcapPlusPlus_INCLUDE_DIRS
    NAMES pcapplusplus/PcapFileDevice.h
    PATHS "${PcapPlusPlus_ROOT}/include"
    NO_DEFAULT_PATH
)

# 查找库文件
find_library(PcapPlusPlus_LIB_Pcap NAMES Pcap++.lib
    PATHS "${PcapPlusPlus_ROOT}/lib" NO_DEFAULT_PATH
)
find_library(PcapPlusPlus_LIB_Packet NAMES Packet++.lib
    PATHS "${PcapPlusPlus_ROOT}/lib" NO_DEFAULT_PATH
)
find_library(PcapPlusPlus_LIB_Common NAMES Common++.lib
    PATHS "${PcapPlusPlus_ROOT}/lib" NO_DEFAULT_PATH
)

# 验证PcapPlusPlus配置
if(NOT PcapPlusPlus_INCLUDE_DIRS)
    message(FATAL_ERROR "❌ PcapPlusPlus头文件未找到: ${PcapPlusPlus_ROOT}/include")
endif()
foreach(lib PcapPlusPlus_LIB_Pcap PcapPlusPlus_LIB_Packet PcapPlusPlus_LIB_Common)
    if(NOT ${lib})
        message(FATAL_ERROR "❌ 未找到PcapPlusPlus库: ${lib}")
    endif()
endforeach()

set(PcapPlusPlus_LIBRARIES
    ${PcapPlusPlus_LIB_Pcap}
    ${PcapPlusPlus_LIB_Packet}
    ${PcapPlusPlus_LIB_Common}
)
message(STATUS "✅ PcapPlusPlus头文件路径: ${PcapPlusPlus_INCLUDE_DIRS}")

# ========== 4. 源文件配置 ==========
include_directories(
    ${PcapPlusPlus_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# 递归收集源文件
file(GLOB_RECURSE SOURCES
    "src/*.cpp"
    "src/*.hpp"
    "src/*.h"
)

# 过滤不需要的文件
list(FILTER SOURCES EXCLUDE REGEX ".*test/.*")
list(FILTER SOURCES EXCLUDE REGEX ".*example/.*")

add_executable(pcap2para ${SOURCES})

# ========== 5. 链接依赖库 ==========
target_link_libraries(pcap2para PRIVATE
    Boost::regex
    ${PcapPlusPlus_LIBRARIES}
    wpcap.lib
    Packet.lib
    ws2_32.lib
    iphlpapi.lib
    dbghelp.lib
)

# ========== 6. 运行时依赖复制 ==========
if(WIN32)
    # 复制Boost regex DLL
    find_file(BOOST_REGEX_DLL
        NAMES boost_regex-vc143-mt-x64-1_81.dll
        PATHS ${Boost_LIBRARY_DIRS}
        NO_DEFAULT_PATH
    )
    if(BOOST_REGEX_DLL)
        add_custom_command(TARGET pcap2para POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${BOOST_REGEX_DLL}
                $<TARGET_FILE_DIR:pcap2para>
            COMMENT "✅ 复制Boost regex DLL到输出目录"
        )
    else()
        message(WARNING "⚠️ 未找到Boost regex DLL，运行时需手动复制")
    endif()

    # 复制Npcap DLL
    set(NPcap_DLLS "wpcap.dll" "Packet.dll")
    foreach(dll ${NPcap_DLLS})
        find_file(NPcap_DLL_PATH ${dll}
            PATHS "C:/Windows/System32/Npcap"
            NO_DEFAULT_PATH
        )
        if(NPcap_DLL_PATH)
            add_custom_command(TARGET pcap2para POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${NPcap_DLL_PATH}
                    $<TARGET_FILE_DIR:pcap2para>
                COMMENT "✅ 复制${dll}到输出目录"
            )
        else()
            message(WARNING "⚠️ 未找到${dll}，需手动安装Npcap")
        endif()
    endforeach()
endif()

# 安装配置
install(TARGETS pcap2para
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)