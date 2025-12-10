cmake_minimum_required(VERSION 3.15)
project(pcap2para VERSION 1.0 LANGUAGES CXX)

# 启用CMP0144政策
cmake_policy(SET CMP0144 NEW)

# C++20标准
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# MSVC编译选项（兼容Windows头文件）
if(MSVC)
    add_compile_options(/Zc:__cplusplus /permissive- /Zc:ternary)
    add_definitions(
        -D_CRT_SECURE_NO_WARNINGS 
        -D_SILENCE_CXX20_FORMAT_DEPRECATION_WARNING
        -D_NOMINMAX
        -DWIN32_LEAN_AND_MEAN
    )
endif()

# ========== 1. 配置Boost库 ==========
set(BOOST_ROOT "C:/Boost/boost_1_81_0")
set(Boost_DIR "C:/Boost/boost_1_81_0/lib64-msvc-14.3/cmake/Boost-1.81.0")
find_package(Boost CONFIG REQUIRED COMPONENTS regex)
if(Boost_FOUND)
    message(STATUS "✅ Boost找到，版本: ${Boost_VERSION}")
    message(STATUS "✅ Boost包含目录: ${Boost_INCLUDE_DIRS}")
endif()

# ========== 2. 配置Npcap SDK（适配正确路径） ==========
# 优先检查64位路径，若不存在则检查32位
if(EXISTS "C:/Program Files/Npcap/SDK")
    set(NPcap_SDK_ROOT "C:/Program Files/Npcap/SDK")
elseif(EXISTS "C:/Program Files (x86)/Npcap/SDK")
    set(NPcap_SDK_ROOT "C:/Program Files (x86)/Npcap/SDK")
else()
    message(FATAL_ERROR "❌ 未找到Npcap SDK！请重新安装Npcap并勾选Install Npcap SDK")
endif()

# 添加Npcap头文件路径
include_directories(${NPcap_SDK_ROOT}/Include)
# 添加Npcap 64位库路径
link_directories(${NPcap_SDK_ROOT}/Lib/x64)
message(STATUS "✅ Npcap SDK路径: ${NPcap_SDK_ROOT}")

# ========== 3. 配置PcapPlusPlus库 ==========
set(PcapPlusPlus_ROOT "C:/Users/z1395/network_trace_system/pcapplusplus")
find_path(PcapPlusPlus_INCLUDE_DIRS 
    NAMES pcapplusplus/PcapFileDevice.h
    PATHS "${PcapPlusPlus_ROOT}/include"
)
find_library(PcapPlusPlus_LIB_Pcap NAMES Pcap++.lib PATHS "${PcapPlusPlus_ROOT}/lib")
find_library(PcapPlusPlus_LIB_Packet NAMES Packet++.lib PATHS "${PcapPlusPlus_ROOT}/lib")
find_library(PcapPlusPlus_LIB_Common NAMES Common++.lib PATHS "${PcapPlusPlus_ROOT}/lib")
set(PcapPlusPlus_LIBRARIES 
    ${PcapPlusPlus_LIB_Pcap} 
    ${PcapPlusPlus_LIB_Packet} 
    ${PcapPlusPlus_LIB_Common}
)

# 检查PcapPlusPlus
if(NOT PcapPlusPlus_INCLUDE_DIRS)
    message(FATAL_ERROR "❌ PcapPlusPlus头文件未找到！路径: ${PcapPlusPlus_ROOT}/include")
endif()
if(NOT PcapPlusPlus_LIB_Pcap)
    message(FATAL_ERROR "❌ Pcap++.lib未找到！路径: ${PcapPlusPlus_ROOT}/lib")
endif()
message(STATUS "✅ PcapPlusPlus头文件路径: ${PcapPlusPlus_INCLUDE_DIRS}")

# ========== 4. 源文件（无Tracy） ==========
include_directories(
    ${PcapPlusPlus_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${Boost_INCLUDE_DIRS}
)
file(GLOB_RECURSE SOURCES 
    "src/*.cpp"           
    "src/*.hpp"           
)
add_executable(pcap2para ${SOURCES})

# ========== 5. 链接依赖库（关键） ==========
target_link_libraries(pcap2para 
    Boost::regex          
    ${PcapPlusPlus_LIBRARIES}  
    # Npcap底层库（解决pcap_*符号未解析）
    wpcap.lib
    Packet.lib
    # Windows系统库
    ws2_32.lib
    iphlpapi.lib
)

# ========== 6. 复制运行时DLL（适配新版Npcap路径+容错） ==========
if(WIN32)
    set_target_properties(pcap2para PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/Debug"
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/Release"
    )

    # 复制Boost DLL
    if(EXISTS "${Boost_LIBRARY_DIRS}/boost_regex-vc143-mt-x64-1_81.dll")
        file(COPY "${Boost_LIBRARY_DIRS}/boost_regex-vc143-mt-x64-1_81.dll" 
             DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/Release")
        message(STATUS "✅ 已复制Boost DLL")
    else()
        message(WARNING "⚠️ 未找到Boost DLL: ${Boost_LIBRARY_DIRS}/boost_regex-vc143-mt-x64-1_81.dll")
    endif()

    # 复制Npcap DLL（新版路径：System32\Npcap）
    set(WPCAP_DLL_PATH "C:/Windows/System32/Npcap/wpcap.dll")
    set(PACKET_DLL_PATH "C:/Windows/System32/Npcap/Packet.dll")
    if(EXISTS ${WPCAP_DLL_PATH})
        file(COPY ${WPCAP_DLL_PATH} DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/Release")
        message(STATUS "✅ 已复制wpcap.dll")
    else()
        message(WARNING "⚠️ 未找到wpcap.dll: ${WPCAP_DLL_PATH}")
    endif()
    if(EXISTS ${PACKET_DLL_PATH})
        file(COPY ${PACKET_DLL_PATH} DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/Release")
        message(STATUS "✅ 已复制Packet.dll")
    else()
        message(WARNING "⚠️ 未找到Packet.dll: ${PACKET_DLL_PATH}")
    endif()
endif()