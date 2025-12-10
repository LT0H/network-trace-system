May 2025 release of PcapPlusPlus (v25.05)
=========================================

PcapPlusPlus web-site:  https://pcapplusplus.github.io/

GitHub page:            https://github.com/seladb/PcapPlusPlus


This package contains:
----------------------

 - PcapPlusPlus compiled libraries for Visual Studio (under `lib\`)
    - Common++.lib
    - Packet++.lib
    - Pcap++.lib
 - PcapPlusPlus header files (under `include\pcapplusplus`)
 - Compiled examples (under `bin\`)
 - Code example with a simple CMake file showing how to build applications with PcapPlusPlus (under `example-app\`)
 - CMake files required to build your application with PcapPlusPlus (under `lib\cmake\pcapplusplus`)


In order to compile your application with these binaries you need to:
---------------------------------------------------------------------

 - Make sure that Microsoft Visual Studio version installed on your machine matches the package (VS 2019 / VS 2022)
 - In addition make sure that the package you downloaded matches the configuration you need: Win32 / x64 and Debug / Release
 - Make sure you have WinPcap or Npcap Developer's pack installed (WinPcap Dev Pack can be downloaded from https://www.winpcap.org/devel.htm, Npcap SDK can be downloaded from https://nmap.org/npcap/#download)
 - If your application uses CMake, you can add `PcapPlusPlus_ROOT=<PACKAGE_DIR>`, `PCAP_ROOT=<WinPcap_OR_Npcap_DIR>` and `Packet_ROOT=<WinPcap_OR_Npcap_DIR>``
   when running CMake. For example: if you downloaded the package for VS 2019, x64 and Release, you need to run the following commands:
   - `cmake -A x64 -G "Visual Studio 16 2019"  -S . -B build -DPcapPlusPlus_ROOT=<PACKAGE_DIR> -DPCAP_ROOT=<WinPcap_OR_Npcap_DIR> -DPacket_ROOT=<WinPcap_OR_Npcap_DIR>`
   - `cmake --build build --config Release`


Running the examples:
---------------------

 - Make sure you have WinPcap, Npcap or Wireshark installed
 - Make sure you have Visual C++ Redistributable for Visual Studio installed
 - If examples still don't run, install Visual C++ Redistributable for Visual Studio 2010 also

Release notes (changes from v24.09)
-----------------------------------

- New protocol support:
  - WireGuard (thanks @nadongjun !)
  - Add gratuitous ARP requests (thanks @Dimi1010 !)
  - GTPv2
  - Cisco HDLC
- Added the option to build only `Common++` and `Packet++` libraries without `Pcap++`, removing the dependency on third-party libraries like libpcap or WinPcap/Npcap (thanks @Dimi1010 !)
- Updated the CMake files to support using `pcapplusplus/` as the include prefix (thanks @clementperon !)
- Added support for DPDK 23.11 and 24.11
- Introduced nanosecond precision for timestamps in TCP reassembly
- Added support for timestamp-related libpcap options (thanks @vcomito-apexai !)
- Added multi-language README support (Traditional Chinese, Korean) (thanks @tigercosmos, @nadongjun !)
- Updated OS/platform support running in CI: Ubuntu ARM64, Alpine 3.20, Fedora 42, FreeBSD 13.4/14.1, newer macOS runners (thanks @clementperon !)
- Migrated Android build to use the new version of ToyVPN
- Introduced a new benchmark system using Google Benchmark (thanks @egecetin !)
- Enhanced Python testing and linting infrastructure with `ruff` (thanks @tigercosmos !)
- Code refactoring:
  - Overhauled the logging infrastructure for better performance and flexibility (thanks @Dimi1010 !)
  - Reformatted `CMakeLists` files using `gersemi` (thanks @egecetin !)
  - Updated the internal implementation of `PcapLiveDevice` to store IP information as `IPAddress` (thanks @Dimi1010 !)
  - Streamlined packet parsing using templated next-layer sub-construction (thanks @Dimi1010 !)
  - Refactored device list classes (`PcapLiveDeviceList`, `DpdkDeviceList`, etc.) to use smart pointers internally for memory management and consolidated common behavior under a base class (thanks @Dimi1010 !)
  - Improved the internal implementation of `MacAddress`, `IPAddress` and `IPNetwork` classes (thanks @Dimi1010 !)
  - Enhanced and modernized the internal implementation of `PfRingDevice` (thanks @Dimi1010 !)
  - Removed usage of VLAs (Variable Length Arrays) for C++ standard compliance (thanks @Dimi1010 !)
  - Numerous C++11 modernization efforts (thanks @Dimi1010, @egecetin, @lumiZGorlic, @kiwixz, @ol-imorozko !)
- Improved documentation using triple-slash Doxygen formatting (thanks @Dimi1010, @tigercosmos !)
- Tons of bug fixes, security fixes and small improvements (thanks @Dimi1010, @clementperon, @rndx21033, @prudens, @Doekin, @egecetin, @ol-imorozko, @1ndahous3, @fxlb, @jj683, @oss-patch, @enomis101, @Shivam7-1, @orgads, @Alexis-Lapierre, @s-genereux, @fasonju !)

Breaking changes
----------------

- `Logger::LogLevel` has been deprecated and moved to `LogLevel`. `LogLevel` is now an `enum class`, so arithmetic operations on it will fail to compile
- The `Logger` copy constructor and copy assignment operator are marked as deleted
- The return type of `Packet::getRawPacketReadOnly()` has been changed from `RawPacket*` to `RawPacket const*`
- SSLv2 support has been removed (it was non-functional in previous versions) (thanks to @droe!)

Deprecation list
----------------

- `PcapLiveDevice::getAddresses()`, which was previously deprecated, has now been removed
- libpcap versions < 0.9 are no longer supported. As a result, the following CMake options have been removed: `PCAPPP_ENABLE_PCAP_IMMEDIATE_MODE` and `PCAPPP_ENABLE_PCAP_SET_DIRECTION`
- The following methods are now deprecated and will be removed in future versions:
  - `Logger::Error`, `Logger::Info`, and `Logger::Debug` are deprecated. Please use `LogLevel::XXX` instead
  - `PcapLiveDeviceList::getPcapLiveDeviceBy***` methods have been deprecated in favor of `PcapLiveDeviceList::getDeviceBy***`
  - `ArpLayer(ArpOpcode opCode, const MacAddress &senderMacAddr, const MacAddress &targetMacAddr, const IPv4Address &senderIpAddr, const IPv4Address &targetIpAddr)` constructor has been deprecated in favor of more explicit overloads

Collaborators
-------------

 - @Dimi1010
 - @tigercosmos
 - @egecetin
 - @clementperon
 - @seladb

Contributors
------------

- @ol-imorozko
- @rndx21033
- @nadongjun
- @lumiZGorlic
- @1ndahous3
- @s-genereux
- @prudens
- @oss-patch
- @kiwixz
- @jj683
- @fxlb
- @enomis101
- @vcomito-apexai
- @Shivam7-1
- @orgads
- @Doekin
- @Alexis-Lapierre
- @droe
- @fasonju

**Full Changelog**: https://github.com/seladb/PcapPlusPlus/compare/v24.09...v25.05
