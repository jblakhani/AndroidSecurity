cmake_minimum_required(VERSION 3.22.1)
project(deviceidentityaudit)

add_library(deviceidentityaudit SHARED src/main/java/com/company/security/native-audit.cpp)
set_target_properties(deviceidentityaudit PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
