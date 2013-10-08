#==================================================================================================#
#                                                                                                  #
#  Copyright 2012 MaidSafe.net limited                                                             #
#                                                                                                  #
#  This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,        #
#  version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which    #
#  licence you accepted on initial access to the Software (the "Licences").                        #
#                                                                                                  #
#  By contributing code to the MaidSafe Software, or to this project generally, you agree to be    #
#  bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root        #
#  directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available   #
#  at: http://www.maidsafe.net/licenses                                                            #
#                                                                                                  #
#  Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed    #
#  under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF   #
#  ANY KIND, either express or implied.                                                            #
#                                                                                                  #
#  See the Licences for the specific language governing permissions and limitations relating to    #
#  use of the MaidSafe Software.                                                                   #
#                                                                                                  #
#==================================================================================================#


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

project(lifestuff)

include(../../cmake_modules/standard_setup.cmake)

include_directories(${common_SOURCE_DIR}/include)
include_directories(${passport_SOURCE_DIR}/include)
include_directories(${private_SOURCE_DIR}/include)
include_directories(${rudp_SOURCE_DIR}/include)
include_directories(${routing_SOURCE_DIR}/include)
include_directories(${nfs_SOURCE_DIR}/include)
include_directories(${encrypt_SOURCE_DIR}/include)
include_directories(${drive_SOURCE_DIR}/include)
if(WIN32 OR APPLE)
  include_directories(${DriveThirdPartyIncludes})
endif()


#==================================================================================================#
# Set up all files as GLOBs                                                                        #
#==================================================================================================#
set(LifestuffSourcesDir ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff)
glob_dir(Lifestuff ${LifestuffSourcesDir} LifeStuff)
glob_dir(LifestuffDetail ${LifestuffSourcesDir}/detail "LifeStuff Detail")

# Tests
set(TESTS_MAIN_CC ${LifestuffSourcesDir}/tests/tests_main.cc)
set(USER_STORAGE_TEST_CC ${LifestuffSourcesDir}/tests/user_storage_test.cc)
set(USER_INPUT_TEST_CC ${LifestuffSourcesDir}/tests/user_input_test.cc)
set(TEST_UTILS_CC ${LifestuffSourcesDir}/tests/test_utils.cc)
set(TEST_UTILS_H ${LifestuffSourcesDir}/tests/test_utils.h)
set(TEST_UTILS_FILES ${TEST_UTILS_CC} ${TEST_UTILS_H})

source_group("Tests Source Files" FILES ${TESTS_MAIN_CC}
                                        ${USER_STORAGE_TEST_CC}
                                        ${USER_INPUT_TEST_CC}
                                        ${NETWORK_HELPER_CC}
                                        ${TEST_UTILS_CC})


#==================================================================================================#
# Define MaidSafe libraries and executables                                                        #
#==================================================================================================#
ms_add_static_library(lifestuff_detail ${LifestuffDetailAllFiles})
if(MaidsafeTesting)
  ms_add_executable(TESTlifestuff_user_storage "Tests/LifeStuff" ${USER_STORAGE_TEST_CC} ${TEST_UTILS_FILES} ${TESTS_MAIN_CC})
  ms_add_executable(TESTlifestuff_user_input "Tests/LifeStuff" ${USER_INPUT_TEST_CC} ${TESTS_MAIN_CC})
endif()

target_link_libraries(maidsafe_lifestuff_detail maidsafe_lifestuff_manager maidsafe_drive maidsafe_passport maidsafe_routing ${BoostRegexLibs})
if(MaidsafeTesting)
  target_link_libraries(TESTlifestuff_user_storage maidsafe_lifestuff_detail ${BoostRegexLibs})
  target_link_libraries(TESTlifestuff_user_input maidsafe_lifestuff ${BoostRegexLibs})
endif()

ms_add_static_library(lifestuff ${LifestuffAllFiles})

if(MaidsafeTesting)
  target_link_libraries(TESTlifestuff_user_input maidsafe_lifestuff ${BoostRegexLibs})
endif()

add_library(lifestuff_python_api SHARED ${LifestuffSourcesDir}/python_bindings/lifestuff_python_api.cc)
if(CMAKE_COMPILER_IS_GNUCXX)
  target_link_libraries(lifestuff_python_api maidsafe_lifestuff maidsafe_lifestuff_manager ${BoostPythonLibs} ${PYTHON_LIBRARIES} stdc++ ${JustThread_LIBRARIES})
else()
  target_link_libraries(lifestuff_python_api maidsafe_lifestuff maidsafe_lifestuff_manager ${BoostPythonLibs} ${PYTHON_LIBRARIES})
endif()
if(WIN32)
  set_target_properties(lifestuff_python_api PROPERTIES SUFFIX ".pyd")
endif()
set_target_properties(lifestuff_python_api PROPERTIES PREFIX ""
                                                      DEBUG_POSTFIX ""
                                                      LABELS Lifestuff
                                                      FOLDER "MaidSafe/Python Bindings")

                                                    #add_dependencies(lifestuff_python_api lifestuff_vault lifestuff_mgr pd_key_helper routing_key_helper)
add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:lifestuff_python_api> ${CMAKE_BINARY_DIR})
add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:lifestuff_python_api> ${CMAKE_SOURCE_DIR}/tools)
add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:lifestuff_vault> ${CMAKE_BINARY_DIR})
add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:lifestuff_mgr> ${CMAKE_BINARY_DIR})
#add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:vault_key_helper> ${CMAKE_BINARY_DIR})
#add_custom_command(TARGET lifestuff_python_api POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:routing_key_helper> ${CMAKE_BINARY_DIR})

target_link_libraries(maidsafe_lifestuff maidsafe_private maidsafe_vault maidsafe_lifestuff_detail maidsafe_lifestuff_manager)

include_directories(${PYTHON_INCLUDE_DIRS})
include_directories(${PROJECT_BINARY_DIR})


rename_outdated_built_exes()


#==================================================================================================#
# Export detail                                                                                    #
#==================================================================================================#
set(ExportFile ${CMAKE_BINARY_DIR}/maidsafe_export.cmake)
file(WRITE ${ExportFile} "# Path to MaidSafe super-project root\n")
file(APPEND ${ExportFile} "set(maidsafe_SOURCE_DIR \"${CMAKE_SOURCE_DIR}\")\n\n")
file(APPEND ${ExportFile} "# Add module path to CMAKE_MODULE_PATH\n")
file(APPEND ${ExportFile} "set(CMAKE_MODULE_PATH \"${maidsafe_SOURCE_DIR}/cmake_modules\")\n\n")
file(APPEND ${ExportFile} "# Set version info\n")
file(APPEND ${ExportFile} "set(ApplicationVersionMajor ${ApplicationVersionMajor})\n")
file(APPEND ${ExportFile} "set(ApplicationVersionMinor ${ApplicationVersionMinor})\n")
file(APPEND ${ExportFile} "set(ApplicationVersionPatch ${ApplicationVersionPatch})\n\n")
file(APPEND ${ExportFile} "# Handle inclusion of just::thread\n")
file(APPEND ${ExportFile} "set(USE_JUST_THREADS ${USE_JUST_THREADS})\n")
file(APPEND ${ExportFile} "include(maidsafe_find_just_thread)\n\n")
file(APPEND ${ExportFile} "# Handle libc++ variables\n")
file(APPEND ${ExportFile} "set(HAVE_LIBC++ ${HAVE_LIBC++})\n")
file(APPEND ${ExportFile} "set(HAVE_LIBC++ABI ${HAVE_LIBC++ABI})\n\n")
file(APPEND ${ExportFile} "# Include paths\n")
file(APPEND ${ExportFile} "include_directories(\"${lifestuff_SOURCE_DIR}/include\")\n")
file(APPEND ${ExportFile} "include_directories(\"${vault_SOURCE_DIR}/include\")\n")
file(APPEND ${ExportFile} "include_directories(\"${nfs_SOURCE_DIR}/include\")\n")
file(APPEND ${ExportFile} "include_directories(\"${routing_SOURCE_DIR}/include\")\n")
file(APPEND ${ExportFile} "include_directories(\"${rudp_SOURCE_DIR}/include\")\n")
file(APPEND ${ExportFile} "include_directories(\"${drive_SOURCE_DIR}/include\")\n")
file(APPEND ${ExportFile} "include_directories(\"${encrypt_SOURCE_DIR}/include\")\n")
file(APPEND ${ExportFile} "include_directories(\"${passport_SOURCE_DIR}/include\")\n")
file(APPEND ${ExportFile} "include_directories(\"${private_SOURCE_DIR}/include\")\n")
file(APPEND ${ExportFile} "include_directories(\"${common_SOURCE_DIR}/include\")\n")
file(APPEND ${ExportFile} "if(WIN32 OR APPLE)\n")
file(APPEND ${ExportFile} "  include_directories(\"${DriveThirdPartyIncludes}\")\n")
file(APPEND ${ExportFile} "endif()\n")
file(APPEND ${ExportFile} "include_directories(SYSTEM \"${maidsafe_SOURCE_DIR}/src/third_party_libs\")  # for cryptopp\n")
file(APPEND ${ExportFile} "include_directories(SYSTEM \"${BoostSourceDir}\")\n")
file(APPEND ${ExportFile} "include_directories(SYSTEM \"${CatchSourceDir}\")\n")
file(APPEND ${ExportFile} "include_directories(SYSTEM \"${maidsafe_SOURCE_DIR}/src/third_party_libs/protobuf/src\")\n")
file(APPEND ${ExportFile} "include_directories(SYSTEM \"${maidsafe_SOURCE_DIR}/src/third_party_libs/googlemock/gtest/include\")\n")
file(APPEND ${ExportFile} "include_directories(SYSTEM \"${maidsafe_SOURCE_DIR}/src/third_party_libs/googlemock/include\")\n\n")
file(APPEND ${ExportFile} "include_directories(SYSTEM \"${maidsafe_SOURCE_DIR}/src/third_party_libs/leveldb/include\")\n\n")
file(APPEND ${ExportFile} "# Set postfixes\n")
file(APPEND ${ExportFile} "set(CMAKE_DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX})\n")
file(APPEND ${ExportFile} "set(CMAKE_RELWITHDEBINFO_POSTFIX ${CMAKE_RELWITHDEBINFO_POSTFIX})\n")
file(APPEND ${ExportFile} "set(CMAKE_MINSIZEREL_POSTFIX ${CMAKE_MINSIZEREL_POSTFIX})\n\n")
file(APPEND ${ExportFile} "set(BoostLocaleLibs ${BoostLocaleLibs})\n\n")
export(TARGETS maidsafe_lifestuff
               maidsafe_lifestuff_detail
               maidsafe_lifestuff_manager
               maidsafe_vault
               maidsafe_nfs_core
               maidsafe_nfs_client
               maidsafe_nfs_vault
               maidsafe_routing
               maidsafe_rudp
               maidsafe_drive
               maidsafe_encrypt
               maidsafe_passport
               maidsafe_private
               maidsafe_common
               maidsafe_network_viewer
               leveldb
               cryptopp
               protobuf
               protoc
               gmock
               gtest
               APPEND
               FILE
               ${ExportFile})


#==================================================================================================#
# Set compiler and linker flags                                                                    #
#==================================================================================================#
include(standard_flags)
if(UNIX)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")
elseif(Cbfs_FOUND)
  add_definitions(-DHAVE_CBFS)
endif()


#==================================================================================================#
# Export LifeStuff Dependency paths for UI projects                                                #
#==================================================================================================#
if(WIN32)
  set(WPFExportFile ${CMAKE_BINARY_DIR}/maidsafe_wpf_export.cmake)
  file(WRITE ${WPFExportFile} "set(NativeIncludes ${PROJECT_SOURCE_DIR}/include)\n")
  get_dependencies(maidsafe_lifestuff OptimizedDependencies DebugDependencies OFF)
  get_target_property(ReleaseLocation maidsafe_lifestuff LOCATION_RELEASE)
  get_target_property(DebugLocation maidsafe_lifestuff LOCATION_DEBUG)
  list(INSERT OptimizedDependencies 0 "\"${ReleaseLocation}\"")
  list(INSERT DebugDependencies 0 "\"${DebugLocation}\"")
  if(${TargetArchitecture} STREQUAL "x86_64")
    set(Arch x64)
  elseif(${TargetArchitecture} STREQUAL "i386")
    set(Arch x86)
  else()
    message(FATAL_ERROR "\nUnknown target architecture.  Should be \"x86_64\" or \"i386\" but is \"${TargetArchitecture}\"")
  endif()
  file(APPEND ${WPFExportFile} "set(NativeLibs${Arch}Debug ${DebugDependencies})\n")
  file(APPEND ${WPFExportFile} "set(NativeLibs${Arch}Release ${OptimizedDependencies})")
endif()


#==================================================================================================#
# Tests                                                                                            #
#==================================================================================================#
if(MaidsafeTesting)
  add_style_test()
  add_project_experimental()
  add_dependencies(AllLifestuff lifestuff_python_api)
  test_summary_output()
endif()

# temporarily removing lifestuff targets from "all" target. FIXME BEFORE_RELEASE
set_target_properties(maidsafe_lifestuff AllLifestuff maidsafe_lifestuff_detail lifestuff_python_api ExperLifestuff
                        PROPERTIES EXCLUDE_FROM_ALL ON EXCLUDE_FROM_DEFAULT_BUILD ON)
if(MaidsafeTesting)
  set_target_properties(TESTlifestuff_user_storage TESTlifestuff_user_input
                          PROPERTIES EXCLUDE_FROM_ALL ON EXCLUDE_FROM_DEFAULT_BUILD ON)
endif()
