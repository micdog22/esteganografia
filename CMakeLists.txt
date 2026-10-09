cmake_minimum_required(VERSION 3.16)
project(esteganografia VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_library(MATH_LIBRARY m)

add_library(esteg_lib STATIC
  src/aleatorio.c src/analise.c src/bmp.c src/chacha20.c src/esteg.c src/sha256.c)
target_include_directories(esteg_lib PUBLIC include src)
if(MATH_LIBRARY)
  target_link_libraries(esteg_lib PUBLIC ${MATH_LIBRARY})
endif()

add_executable(esteg src/main.c)
target_link_libraries(esteg PRIVATE esteg_lib)

enable_testing()

add_executable(test_esteg tests/test_esteg.c tests/bmp_sintetico.c)
target_include_directories(test_esteg PRIVATE tests)
target_link_libraries(test_esteg PRIVATE esteg_lib)
add_test(NAME unidade COMMAND test_esteg)

add_executable(gerar_bmp tests/gerar_bmp.c tests/bmp_sintetico.c)
target_include_directories(gerar_bmp PRIVATE tests)
if(MATH_LIBRARY)
  target_link_libraries(gerar_bmp PRIVATE ${MATH_LIBRARY})
endif()

add_test(NAME linha_de_comando
  COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli.sh $<TARGET_FILE:esteg> $<TARGET_FILE:gerar_bmp>)
