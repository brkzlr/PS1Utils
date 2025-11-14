add_executable(edc_checker main.c)
set_target_properties(edc_checker PROPERTIES
	C_STANDARD 11
	C_STANDARD_REQUIRED ON
	C_EXTENSIONS OFF
	EXPORT_COMPILE_COMMANDS ON
	RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
)
target_compile_options(edc_checker PRIVATE -pedantic-errors)

install(TARGETS edc_checker RUNTIME DESTINATION bin)
