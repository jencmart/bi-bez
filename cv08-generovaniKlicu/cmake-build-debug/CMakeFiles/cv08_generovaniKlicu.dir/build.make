# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/jetbrainsToolbox/apps/CLion/ch-0/181.4445.84/bin/cmake/bin/cmake

# The command to remove a file.
RM = /opt/jetbrainsToolbox/apps/CLion/ch-0/181.4445.84/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv08-generovaniKlicu

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv08-generovaniKlicu/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/cv08_generovaniKlicu.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/cv08_generovaniKlicu.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/cv08_generovaniKlicu.dir/flags.make

CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.o: CMakeFiles/cv08_generovaniKlicu.dir/flags.make
CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jencmart/Dropbox/development/fitcvut/bi-bez/cv08-generovaniKlicu/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.o -c /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv08-generovaniKlicu/main.cpp

CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv08-generovaniKlicu/main.cpp > CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.i

CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv08-generovaniKlicu/main.cpp -o CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.s

CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.o.requires:

.PHONY : CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.o.requires

CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.o.provides: CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.o.requires
	$(MAKE) -f CMakeFiles/cv08_generovaniKlicu.dir/build.make CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.o.provides.build
.PHONY : CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.o.provides

CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.o.provides.build: CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.o


# Object files for target cv08_generovaniKlicu
cv08_generovaniKlicu_OBJECTS = \
"CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.o"

# External object files for target cv08_generovaniKlicu
cv08_generovaniKlicu_EXTERNAL_OBJECTS =

cv08_generovaniKlicu: CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.o
cv08_generovaniKlicu: CMakeFiles/cv08_generovaniKlicu.dir/build.make
cv08_generovaniKlicu: libLibsModule.a
cv08_generovaniKlicu: CMakeFiles/cv08_generovaniKlicu.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/jencmart/Dropbox/development/fitcvut/bi-bez/cv08-generovaniKlicu/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable cv08_generovaniKlicu"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/cv08_generovaniKlicu.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/cv08_generovaniKlicu.dir/build: cv08_generovaniKlicu

.PHONY : CMakeFiles/cv08_generovaniKlicu.dir/build

CMakeFiles/cv08_generovaniKlicu.dir/requires: CMakeFiles/cv08_generovaniKlicu.dir/main.cpp.o.requires

.PHONY : CMakeFiles/cv08_generovaniKlicu.dir/requires

CMakeFiles/cv08_generovaniKlicu.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/cv08_generovaniKlicu.dir/cmake_clean.cmake
.PHONY : CMakeFiles/cv08_generovaniKlicu.dir/clean

CMakeFiles/cv08_generovaniKlicu.dir/depend:
	cd /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv08-generovaniKlicu/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv08-generovaniKlicu /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv08-generovaniKlicu /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv08-generovaniKlicu/cmake-build-debug /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv08-generovaniKlicu/cmake-build-debug /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv08-generovaniKlicu/cmake-build-debug/CMakeFiles/cv08_generovaniKlicu.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/cv08_generovaniKlicu.dir/depend
