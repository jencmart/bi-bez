# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.9

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
CMAKE_COMMAND = /opt/clion-2017.3.4/bin/cmake/bin/cmake

# The command to remove a file.
RM = /opt/clion-2017.3.4/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv05-hash

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv05-hash/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/cv05_hash.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/cv05_hash.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/cv05_hash.dir/flags.make

CMakeFiles/cv05_hash.dir/main.cpp.o: CMakeFiles/cv05_hash.dir/flags.make
CMakeFiles/cv05_hash.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jencmart/Dropbox/development/fitcvut/bi-bez/cv05-hash/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/cv05_hash.dir/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/cv05_hash.dir/main.cpp.o -c /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv05-hash/main.cpp

CMakeFiles/cv05_hash.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/cv05_hash.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv05-hash/main.cpp > CMakeFiles/cv05_hash.dir/main.cpp.i

CMakeFiles/cv05_hash.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/cv05_hash.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv05-hash/main.cpp -o CMakeFiles/cv05_hash.dir/main.cpp.s

CMakeFiles/cv05_hash.dir/main.cpp.o.requires:

.PHONY : CMakeFiles/cv05_hash.dir/main.cpp.o.requires

CMakeFiles/cv05_hash.dir/main.cpp.o.provides: CMakeFiles/cv05_hash.dir/main.cpp.o.requires
	$(MAKE) -f CMakeFiles/cv05_hash.dir/build.make CMakeFiles/cv05_hash.dir/main.cpp.o.provides.build
.PHONY : CMakeFiles/cv05_hash.dir/main.cpp.o.provides

CMakeFiles/cv05_hash.dir/main.cpp.o.provides.build: CMakeFiles/cv05_hash.dir/main.cpp.o


# Object files for target cv05_hash
cv05_hash_OBJECTS = \
"CMakeFiles/cv05_hash.dir/main.cpp.o"

# External object files for target cv05_hash
cv05_hash_EXTERNAL_OBJECTS =

cv05_hash: CMakeFiles/cv05_hash.dir/main.cpp.o
cv05_hash: CMakeFiles/cv05_hash.dir/build.make
cv05_hash: libLibsModule.a
cv05_hash: CMakeFiles/cv05_hash.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/jencmart/Dropbox/development/fitcvut/bi-bez/cv05-hash/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable cv05_hash"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/cv05_hash.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/cv05_hash.dir/build: cv05_hash

.PHONY : CMakeFiles/cv05_hash.dir/build

CMakeFiles/cv05_hash.dir/requires: CMakeFiles/cv05_hash.dir/main.cpp.o.requires

.PHONY : CMakeFiles/cv05_hash.dir/requires

CMakeFiles/cv05_hash.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/cv05_hash.dir/cmake_clean.cmake
.PHONY : CMakeFiles/cv05_hash.dir/clean

CMakeFiles/cv05_hash.dir/depend:
	cd /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv05-hash/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv05-hash /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv05-hash /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv05-hash/cmake-build-debug /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv05-hash/cmake-build-debug /home/jencmart/Dropbox/development/fitcvut/bi-bez/cv05-hash/cmake-build-debug/CMakeFiles/cv05_hash.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/cv05_hash.dir/depend

