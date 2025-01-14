#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Environment
MKDIR=mkdir
CP=cp
GREP=grep
NM=nm
CCADMIN=CCadmin
RANLIB=ranlib
CC=gcc
CCC=g++
CXX=g++
FC=gfortran
AS=as

# Macros
CND_PLATFORM=GNU-Linux
CND_DLIB_EXT=so
CND_CONF=VeracodeExportMapInline
CND_DISTDIR=dist
CND_BUILDDIR=build

# Include project Makefile
include Makefile

# Object Directory
OBJECTDIR=${CND_BUILDDIR}/${CND_CONF}/${CND_PLATFORM}

# Object Files
OBJECTFILES= \
	${OBJECTDIR}/sqlite3.o \
	${OBJECTDIR}/tcpclient.o


# C Compiler Flags
CFLAGS=-fpermissive -gdwarf-2 -g3 -O0 -fno-builtin

# CC Compiler Flags
CCFLAGS=-fpermissive -gdwarf-2 -g3 -O0 -fno-builtin
CXXFLAGS=-fpermissive -gdwarf-2 -g3 -O0 -fno-builtin

# Fortran Compiler Flags
FFLAGS=

# Assembler Flags
ASFLAGS=

# Link Libraries and Options
LDLIBSOPTIONS=-Wl,--version-script=<(echo '{global:main;local:*;};')
#LDLIBSOPTIONS=

# Build Targets
.build-conf: ${BUILD_SUBPROJECTS}
	"${MAKE}"  -f nbproject/Makefile-${CND_CONF}.mk ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/tcpclient

${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/tcpclient: ${OBJECTFILES}
	${MKDIR} -p ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}
	${LINK.cc} -o ${CND_DISTDIR}/${CND_CONF}/${CND_PLATFORM}/tcpclient ${OBJECTFILES} ${LDLIBSOPTIONS} -lcrypto -lpthread -ldl -lz -lboost_system -lboost_filesystem -ldl

${OBJECTDIR}/sqlite3.o: sqlite3.c
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.c) -g -w -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/sqlite3.o sqlite3.c

${OBJECTDIR}/tcpclient.o: tcpclient.cpp
	${MKDIR} -p ${OBJECTDIR}
	${RM} "$@.d"
	$(COMPILE.cc) -g -w -std=c++11 -MMD -MP -MF "$@.d" -o ${OBJECTDIR}/tcpclient.o tcpclient.cpp

# Subprojects
.build-subprojects:

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r ${CND_BUILDDIR}/${CND_CONF}

# Subprojects
.clean-subprojects:

# Enable dependency checking
.dep.inc: .depcheck-impl

include .dep.inc
