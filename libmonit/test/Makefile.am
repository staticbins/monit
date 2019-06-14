AUTOMAKE_OPTIONS = foreign no-dependencies

LDADD = ../libmonit.la
AM_CPPFLAGS = -I../src/ -I../src/util -I../src/io -I../src/exceptions -I../src/statistics -I../src/thread

noinst_PROGRAMS = StrTest \
                  ConvertTest \
                  SystemTest \
                  ListTest \
                  DirTest \
                  DispatcherTest \
                  StringBufferTest \
                  InputStreamTest \
                  OutputStreamTest \
                  FileTest \
                  ExceptionTest \
                  NetTest \
                  TimeTest \
                  CommandTest \
                  SchedulerTest

StrTest_SOURCES = StrTest.c
ConvertTest_SOURCES = ConvertTest.c
CommandTest_SOURCES = CommandTest.c
SystemTest_SOURCES = SystemTest.c
ListTest_SOURCES = ListTest.c
DirTest_SOURCES = DirTest.c
DispatcherTest_SOURCES = DispatcherTest.c
StringBufferTest_SOURCES = StringBufferTest.c
InputStreamTest_SOURCES = InputStreamTest.c
OutputStreamTest_SOURCES = OutputStreamTest.c
FileTest_SOURCES = FileTest.c
ExceptionTest_SOURCES = ExceptionTest.c
NetTest_SOURCES = NetTest.c
TimeTest_SOURCES = TimeTest.c
SchedulerTest_SOURCES = SchedulerTest.c

DISTCLEANFILES = *~ 

verify:
	@/bin/sh ./test.sh

