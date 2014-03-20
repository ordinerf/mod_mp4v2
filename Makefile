#LOCAL_CFLAGS=-I./mp4v2-2.0.0/include -I.
# For Ubuntu or newer gcc
LOCAL_CFLAGS=-I./mp4v2-2.0.0/include -I. -Wno-error=unused-but-set-variable
# For Mac
# LOCAL_CFLAGS=-I./mp4v2-2.0.0/include -I.
LOCAL_LDFLAGS=-static ./mp4v2-2.0.0/.libs/libmp4v2.a

BASE=../../../..
include $(BASE)/build/modmake.rules
