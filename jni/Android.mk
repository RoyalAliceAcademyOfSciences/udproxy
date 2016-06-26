#LOCAL_PATH is used to locate source files in the development tree.
#the macro my-dir provided by the build system, indicates the path of the current directory
LOCAL_PATH:=$(call my-dir)
 
#####################################################################
#			build libnflink						#
#####################################################################
include $(CLEAR_VARS)
LOCAL_MODULE:=nflink
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libnfnetlink/include
LOCAL_SRC_FILES := libnfnetlink/src/iftable.c \
libnfnetlink/src/rtnl.c \
libnfnetlink/src/libnfnetlink.c
include $(BUILD_STATIC_LIBRARY)
#include $(BUILD_SHARED_LIBRARY)
 
#####################################################################
#			build libnetfilter_queue			#
#####################################################################
include $(CLEAR_VARS)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libnfnetlink/include \
$(LOCAL_PATH)/libnetfilter_queue/include
LOCAL_MODULE:=netfilter_queue
LOCAL_SRC_FILES:=libnetfilter_queue/src/libnetfilter_queue.c
LOCAL_STATIC_LIBRARIES:=libnflink
include $(BUILD_STATIC_LIBRARY)
#include $(BUILD_SHARED_LIBRARY)
 
#####################################################################
#			build libuv							#
#####################################################################
include $(CLEAR_VARS)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libuv/include \
$(LOCAL_PATH)/libuv/src \
$(LOCAL_PATH)/libuv/src/unix
LOCAL_MODULE:=uv

UV_SRC_LIST += $(wildcard $(LOCAL_PATH)/libuv/src/*.c)
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/android-ifaddrs.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/async.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/core.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/dl.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/fs.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/getaddrinfo.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/getnameinfo.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/linux-core.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/linux-inotify.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/linux-syscalls.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/loop-watcher.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/loop.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/pipe.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/poll.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/process.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/proctitle.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/pthread-fixes.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/signal.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/stream.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/tcp.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/thread.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/timer.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/tty.c
UV_SRC_LIST += $(LOCAL_PATH)/libuv/src/unix/udp.c

LOCAL_SRC_FILES:=$(UV_SRC_LIST:$(LOCAL_PATH)/%=%)


include $(BUILD_STATIC_LIBRARY)
#include $(BUILD_SHARED_LIBRARY)
 
#####################################################################
#			build our code						#
#####################################################################
include $(CLEAR_VARS)

# Enable PIE manually. Will get reset on $(CLEAR_VARS). This
# is what enabling PIE translates to behind the scenes.
LOCAL_CFLAGS += -fPIE
LOCAL_LDFLAGS += -fPIE -pie

LOCAL_C_INCLUDES := $(LOCAL_PATH)/libnfnetlink/include \
$(LOCAL_PATH)/libnetfilter_queue/include \
$(LOCAL_PATH)/libuv/include
LOCAL_MODULE:=udproxy
LOCAL_SRC_FILES:=../src/udproxy.c
LOCAL_STATIC_LIBRARIES:=libnetfilter_queue libuv
LOCAL_LDLIBS:=-llog -lm
#include $(BUILD_SHARED_LIBRARY)
include $(BUILD_EXECUTABLE)
