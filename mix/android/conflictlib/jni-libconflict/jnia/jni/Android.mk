LOCAL_PATH :=$(call my-dir)

include $(CLEAR_VARS)

include $(CLEAR_VARS) 

LOCAL_C_INCLUDES := -I$(LOCAL_PATH)
LOCAL_C_INCLUDES += -I/usr/include

LOCAL_MODULE := libO_AllA

LOCAL_LDLIBS := -L$(SYSROOT)/usr/lib -ldl
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog

LOCAL_SRC_FILES := func_defa_jni.c
LOCAL_SRC_FILES += func_defa.c
LOCAL_SRC_FILES += FILE_LOG.c


ifeq ($(TARGET_ARCH), arm)
LOCAL_CFLAGS += $(LOCAL_C_INCLUDES) -DPACKED="__attribute__((packed))"
else
LOCAL_CFLAGS += $(LOCAL_C_INCLUDES) -DPACKED=""
endif

include $(BUILD_SHARED_LIBRARY)

