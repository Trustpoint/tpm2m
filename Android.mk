LOCAL_PATH := $(call my-dir)

LIB_NAME := tpm2m

############################################################################
# build tpm2m from source
############################################################################
include $(CLEAR_VARS)
LOCAL_MODULE := tpm2mlite-nojarjar
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := src/ca/trustpoint/m2m/M2mCertificateLite.java
LOCAL_NO_STANDARD_LIBRARIES := true
LOCAL_JAVA_LIBRARIES := core-oj core-libart
include $(BUILD_STATIC_JAVA_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := tpm2mlite
LOCAL_MODULE_TAGS := optional
LOCAL_NO_STANDARD_LIBRARIES := true
LOCAL_JAVA_LIBRARIES := core-oj core-libart
LOCAL_STATIC_JAVA_LIBRARIES := tpm2mlite-nojarjar
LOCAL_JARJAR_RULES := $(LOCAL_PATH)/jarjar-rules.txt
include $(BUILD_JAVA_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := tpm2m-nojarjar
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := $(call all-java-files-under, src)
LOCAL_NO_STANDARD_LIBRARIES := true
LOCAL_JAVA_LIBRARIES := core-oj core-libart
LOCAL_STATIC_JAVA_LIBRARIES := bouncycastle-nojarjar
include $(BUILD_STATIC_JAVA_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := tpm2m
LOCAL_MODULE_TAGS := optional
LOCAL_NO_STANDARD_LIBRARIES := true
LOCAL_JAVA_LIBRARIES := core-oj core-libart
LOCAL_STATIC_JAVA_LIBRARIES := tpm2m-nojarjar
LOCAL_JARJAR_RULES := $(LOCAL_PATH)/jarjar-rules.txt
include $(BUILD_JAVA_LIBRARY)
