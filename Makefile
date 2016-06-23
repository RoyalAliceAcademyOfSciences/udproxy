include $(TOPDIR)/rules.mk
# Name and release number of this package
PKG_NAME:=udproxy
PKG_RELEASE:=1.0.0

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/udproxy
	SECTION:=net
	CATEGORY:=Network
	TITLE:=udproxy -- A simple proxy server for UDP
	DEPENDS:=+libnetfilter-queue +libuv
endef

define Package/udproxy/description
	a simple proxy server for UDP.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/udproxy/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/udproxy $(1)/bin/
endef

$(eval $(call BuildPackage,udproxy))
