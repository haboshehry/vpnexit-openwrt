# OpenWrt package definition.  Build with the OpenWrt SDK:
#
#   make -C /path/to/sdk package/vpnexit/compile V=s
#
# For a quick install on a running router use ./install.sh instead.

include $(TOPDIR)/rules.mk

PKG_NAME:=vpnexit
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=haboshehry

include $(INCLUDE_DIR)/package.mk

define Package/vpnexit
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=IKEv2 exit switcher with LAN sharing
  DEPENDS:=+ucode +ucode-mod-fs +ucode-mod-uci +uclient-fetch +openssl-util +ip-full \
	+strongswan-charon +strongswan-swanctl +strongswan-mod-eap-mschapv2 \
	+strongswan-mod-eap-identity +strongswan-mod-openssl +strongswan-mod-gcm \
	+strongswan-mod-constraints +strongswan-mod-revocation +strongswan-mod-resolve \
	+kmod-ipsec4 +kmod-ipsec6 +kmod-crypto-gcm +kmod-crypto-authenc
  PKGARCH:=all
endef

define Package/vpnexit/description
  Downloads a daily IKEv2 profile feed, lets you pick an exit from a small web
  panel served by uhttpd, and routes all LAN/Wi-Fi traffic through it using
  nftables marks and a dedicated routing table.
endef

define Package/vpnexit/conffiles
/etc/config/vpnexit
endef

define Build/Compile
endef

define Package/vpnexit/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/usr/share/vpnexit $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/www/vpnexit $(1)/www/cgi-bin $(1)/etc/strongswan.d
	$(CP) ./files/. $(1)/
	chmod 0755 $(1)/usr/sbin/vpnexit $(1)/etc/init.d/vpnexit $(1)/www/cgi-bin/vpnexit
endef

define Package/vpnexit/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	/etc/init.d/swanctl enable 2>/dev/null
	/etc/init.d/vpnexit enable 2>/dev/null
	/etc/init.d/vpnexit restart 2>/dev/null
}
exit 0
endef

$(eval $(call BuildPackage,vpnexit))
