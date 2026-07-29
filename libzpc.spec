Name:		libzpc
Version:	2.0.1
Release:	%autorelease
Summary:	Open Source library for the IBM Z Protected-key crypto feature

License:	MIT
Url:		https://github.com/opencryptoki/libzpc
Source0:	%{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:	cmake
BuildRequires:	gcc
BuildRequires:	g++
BuildRequires:	make
BuildRequires:	clang-tools-extra
BuildRequires:	json-c-devel
BuildRequires:	openssl-devel >= 3.0.7
BuildRequires:	p11-kit-devel


%description
The IBM Z Protected-key Crypto library %{name} is an open-source project
targeting the 64-bit Linux on IBM Z (s390x) platform. It provides access
to z/Architecture's extensive performance-boosting hardware support and its
protected-key feature which ensures that key material is never present in
main memory at any time.


%ifarch s390x
%package	provider
Summary:	OpenSSL provider module for %{name}

%description	provider
The %{name}-provider package contains a provider module for OpenSSL v3.0 (and
later), interfacing to the protected key feature of z/Architecture.

%package	pkcs11
Summary:	PKCS#11 module for %{name}
Requires:	%{name}-provider

%description	pkcs11
The %{name}-pkcs11 package contains a PKCS#11 module for using protected key
origins.
%endif


%package	tools
Summary:	Key management tool for %{name} keys

%description	tools
The %{name}-tools package contains a key management tool for key origins.
As the protected keys itself are volatile, the tooling can be used to manage
persistent protected key origins, from which protected keys can be (re-)derived.


%prep
%autosetup -p1
%global modulesdir %(pkg-config --variable=modulesdir libcrypto)
%global p11modulesdir %(pkg-config --variable=p11_module_path p11-kit-1)

%build
%cmake
%cmake_build

%install
%cmake_install
%ifarch s390x
install -m644 %_vpath_builddir/hbkzpcprovider.conf \
        -D -t $RPM_BUILD_ROOT%{_sysconfdir}/pki/tls/openssl.d/
%endif

%check
%ctest


%ifarch s390x
%files provider
%doc README.md CHANGES.md
%license LICENSE
%{modulesdir}/zpcprovider.so
%{_mandir}/man5/hbkzpcprovider.conf.5*
%{_mandir}/man7/hbkzpcprovider.7*
%config(noreplace) %{_sysconfdir}/pki/tls/openssl.d/hbkzpcprovider.conf

%files pkcs11
%doc README.md CHANGES.md
%license LICENSE
%{p11modulesdir}/zpcpkcs11.so
%{_mandir}/man5/zpcpkcs11.conf.5*
%{_mandir}/man7/zpcpkcs11.7*
%endif

%files tools
%doc README.md CHANGES.md
%license LICENSE
%{_bindir}/zpckey
%{_mandir}/man1/zpckey.1*


%changelog
%autochangelog
