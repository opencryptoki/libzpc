Name:		libzpc
Version:	1.5.0
Release:	1%{?dist}
Summary:	Open Source library for the IBM Z Protected-key crypto feature

License:	MIT
Url:		https://github.com/opencryptoki/libzpc
Source0:	%{url}/archive/v%{version}/%{name}-%{version}.tar.gz

ExclusiveArch:	s390x
BuildRequires:	cmake
BuildRequires:	gcc
BuildRequires:	g++
BuildRequires:	make
BuildRequires:	json-c-devel

#Additional prerequisites for building the test program: libjson-c devel 
#Additional prereqs for building the html and latex doc: doxygen >= 1.8.17, latex, bibtex

# Be explicit about the soversion in order to avoid unintentional changes.
%global soversion 1

%description
The IBM Z Protected-key Crypto library libzpc is an open-source library
targeting the 64-bit Linux on IBM Z (s390x) platform. It provides interfaces
for cryptographic primitives. The underlying implementations make use of
z/Architecture's extensive performance-boosting hardware support and its
protected-key feature which ensures that key material is never present in
main memory at any time.

%package	devel
Summary:	Development files for %{name}
Requires:	%{name}%{?_isa} = %{version}-%{release}

%description	devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}.


%prep
%autosetup %{name}-%{version}

# The following options can be passed to cmake:
#   -DCMAKE_INSTALL_PREFIX=<path> : 
#        Change the install prefix from `/usr/local/` to `<path>`.
#   -DCMAKE_BUILD_TYPE=<type> : Choose predefined build options. 
#        The choices for `<type>` are `Debug`, `Release`, `RelWithDebInfo`, 
#        and `MinSizeRel`.
#   -DBUILD_SHARED_LIBS=ON : Build a shared object (instead of an archive).
#   -DBUILD_TEST=ON : Build the test program.
#   -DBUILD_DOC=ON : Build the html and latex doc.
%build
%cmake
%cmake_build


%install
%cmake_install


%check
%ctest


%files
%doc README.md CHANGES.md
%license LICENSE
%{_libdir}/%{name}.so.%{soversion}*


%files devel
%{_includedir}/zpc/
%{_libdir}/pkgconfig/%{name}.pc
%{_libdir}/%{name}.so


%changelog
* Thu Feb 05 2026 Holger Dengler <dengler@linux.ibm.com> - 1.5.0
- Support for live guest relocation.

* Mon Dec 15 2025 Holger Dengler <dengler@linux.ibm.com> - 1.4.1
- Bug fixes.

* Thu May 22 2025 Joerg Schmidbauer <jschmidb@de.ibm.com> - 1.4.0
- Support for MSA 10 (XTS-FULL) and MSA 11 (HMAC)
- Bug fixes.

* Tue Mar 25 2025 Joerg Schmidbauer <jschmidb@de.ibm.com> - 1.3.1
- Bug fixes.

* Fri Feb 07 2025 Joerg Schmidbauer <jschmidb@de.ibm.com> - 1.3.0
- Support for UV retrievable secrets.

* Thu Dec 07 2023 Joerg Schmidbauer <jschmidb@de.ibm.com> - 1.2.0
- Support for get/set intermediate iv for CBC and XTS.
- Support for internal iv for GCM.

* Fri Sep 15 2023 Joerg Schmidbauer <jschmidb@de.ibm.com> - 1.1.1
- Exploit PKEY_KBLOB2PROTK2 for AES EP11 version 6 keys.

* Thu Feb 02 2023 Joerg Schmidbauer <jschmidb@de.ibm.com> - 1.1.0
- Support for ECC keys and ECDSA signatures.

* Wed Jun 22 2022 Joerg Schmidbauer <jschmidb@de.ibm.com> - 1.0.1
- Updated spec file for rpm build and changed location
  of pkgconfig file to libdir.

* Mon Feb 21 2022 Joerg Schmidbauer <jschmidb@de.ibm.com> - 1.0.0
- Initial version based on libzpc provided by Patrick Steuer,
  <steuer@linux.vnet.ibm.com>

