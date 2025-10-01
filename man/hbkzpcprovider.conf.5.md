% HBKZPCPROVIDER.CNF(5) LIBZPC v2
%
% 2026

# NAME

hbkzpcprovider.conf - Configuration syntax for the `hbkzpc provider`

# DESCRIPTION

This page documents the syntax of the OpenSSL configuration file for the `hbkzpc
provider`. It is a sub-set of the OpenSSL configuration file format, described
in config(5SSL).

# CONFIGURATION

## OpenSSL Configuration

The `hbkzpc provider` can be configured application-specific or system-wide. In
both cases, the configuration file needs to define and reference a section for
the `hbkzpc provider`, following the OpenSSL configuration syntax
(config(5SSL)).

The provider section for the `hbkzpc provider` specifies the shared library of
the provider (mandatory) and an activation flag (optional).

Since OpenSSL configuration supports drop-ins (keyword `.inlcude`), the
configuration for the `hbkzpc provider` can also be placed in a separate
configuration file.

## Provider Section

A provider section in the OpenSSL configuration defines generic parameters, as
well as provider-specific parameters. Each provider section must be referenced
in the global providers sections (*provider_sect*) of the OpenSSL configuration
file. The `hbkzpc provider` supports no provider-specific parameters, but the
provider section for the `hbkzpc provider` must specify at least the generic
provider section parameter *module*. For more details about the generic provider
parameters, see config(5SSL).

module (mandatory)
:    This parameter takes a path to the provider shared object file. For the
     `hbkzpc provider`, use the absolute path to the installation location of
     `zpcprovider.so` or the relative path to the OpenSSL modules directory.

activate (optional)
:    If present and set to `1`, then the associated provider is
     activated. Conversely, setting this value to `0` or not specifying the
     parameter at all prevents the provider from being activated (default:
     `0`).

The *identity* parameter may be used in the provider section, but it has no
impact to the registration of the `hbkzpc provider`. It will always register
itself with "provider=hbkzpc". Multiple instances of this provider may work but
are not supported.

# EXAMPLES

The following drop-in example specifies the `hbkzpc provider` module and
activates it.

    [provider_sect]
    hbkzpc = hbkzpc_sect

    [hbkzpc_sect]
    module = zpcprovider.so
    activate = 1


The drop-in file needs to be included in the main OpenSSL configuration, either
by specifying the drop-in file or the drop-in directory (for example
`/etc/pki/tls/openssl.d/` on Fedora).

    .include /path/to/drop-in-directory

The following configuration example covers a complete minimal OpenSSL
configuration. It can be used for example as a temporary replacement for the
system-wide OpenSSL configuration.

    HOME = .

    openssl_conf = openssl_init

    [openssl_init]
    providers = provider_sect
    alg_section = evp_properties

    [provider_sect]
    default = default_sect
    base = base_sect
    hbkzpc = hbkzpc_sect

    [evp_properties]

    [base_sect]
    activate = 1

    [default_sect]
    activate = 1

    [hbkzpc_sect]
    module = /path/to/zpcprovider.so
    activate = 1

To use this configuration example for an application, store it to a file
(e.g. my-openssl.conf) and reference this file in the environment variable
`OPENSSL_CONF`. The following command lists all configured providers: base,
default and hbkzpc.

    $ env OPENSSL_CONF=my-openssl.conf openssl list -providers
    Providers:
      base
        name: OpenSSL Base Provider
        version: 4.0.0
        status: active
      default
        name: OpenSSL Default Provider
        version: 4.0.0
        status: active
      hbkzpc
        name: hbkzpc
        version: 2.0.0
        status: active

# SEE ALSO

hbkzpcprovider(7), config(5SSL).
