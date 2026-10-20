# SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
# SPDX-License-Identifier: GPL-3.0-only
#
# One source package, six binaries, the same split as debian/control:
# ghostd (host), ghostauth (PAM helper), veild (Veil broker), spectre
# (client), libgdp-devel and pyrowave-libs. Everything is built and
# installed once by the CMake project; the files lists below pick out
# each package's share.
#
# Build with `make rpm` at the repo root, which makes the source tarball
# from the working tree and passes the version from CMakeLists.txt. By
# hand: rpmbuild -bb --define "ghost_version X.Y.Z" packaging/rpm/ghost.spec
#
# The build needs the network: cargo fetches its crates, and PyroWave is
# cloned from GitHub (packaging/build-pyrowave.sh). Under mock that is
# --enable-network. x264 and the FFmpeg this links come from RPM Fusion
# (free), on the build machine and on the machines the packages go to.

Name:           ghost
Version:        %{ghost_version}
Release:        1%{?dist}
Summary:        Remote desktop sessions over the Ghost Display Protocol
# libgdp (MIT) is linked statically into every binary, as are the Rust
# crates in host/Cargo.lock under their own permissive licences.
License:        GPL-3.0-only AND MIT
URL:            https://github.com/saiko/ghost
Source0:        %{name}-%{version}.tar.gz

# libgdp ships as a static library, which LTO objects would tie to this
# exact compiler; and the link step needs more memory with it than a small
# builder has.
%global _lto_cflags %{nil}

BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  cmake >= 3.20
BuildRequires:  ninja-build
BuildRequires:  pkgconf-pkg-config
BuildRequires:  git-core
BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  systemd-rpm-macros
BuildRequires:  firewalld-filesystem
BuildRequires:  desktop-file-utils
BuildRequires:  protobuf-compiler
BuildRequires:  protobuf-devel
BuildRequires:  openssl
BuildRequires:  openssl-devel >= 3.5
BuildRequires:  ngtcp2-devel
BuildRequires:  ngtcp2-crypto-ossl-devel
BuildRequires:  wayland-protocols-devel
BuildRequires:  wayland-devel
BuildRequires:  libxkbcommon-devel
BuildRequires:  libdrm-devel
BuildRequires:  libva-devel
BuildRequires:  mesa-libgbm-devel
BuildRequires:  libglvnd-devel
BuildRequires:  x264-devel
BuildRequires:  libzstd-devel
BuildRequires:  tomlplusplus-devel
BuildRequires:  pipewire-devel
BuildRequires:  opus-devel
BuildRequires:  libei-devel
BuildRequires:  fuse3-devel
BuildRequires:  systemd-devel
BuildRequires:  SDL3-devel
BuildRequires:  ffmpeg-devel
BuildRequires:  vulkan-loader-devel
BuildRequires:  vulkan-headers
BuildRequires:  glslang
BuildRequires:  qt6-qtbase-devel
BuildRequires:  pam-devel
BuildRequires:  pcsc-lite-devel

%description
Ghost is a remote desktop for Linux hosts: ghostd logs clients in and
starts a graphical session for each, wraith captures and encodes it, and
spectre is the client. They speak GDP, the Ghost Display Protocol, over
QUIC.

%package -n ghostd
Summary:        Ghost host: remote desktop sessions over GDP
Requires:       ghostauth%{?_isa} = %{version}-%{release}
Requires:       openssl
Requires:       hostname
Requires:       firewalld-filesystem
Requires(post): policycoreutils
%{?systemd_requires}
Recommends:     foot
Recommends:     fuse3
Recommends:     labwc
Recommends:     mesa-dri-drivers
Recommends:     pcsc-lite
Recommends:     pipewire
Recommends:     xorg-x11-server-Xwayland

%description -n ghostd
ghostd authenticates GDP clients against PAM (through ghostauth) and
starts a graphical session for each login, hosted by wraith: capture,
encode and the GDP transport. Sessions run on a real compositor (labwc,
KWin, GNOME Shell or others, per the session profiles in
/usr/share/ghost/sessions.d).

Install this on the machine whose desktop you want to reach. The Veil
broker (package veild) is separate and optional.

%package -n ghostauth
Summary:        Ghost PAM helper
Requires:       openssl
Requires(post): policycoreutils-python-utils
Requires(postun): policycoreutils-python-utils
%{?systemd_requires}

%description -n ghostauth
ghostauth runs one PAM authentication per login for ghostd and veild,
in its own unprivileged process started by systemd per connection, so
neither network-facing daemon loads PAM or reads /etc/shadow. Pulled in
by ghostd and veild; of no use on its own.

%package -n veild
Summary:        Veil: the Ghost broker and web UI
Requires:       ghostauth%{?_isa} = %{version}-%{release}
Requires:       openssl
Requires:       hostname
Requires:       firewalld-filesystem
%{?systemd_requires}

%description -n veild
Veil is the lobby clients sign in to before being connected to a Ghost
host. It serves a web UI and administers Wisp thin clients and the hosts
that join it.

A Veil machine does not need the host package, and a host does not need
this one.

%package -n spectre
Summary:        Ghost client: spectre and its Qt launcher
Requires:       hicolor-icon-theme
Recommends:     fuse3
Recommends:     mesa-dri-drivers
Recommends:     mesa-vulkan-drivers
Recommends:     pcsc-lite

%description -n spectre
spectre is the GDP client: it connects to a Ghost host, decodes the video
(VA-API, Vulkan Video or software) and sends input back. spectre-qt is the
launcher that collects the connection settings and starts it.

%package -n libgdp-devel
Summary:        Ghost Display Protocol library (development files)
License:        MIT
Provides:       libgdp-static = %{version}-%{release}
Requires:       ngtcp2-devel
Requires:       ngtcp2-crypto-ossl-devel
Requires:       protobuf-devel
Requires:       openssl-devel >= 3.5
Requires:       libzstd-devel

%description -n libgdp-devel
Headers, the static library, a pkg-config file and the .proto wire schema
for writing a GDP client or server. libgdp is linked statically into
ghostd, spectre and the others, so nothing here is needed at runtime.

%package -n pyrowave-libs
Summary:        PyroWave wavelet video codec (shared library)
License:        MIT

%description -n pyrowave-libs
PyroWave's C API, built from the pinned upstream commit
(github.com/Themaister/pyrowave) that ghostd's and spectre's "pyrowave"
codec was written against. The bitstream is still a draft upstream, so
both ends of a session must run the same build. Needs a Vulkan device
with compute support.

%prep
%autosetup

%build
# PyroWave (the optional "pyrowave" codec) has no distro package, so its
# pinned commit is built first, into _pyrowave, by the same script `make`
# users run. wraith and spectre link against it, and its shared library
# ships as pyrowave-libs, which rpm's dependency generator then makes
# ghostd and spectre require. The directory must exist and be ours, or
# the script falls back to sudo.
export CMAKE_BUILD_PARALLEL_LEVEL=%{_smp_build_ncpus}
mkdir -p _pyrowave
packaging/build-pyrowave.sh "$PWD/_pyrowave"
export PKG_CONFIG_PATH="$PWD/_pyrowave/share/pkgconfig:$PWD/_pyrowave/%{_lib}/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

# The prefix is baked into ghostd at compile time (host/ghostd/build.rs)
# and is the macro's /usr. The PAM stack and the pam-configs directory
# (Debian's pam-auth-update, absent here) are given explicitly: CMake's
# defaults probe the build machine. The polkit rule goes where packages
# put theirs; /etc/polkit-1/rules.d is the admin's.
%cmake \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DBUILD_SHARED_LIBS=OFF \
    -DGHOST_INSTALL_LIBGDP_DEV=ON \
    -DGHOST_ENABLE_PYROWAVE=ON \
    -DGHOST_PAM_STACK=system-auth \
    -DGHOST_PAM_CONFIGS_DIR= \
    -DGHOST_POLKIT_RULES_DIR=%{_datadir}/polkit-1/rules.d \
    -DGHOST_UDEV_RULES_DIR=%{_udevrulesdir}
# cargo is run by CMake and takes its job count from neither. The
# distribution's RUSTFLAGS (one codegen unit, opt-level 3) are dropped:
# the Rust binaries are built with host/Cargo.toml's release profile, as
# everywhere else.
unset RUSTFLAGS
export CARGO_BUILD_JOBS=%{_smp_build_ncpus}
%cmake_build

%install
%cmake_install

install -d %{buildroot}%{_libdir}
cp -a _pyrowave/%{_lib}/libpyrowave-shared.so.* %{buildroot}%{_libdir}/

# The live configs: the admin's from the first install on, so an upgrade
# leaves an edited one alone. Pristine copies are in the doc directory.
install -D -m 0644 -t %{buildroot}%{_sysconfdir}/ghost \
    packaging/config/ghostd.toml packaging/config/wraith.toml packaging/config/veild.toml

# veild is built by the same cargo workspace but, deliberately, not
# installed by CMake (a host never gets it): its binary comes from the
# cargo output, and its unit and PAM service are expanded here.
install -D -m 0755 host/target/release/veild %{buildroot}%{_bindir}/veild
install -d %{buildroot}%{_unitdir} %{buildroot}%{_sysconfdir}/pam.d
sed 's|@GHOST_BINDIR@|%{_bindir}|g' packaging/system/systemd/veild.service.in \
    > %{buildroot}%{_unitdir}/veild.service
packaging/system/pam-render.sh system-auth packaging/system/pam.d/veild.in \
    %{buildroot}%{_sysconfdir}/pam.d/veild
chmod 0644 %{buildroot}%{_unitdir}/veild.service %{buildroot}%{_sysconfdir}/pam.d/veild
# The veil account and the ghost-admins group: the fragment the Debian
# package installs.
install -D -m 0644 debian/veild.sysusers %{buildroot}%{_sysusersdir}/veild.conf
install -d -m 0700 %{buildroot}%{_sharedstatedir}/veil

# firewalld service definitions for the default ports. Nothing is opened
# by installing them: firewall-cmd --permanent --add-service=ghostd (or
# veild), then --reload.
install -D -m 0644 -t %{buildroot}%{_prefix}/lib/firewalld/services \
    packaging/system/firewalld/ghostd.xml packaging/system/firewalld/veild.xml

%check
desktop-file-validate %{buildroot}%{_datadir}/applications/spectre-qt.desktop
desktop-file-validate %{buildroot}%{_datadir}/applications/wraith.desktop
# One at a time: the libgdp transport tests share /tmp.
%ctest -j1

# The accounts come from the packaged sysusers.d fragments, which rpm
# applies before a package's files are unpacked, and systemd's file
# triggers reload udev for the gamepad seat rule. The units are left to
# the presets, as on any Fedora package: enable them with
#   systemctl enable --now ghostauth.socket ghostseat.socket ghostd
# What the scriptlets generate in /etc/ghost is not part of any package
# and stays when the packages are removed.
#
# SELinux: the helpers in /usr/lib/ghost would be lib_t, which leaves
# ghostauth and ghostseat in systemd's own domain, where pam_unix may not
# run its password helper. Labelled bin_t they run as unconfined services,
# like ghostd. ghostauth owns the rule, since a host and a Veil both have
# it; ghostd relabels its own files in the directory.

%post -n ghostauth
if command -v semanage >/dev/null 2>&1; then
    semanage fcontext -a -t bin_t '%{_prefix}/lib/ghost(/.*)?' 2>/dev/null \
        || semanage fcontext -m -t bin_t '%{_prefix}/lib/ghost(/.*)?' 2>/dev/null || :
    restorecon -R %{_prefix}/lib/ghost 2>/dev/null || :
fi
# The key ghostauth mints its tickets with and ghostseat verifies them
# (host/authticket). Generated once, root:ghostauth 0640; delete it and
# reinstall to rotate.
f=%{_sysconfdir}/ghost/auth-ticket.key
if [ ! -e "$f" ]; then
    echo "ghostauth: generating the authentication ticket key"
    if ( umask 077 && openssl rand -hex 32 > "$f" ); then
        chmod 0640 "$f"
        chgrp ghostauth "$f"
    else
        rm -f "$f"
        echo "ghostauth: ticket key generation failed" >&2
    fi
fi
%systemd_post ghostauth.socket

%preun -n ghostauth
%systemd_preun ghostauth.socket

%postun -n ghostauth
if [ $1 -eq 0 ] && command -v semanage >/dev/null 2>&1; then
    semanage fcontext -d '%{_prefix}/lib/ghost(/.*)?' 2>/dev/null || :
fi

%post -n ghostd
restorecon -R %{_prefix}/lib/ghost 2>/dev/null || :
%tmpfiles_create %{_tmpfilesdir}/ghost.conf
# The host's identity (gdp-spec.md section 2.3): a self-signed certificate
# ghostd's lobby presents and spectre pins on first use. Generated once and
# never replaced -- a new one makes every client that trusted this host warn
# that its certificate changed -- so it is not part of the package. The key
# is readable by the ghost group only; ghostd, which runs as that user, is
# its one reader.
crt=%{_sysconfdir}/ghost/host-cert.pem
key=%{_sysconfdir}/ghost/host-key.pem
if [ -e "$crt" ] || [ -e "$key" ]; then
    [ -e "$key" ] && chgrp ghost "$key" && chmod 0640 "$key"
else
    host=$(hostname -f 2>/dev/null || hostname)
    echo "ghostd: generating a self-signed host certificate for $host"
    if ( umask 077 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -sha256 -nodes -days 36500 -subj "/CN=$host" \
            -addext "subjectAltName=DNS:$host" -keyout "$key" -out "$crt" 2>/dev/null ); then
        chmod 0640 "$key"
        chgrp ghost "$key"
        chmod 0644 "$crt"
        openssl x509 -in "$crt" -noout -fingerprint -sha256
    else
        rm -f "$crt" "$key"
        echo "ghostd: certificate generation failed; create $crt and $key by hand" >&2
    fi
fi
%systemd_post ghostd.service ghostseat.socket
%firewalld_reload

%preun -n ghostd
%systemd_preun ghostd.service ghostseat.socket

%postun -n ghostd
%systemd_postun_with_restart ghostd.service

%post -n veild
# Generated once, never replaced, and not part of the package (an upgrade
# must not change the lobby's identity under the clients that pinned it).
# The keys are readable by the veil group.
dir=%{_sysconfdir}/ghost
host=$(hostname -f 2>/dev/null || hostname)
short=$(hostname -s 2>/dev/null || hostname)

# Veil's lobby certificate, what GDP clients pin.
crt=$dir/veil-cert.pem
key=$dir/veil-key.pem
if [ ! -e "$crt" ] && [ ! -e "$key" ]; then
    echo "veild: generating Veil's lobby certificate for $host"
    if ( umask 077 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -sha256 -nodes -days 36500 -subj "/CN=$host" \
            -addext "subjectAltName=DNS:$host" -keyout "$key" -out "$crt" 2>/dev/null ); then
        chmod 0644 "$crt"
        chmod 0640 "$key"
        chgrp veil "$key"
        openssl x509 -in "$crt" -noout -fingerprint -sha256
    else
        rm -f "$crt" "$key"
        echo "veild: lobby certificate generation failed" >&2
    fi
fi

# The web UI's HTTPS pair: self-signed, so browsers warn until the admin
# points veild.toml at a real one. It names every name and address this
# machine has right now.
crt=$dir/veil-web-cert.pem
key=$dir/veil-web-key.pem
if [ ! -e "$crt" ] && [ ! -e "$key" ]; then
    san="DNS:$host"
    [ "$short" = "$host" ] || san="$san,DNS:$short"
    san="$san,DNS:localhost,IP:127.0.0.1,IP:::1"
    for ip in $(hostname -I 2>/dev/null); do
        case "$ip" in fe80:*) ;; *) san="$san,IP:$ip" ;; esac
    done
    echo "veild: generating a self-signed web certificate for $san"
    if ( umask 077 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -sha256 -nodes -days 825 -subj "/CN=$host" -addext "subjectAltName=$san" \
            -addext "basicConstraints=critical,CA:FALSE" \
            -addext "keyUsage=critical,digitalSignature" \
            -addext "extendedKeyUsage=serverAuth" -keyout "$key" -out "$crt" 2>/dev/null ); then
        chmod 0644 "$crt"
        chmod 0640 "$key"
        chgrp veil "$key"
    else
        rm -f "$crt" "$key"
        echo "veild: web certificate generation failed" >&2
    fi
fi

# The Wisp thin clients' shared key ([thin_clients] key). Delete it and
# reinstall to rotate.
f=$dir/veil-wisp.key
if [ ! -e "$f" ]; then
    echo "veild: generating the Wisp key"
    if ( umask 077 && openssl rand -hex 32 > "$f" ); then
        chmod 0640 "$f"
        chgrp veil "$f"
    else
        rm -f "$f"
        echo "veild: Wisp key generation failed" >&2
    fi
fi
%systemd_post veild.service
%firewalld_reload

%preun -n veild
%systemd_preun veild.service

%postun -n veild
%systemd_postun_with_restart veild.service

%files -n ghostd
%license COPYING LICENSES/*.txt
%dir %{_sysconfdir}/ghost
%config(noreplace) %{_sysconfdir}/ghost/ghostd.toml
%config(noreplace) %{_sysconfdir}/ghost/wraith.toml
%config %{_sysconfdir}/pam.d/ghostd
%config %{_sysconfdir}/pam.d/ghostseat
%{_bindir}/ghostd
%{_bindir}/wraith
%dir %{_prefix}/lib/ghost
%{_prefix}/lib/ghost/ghostlogin
%{_prefix}/lib/ghost/ghostseat
%{_prefix}/lib/ghost/pcsc/
%{_prefix}/lib/ghost/sessions/
%{_unitdir}/ghostd.service
%{_unitdir}/ghostseat.socket
%{_unitdir}/ghostseat@.service
%{_userunitdir}/wraith.service
%{_userunitdir}/plasma-kwin_wayland.service.d/
%{_sysusersdir}/ghostd.conf
%{_tmpfilesdir}/ghost.conf
%{_udevrulesdir}/72-ghost-input.rules
%{_prefix}/lib/firewalld/services/ghostd.xml
%{_datadir}/polkit-1/rules.d/49-ghost-sessions.rules
%{_datadir}/applications/wraith.desktop
%{_datadir}/ghost/
%dir %{_docdir}/ghost
%{_docdir}/ghost/ghostd.toml
%{_docdir}/ghost/wraith.toml

%files -n ghostauth
%license COPYING LICENSES/*.txt
%dir %{_sysconfdir}/ghost
%dir %{_prefix}/lib/ghost
%{_prefix}/lib/ghost/ghostauth
%{_unitdir}/ghostauth.socket
%{_unitdir}/ghostauth@.service
%{_sysusersdir}/ghostauth.conf

%files -n veild
%license COPYING LICENSES/*.txt
%dir %{_sysconfdir}/ghost
%config(noreplace) %{_sysconfdir}/ghost/veild.toml
%config %{_sysconfdir}/pam.d/veild
%{_bindir}/veild
%{_unitdir}/veild.service
%{_sysusersdir}/veild.conf
%{_prefix}/lib/firewalld/services/veild.xml
%dir %attr(0700,veil,veil) %{_sharedstatedir}/veil

%files -n spectre
%license COPYING LICENSES/*.txt
%{_bindir}/spectre
%{_bindir}/spectre-qt
%{_datadir}/applications/spectre-qt.desktop
%{_datadir}/icons/hicolor/256x256/apps/spectre-qt.png
%{_datadir}/pixmaps/spectre-qt.png

%files -n libgdp-devel
%license LICENSES/MIT.txt
%{_includedir}/gdp/
%{_libdir}/libgdp.a
%{_libdir}/pkgconfig/gdp.pc
%{_datadir}/gdp/

%files -n pyrowave-libs
%license _pyrowave/share/doc/pyrowave/LICENSE
%license _pyrowave/share/doc/pyrowave/LICENSE-Granite
%{_libdir}/libpyrowave-shared.so.0*

%changelog
* Tue Oct 13 2026 Joseph Saiko <68829025+jsaiko@users.noreply.github.com>
- Initial RPM packaging: ghostd (host), ghostauth, veild (Veil broker),
  spectre (client), libgdp-devel and pyrowave-libs.
