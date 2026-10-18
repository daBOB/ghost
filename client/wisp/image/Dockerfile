# Wisp image: an Ubuntu 26.04 rootfs that boots into wisp-greeter under labwc
# (a Wayland compositor, configured as a kiosk), which signs in to Veil and
# runs spectre. `make rootfs` (client/wisp/Makefile) builds the `out` stage with
# the repo root as context and drops vmlinuz, initrd and wisp.squashfs into
# content/x86_64/; `make rootfs ARCH=arm64` builds the same for arm64 (UEFI
# machines) into content/arm64/. Ubuntu 26.04 packages everything spectre
# needs but PyroWave: OpenSSL 3.5, ngtcp2 with its OpenSSL QUIC helper, and
# SDL 3.4. Debian trixie had neither of the last two new enough, and its
# labwc (0.8) left spectre's fullscreen window at its opening size on a
# 200%-scaled output.
#
# The build stage runs on the build machine's own architecture and
# cross-compiles for the target's, so an x86 host builds arm64 (and an ARM
# Mac x86_64) at native compiler speed. Only the rootfs stage, which installs
# packages and builds the initramfs, runs as the target, under QEMU emulation
# when the architectures differ.

# --- build: spectre, wisp-greeter and wisp-agent ---------------------------
FROM --platform=$BUILDPLATFORM ubuntu:26.04 AS build
ARG BUILDARCH
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive
# Tools that run during the build (compilers, protoc, glslangValidator,
# wayland-scanner, Qt's moc/rcc/uic) are the build machine's; libraries are
# the target's (multiarch, :$TARGETARCH). Qt's host tools come from the build
# machine's own qt6-base-dev, which co-installs with the target's. Ubuntu
# keeps amd64 on archive.ubuntu.com and every other architecture on
# ports.ubuntu.com, so a cross build pins the image's own sources to the
# build machine's architecture and adds the target's archive beside them.
RUN if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
        archive_of() { case "$1" in amd64) echo http://archive.ubuntu.com/ubuntu ;; *) echo http://ports.ubuntu.com/ubuntu-ports ;; esac; }; \
        . /etc/os-release \
     && sed -i "/^Types:/a Architectures: $BUILDARCH" /etc/apt/sources.list.d/ubuntu.sources \
     && printf '%s\n' 'Types: deb' "URIs: $(archive_of "$TARGETARCH")" \
            "Suites: $VERSION_CODENAME $VERSION_CODENAME-updates $VERSION_CODENAME-security" \
            'Components: main universe' "Architectures: $TARGETARCH" \
            'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
            > /etc/apt/sources.list.d/target.sources \
     && dpkg --add-architecture "$TARGETARCH"; \
    fi \
 && apt-get update \
 && if [ "$TARGETARCH" = "$BUILDARCH" ]; then cc=build-essential; else cc="crossbuild-essential-$TARGETARCH"; fi \
 && apt-get install -y --no-install-recommends \
        $cc make cmake ninja-build pkgconf git ca-certificates binutils \
        glslang-tools protobuf-compiler libwayland-bin wayland-protocols qt6-base-dev \
        $(for pkg in libssl-dev libavcodec-dev libavutil-dev libopus-dev \
                libva-dev libvulkan-dev libprotobuf-dev libzstd-dev qt6-base-dev \
                libwayland-dev libxkbcommon-dev libdecor-0-dev libasound2-dev \
                libdrm-dev libgbm-dev libegl-dev libgles-dev libudev-dev libdbus-1-dev \
                libsdl3-dev libngtcp2-dev libngtcp2-crypto-ossl-dev; do \
            echo "$pkg:$TARGETARCH"; done) \
 && rm -rf /var/lib/apt/lists/*
# Every CMake configure below (and in build-pyrowave.sh) picks this up from
# the environment. Empty for a native build.
ENV CMAKE_TOOLCHAIN_FILE=/toolchain.cmake
# PyroWave, built from source, installs here, for the target.
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
RUN triplet_of() { case "$1" in amd64) echo x86_64-linux-gnu ;; arm64) echo aarch64-linux-gnu ;; esac; } \
 && triplet=$(triplet_of "$TARGETARCH") && host_triplet=$(triplet_of "$BUILDARCH") \
 && [ -n "$triplet" ] && [ -n "$host_triplet" ] \
 || { echo "unsupported architecture: $BUILDARCH -> $TARGETARCH" >&2; exit 1; } \
 && cpu=${triplet%%-*} \
 && echo "$triplet" > /triplet \
 && if [ "$TARGETARCH" = "$BUILDARCH" ]; then : > /toolchain.cmake; else \
        printf '%s\n' \
        'set(CMAKE_SYSTEM_NAME Linux)' \
        "set(CMAKE_SYSTEM_PROCESSOR $cpu)" \
        "set(CMAKE_C_COMPILER $triplet-gcc)" \
        "set(CMAKE_CXX_COMPILER $triplet-g++)" \
        "set(CMAKE_LIBRARY_ARCHITECTURE $triplet)" \
        "set(PKG_CONFIG_EXECUTABLE /usr/bin/$triplet-pkg-config)" \
        '# Run the build machine'"'"'s moc/rcc/uic, protoc and glslangValidator.' \
        'set(QT_HOST_PATH /usr)' \
        "set(QT_HOST_PATH_CMAKE_DIR /usr/lib/$host_triplet/cmake)" \
        'set(Protobuf_PROTOC_EXECUTABLE /usr/bin/protoc)' \
        > /toolchain.cmake; \
    fi \
 && cat /toolchain.cmake
# PyroWave's C API, for spectre's "pyrowave" codec: the same script and pinned
# commit the desktop builds use (both ends of a session must run the same draft
# bitstream). Without it spectre builds without the codec and never offers it.
COPY packaging/build-pyrowave.sh /tmp/build-pyrowave.sh
RUN bash /tmp/build-pyrowave.sh /usr/local
COPY . /src
RUN cmake -S /src -B /build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DGHOST_BUILD_HOST=OFF -DGHOST_BUILD_LAUNCHER=OFF -DGHOST_BUILD_WISP=ON \
 && cmake --build /build -j"$(nproc)" --target spectre wisp-greeter wisp-agent \
 && mkdir -p /out/usr/local/bin /out/usr/local/lib \
 && cp /build/bin/spectre /build/bin/wisp-greeter /build/bin/wisp-agent /out/usr/local/bin/ \
 && cp -a /usr/local/lib/libpyrowave-shared.so.0* /out/usr/local/lib/ \
 && mkdir -p /out/usr/local/share/doc/ghost \
 && cp /src/debian/copyright /out/usr/local/share/doc/ghost/copyright \
 && cp -a /usr/local/share/doc/pyrowave /out/usr/local/share/doc/ \
 && strip=strip && if [ -s /toolchain.cmake ]; then strip="$(cat /triplet)-strip"; fi \
 && $strip --strip-debug /out/usr/local/bin/* /out/usr/local/lib/*
# The runtime packages, from the libraries the binaries name (DT_NEEDED;
# ldd can't run a binary of another architecture). Their own dependencies
# come along with them in the rootfs stage.
RUN triplet=$(cat /triplet) \
 && readelf -d /out/usr/local/bin/* /out/usr/local/lib/*.so.* > /tmp/dynamic \
 && needed=$(sed -n 's/.*Shared library: \[\(.*\)\]/\1/p' /tmp/dynamic | sort -u) \
 && [ -n "$needed" ] \
 && for so in $needed; do \
        [ -e "/out/usr/local/lib/$so" ] && continue; \
        path=$(ls "/usr/lib/$triplet/$so" "/lib/$triplet/$so" 2>/dev/null | head -1); \
        [ -n "$path" ] || { echo "no package has $so" >&2; exit 1; }; \
        dpkg -S "$path" 2>/dev/null || dpkg -S "$(realpath "$path")"; \
    done | cut -d: -f1 | sort -u > /out/runtime-packages \
 && [ -s /out/runtime-packages ] \
 && cat /out/runtime-packages

# --- rootfs ----------------------------------------------------------------
FROM ubuntu:26.04 AS rootfs
ENV DEBIAN_FRONTEND=noninteractive
# Set by BuildKit from --platform: amd64 or arm64, Ubuntu's names too.
ARG TARGETARCH
# live-boot's initramfs fetches the squashfs (fetch=URL) into RAM and puts a
# writable overlay on top. MODULES=most keeps the initrd bootable on NICs we
# haven't seen yet; initramfs-tools goes in first, as what live-boot hooks
# into (Ubuntu's kernels otherwise suggest dracut). The kernel by version, not
# linux-image-generic: that metapackage depends on all of linux-firmware
# (every vendor's, about 1 GB) and the microcode packages. The firmware, PC
# GPUs and Realtek NICs on amd64 only: AMD's and Intel's, without which
# amdgpu/i915 fall back to a dumb framebuffer, and NVIDIA's GSP firmware,
# without which nouveau fails to probe Turing and newer and leaves no DRM
# device at all.
RUN case "$TARGETARCH" in \
        amd64) firmware="linux-firmware-amd-graphics linux-firmware-intel-graphics linux-firmware-nvidia-graphics linux-firmware-realtek" ;; \
        arm64) firmware="" ;; \
        *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && apt-get update && apt-get install -y --no-install-recommends \
        initramfs-tools \
 && echo 'MODULES=most' >> /etc/initramfs-tools/initramfs.conf \
 && kernel=$(apt-cache depends linux-image-generic | sed -n 's/.*Depends: linux-image-\([0-9].*\)$/\1/p' | head -1) \
 && [ -n "$kernel" ] \
 && apt-get install -y --no-install-recommends \
        "linux-image-$kernel" live-boot \
        systemd systemd-sysv systemd-resolved systemd-timesyncd libpam-systemd udev dbus kmod polkitd \
        bash iproute2 iputils-ping curl ca-certificates less pciutils usbutils \
        openssh-server \
        $firmware \
 && rm -rf /var/lib/apt/lists/*
# The kiosk: labwc (not cage: games' mouselook needs pointer-constraints,
# which cage lacks; labwc's hard dependency on xwayland comes along, but it
# only starts if an X client connects), and what spectre and the greeter
# load at runtime beyond their direct links (Qt's Wayland plugin, SDL3's dlopen'd Wayland and ALSA,
# Mesa's GL/Vulkan/VA-API drivers incl. lavapipe for GPU-less clients, the
# VA-API ones in mesa-libgallium; Intel's iHD VA-API driver on amd64, since
# Mesa's only cover AMD and nouveau -- without it an N100-class client has no
# hardware decode over VA-API).
# PipeWire in the wisp user's session gives the client a volume (spectre's
# kiosk menu, through wpctl) even on HDMI outputs without a hardware mixer;
# pipewire-alsa routes ALSA's default device, which SDL plays to, through it.
# swayidle and wlopm turn the display off after the profile's idle time
# (the greeter's display_sleep.cpp). wlr-randr sets a 4K-class output's
# scale (wisp-session).
COPY --from=build /out/runtime-packages /tmp/runtime-packages
RUN apt-get update && apt-get install -y --no-install-recommends \
        labwc qt6-wayland fonts-dejavu-core swayidle wlopm wlr-randr \
        libwayland-client0 libwayland-cursor0 libwayland-egl1 libxkbcommon0 libdecor-0-0 \
        libegl1 libegl-mesa0 libgl1-mesa-dri mesa-vulkan-drivers mesa-libgallium \
        libasound2t64 alsa-ucm-conf pipewire pipewire-alsa wireplumber \
        $(if [ "$TARGETARCH" = amd64 ]; then echo intel-media-va-driver; fi) \
        $(cat /tmp/runtime-packages) \
 && rm -rf /var/lib/apt/lists/* /tmp/runtime-packages
COPY --from=build /out/usr/local/ /usr/local/
RUN ldconfig && for bin in /usr/local/bin/spectre /usr/local/bin/wisp-greeter /usr/local/bin/wisp-agent; do \
        ! ldd "$bin" | grep 'not found' || exit 1; \
    done
COPY client/wisp/image/rootfs/ /
# The kiosk user: no password, no shell login; logind hands its session the
# seat (DRM, input, sound) while it is the active one on tty1. The base
# image's own "ubuntu" user, which has a login shell, goes.
# sshd only through wisp-ssh.service (the boot server's WISP_SSH_KEY), never
# Ubuntu's own units, and with no host keys in the image: anyone can fetch
# the squashfs, so wisp-ssh makes them at boot.
RUN userdel --remove ubuntu 2>/dev/null; \
    useradd --create-home --shell /usr/sbin/nologin --groups audio,video,render wisp \
 && rm -f /etc/ssh/ssh_host_* \
 && systemctl mask ssh.service ssh.socket \
 && systemctl enable wisp-hostname wisp-ntp wisp-agent wisp-kiosk wisp-ssh systemd-networkd systemd-resolved systemd-timesyncd getty@tty2 \
 && systemctl set-default graphical.target \
 && systemctl mask systemd-networkd-wait-online \
 && update-initramfs -u \
 && rm -rf /var/cache/apt /var/log/*.log
# What wisp-agent reports to Veil as the image version (make rootfs sets
# it). Last, so a new version doesn't redo the layers above.
ARG WISP_VERSION=unknown
RUN echo "$WISP_VERSION" > /etc/wisp-release

# --- pack ------------------------------------------------------------------
# Only copies files and runs mksquashfs, so on the build machine's own
# architecture: emulated, compressing the squashfs takes minutes.
FROM --platform=$BUILDPLATFORM ubuntu:26.04 AS pack
RUN apt-get update && apt-get install -y --no-install-recommends squashfs-tools \
 && rm -rf /var/lib/apt/lists/*
COPY --from=rootfs / /rootfs
# One kernel per image: the newest, should a package ever leave two.
RUN mkdir /out \
 && kernel=$(ls /rootfs/boot/vmlinuz-* | sort -V | tail -1) && version=${kernel#/rootfs/boot/vmlinuz-} \
 && cp "$kernel" /out/vmlinuz \
 && cp "/rootfs/boot/initrd.img-$version" /out/initrd \
 && chmod 644 /out/vmlinuz /out/initrd \
 && mksquashfs /rootfs /out/wisp.squashfs -comp zstd -noappend -quiet \
        -e rootfs/boot rootfs/proc rootfs/sys rootfs/dev rootfs/run rootfs/tmp

FROM scratch AS out
COPY --from=pack /out/ /
