#!/bin/bash
# SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
# SPDX-License-Identifier: GPL-3.0-only
# Turns a build tree's spectre-qt.app into a self-contained Spectre.app and
# a .dmg of it: Qt (macdeployqt), the vcpkg dylibs spectre-qt and spectre
# link, and MoltenVK with its ICD manifest, which the Vulkan loader finds
# in the bundle's Contents/Resources/vulkan/icd.d -- so VK_DRIVER_FILES is
# no longer needed.
#
#   packaging/macos/bundle.sh BUILD_DIR OUT.dmg
#
# Needs macdeployqt (Qt's bin/, or QT_ROOT_DIR set as install-qt-action
# does) and the network, for MoltenVK. Signs ad hoc unless
# CODESIGN_IDENTITY names a Developer ID; notarization is separate.
set -euo pipefail

# The MoltenVK release bundled, by the hash of its MoltenVK-macos.tar.
MOLTENVK_VERSION=v1.4.2
MOLTENVK_SHA256=f95765a6229cb7b915990a2890ce12ebe36a730b021545d3d52ae69ce4c4024e

build=$(cd "$1" && pwd)
out=$2
identity=${CODESIGN_IDENTITY:--}
macdeployqt=${MACDEPLOYQT:-${QT_ROOT_DIR:+$QT_ROOT_DIR/bin/}macdeployqt}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

app=$work/dmg/Spectre.app
mkdir -p "$work/dmg"
ditto "$build/bin/spectre-qt.app" "$app"

# MoltenVK, the only Vulkan driver on macOS. The loader dlopens it through
# the manifest, whose library_path is relative to the manifest itself.
curl -fsSL -o "$work/MoltenVK-macos.tar" \
	"https://github.com/KhronosGroup/MoltenVK/releases/download/$MOLTENVK_VERSION/MoltenVK-macos.tar"
echo "$MOLTENVK_SHA256  $work/MoltenVK-macos.tar" | shasum -a 256 -c -
tar -xf "$work/MoltenVK-macos.tar" -C "$work" MoltenVK/MoltenVK/dynamic/dylib/macOS
mkdir -p "$app/Contents/Frameworks" "$app/Contents/Resources/vulkan/icd.d"
cp "$work/MoltenVK/MoltenVK/dynamic/dylib/macOS/libMoltenVK.dylib" "$app/Contents/Frameworks/"
sed 's|"library_path" *: *"[^"]*"|"library_path": "../../../Frameworks/libMoltenVK.dylib"|' \
	"$work/MoltenVK/MoltenVK/dynamic/dylib/macOS/MoltenVK_icd.json" \
	> "$app/Contents/Resources/vulkan/icd.d/MoltenVK_icd.json"

# Qt's frameworks and plugins, and every non-system dylib either
# executable loads (vcpkg's, found through the build tree's rpath or
# -libpath), copied into Contents/Frameworks with their install names
# rewritten to match.
vcpkg_lib=$(find "$build/vcpkg_installed" -maxdepth 2 -type d -name lib -not -path '*/debug/*' | head -n 1)
"$macdeployqt" "$app" \
	-executable="$app/Contents/MacOS/spectre" \
	${vcpkg_lib:+-libpath="$vcpkg_lib"} \
	-always-overwrite

# The build tree's absolute rpaths would make the bundle look outside
# itself on a machine that happens to have the same path.
for bin in "$app/Contents/MacOS/spectre-qt" "$app/Contents/MacOS/spectre"; do
	otool -l "$bin" | awk '/LC_RPATH/ { getline; getline; print $2 }' | while read -r rpath; do
		case "$rpath" in
		/*) install_name_tool -delete_rpath "$rpath" "$bin" ;;
		esac
	done
done

# Nothing in the bundle may load from outside it, apart from the system.
bad=0
while IFS= read -r -d '' f; do
	file -b "$f" | grep -q 'Mach-O' || continue
	while read -r dep; do
		case "$dep" in
		/System/* | /usr/lib/* | @executable_path/* | @loader_path/* | @rpath/*) ;;
		*) echo "error: ${f#"$work"/dmg/} loads $dep" >&2; bad=1 ;;
		esac
	# The dependencies are the indented lines; a universal binary (MoltenVK)
	# has a header line per architecture.
	done < <(otool -L "$f" | awk '/^\t/ { print $1 }')
done < <(find "$app" -type f -print0)
[ "$bad" -eq 0 ]

# install_name_tool broke every signature it touched, and Apple silicon
# runs nothing unsigned. Nested code first, then the bundle.
sign=(codesign --force --sign "$identity" --timestamp=none)
[ "$identity" = "-" ] || sign=(codesign --force --sign "$identity" --options runtime --timestamp)
find "$app/Contents/Frameworks" "$app/Contents/PlugIns" \( -name '*.dylib' -o -name '*.framework' \) -prune -print0 |
	xargs -0 "${sign[@]}"
"${sign[@]}" "$app/Contents/MacOS/spectre"
"${sign[@]}" "$app"
codesign --verify --deep --strict "$app"

# The usual drag-to-install image.
ln -s /Applications "$work/dmg/Applications"
rm -f "$out"
hdiutil create -volname Spectre -srcfolder "$work/dmg" -fs HFS+ -format UDZO "$out"
echo "-- $out"
