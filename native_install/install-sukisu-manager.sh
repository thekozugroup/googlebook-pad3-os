#!/system/bin/sh
# Parent-owned one-shot init service uses shell UID/domain after boot completion.
set -eu
apk=/system_ext/etc/googlebook/SukiSU.apk
checker=/system_ext/etc/googlebook/SukiSUManagerCheck.jar
expected=a928eb57ad34b105233f92dcd55e54dd883482e417970276329a7d0f0979e212
checker_expected=e46d45f8eeeb444c33a58573475049e7dfbe6b0340945399de1e5114b8f7816e
case "$(id -u)" in 0|2000) ;; *) exit 1 ;; esac
[ "$(getprop sys.boot_completed)" = 1 ] || exit 1
[ "$(readlink -f "$0")" = /system_ext/etc/googlebook/install-sukisu-manager.sh ] || exit 1
for file in "$apk" "$checker"; do
    [ -f "$file" ] && [ ! -L "$file" ] && [ "$(readlink -f "$file")" = "$file" ] || exit 1
done
actual=$(sha256sum "$apk")
[ "${actual%% *}" = "$expected" ] || exit 1
actual=$(sha256sum "$checker")
[ "${actual%% *}" = "$checker_expected" ] || exit 1
# Check the current signer, data path and version; preserve newer official installs.
if CLASSPATH="$checker" app_process /system/bin SukiSUManagerCheck; then
    exit 0
else
    result=$?
fi
[ "$result" = 10 ] || exit 1
# The seed is outside APK scanning; install the official identity into /data/app.
cmd package install -r --user all "$apk" >/dev/null
CLASSPATH="$checker" app_process /system/bin SukiSUManagerCheck
