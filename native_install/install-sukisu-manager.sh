#!/system/bin/sh
# Parent-owned one-shot init service uses shell UID/domain after boot completion.
set -eu
apk=/product/app/SukiSU/SukiSU.apk
checker=/product/etc/googlebook/SukiSUManagerCheck.jar
expected=c7f69280cf468e8415c585ff31f963d0147386831217a1e89b822afddc5f40ed
checker_expected=4758405679d172ab7d530a18aa4f1c68a7204ec035724848122bc7d1270ac822
case "$(id -u)" in 0|2000) ;; *) exit 1 ;; esac
[ "$(getprop sys.boot_completed)" = 1 ] || exit 1
[ "$(readlink -f "$0")" = /product/etc/googlebook/install-sukisu-manager.sh ] || exit 1
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
# A system preinstall alone is outside SukiSU 4.2.1's /data/app scanner.
cmd package install -r --user all "$apk" >/dev/null
CLASSPATH="$checker" app_process /system/bin SukiSUManagerCheck
