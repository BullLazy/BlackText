[app]

title = BlackText

package.name = blacktext
package.domain = com.blacktext

source.dir = .
source.include_exts = py,kv,png,jpg,jpeg,atlas
source.exclude_dirs = .git,.github,__pycache__,tests,bin,.buildozer

version = 0.1.0

requirements = python3,kivy,cryptography,charset_normalizer==2.1.1

orientation = portrait
fullscreen = 0

android.permissions = INTERNET

android.api = 36
android.minapi = 24

android.ndk = 29
android.ndk_api = 24

android.sdk_path = /usr/local/lib/android/sdk
android.ndk_path = /usr/local/lib/android/sdk/ndk/29.0.14206865

android.skip_update = True
android.accept_sdk_license = True

android.archs = arm64-v8a

android.allow_backup = False

android.debug_artifact = apk
android.release_artifact = apk

p4a.branch = develop


[buildozer]

log_level = 2
warn_on_root = 1
