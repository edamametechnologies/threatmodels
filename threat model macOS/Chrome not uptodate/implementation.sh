#!/bin/bash

defaults read /Applications/Google\ Chrome.app/Contents/Info.plist CFBundleShortVersionString &>/dev/null &&
{ local_version=$(defaults read /Applications/Google\ Chrome.app/Contents/Info.plist CFBundleShortVersionString);
latest_version=$(curl -s "https://formulae.brew.sh/api/cask/google-chrome.json" | sed -n 's/.*\"version\": \"\([^\"]*\)\".*/\1/p');
if [ "$(printf '%s\n%s\n' "$local_version" "$latest_version" | sort -V | tail -n1)" = "$latest_version" ] &&
[ "$local_version" != "$latest_version" ];
then echo "Chrome is not up to date (Installed: $local_version, Latest: $latest_version)";
fi;
}
