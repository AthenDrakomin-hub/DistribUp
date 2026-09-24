const crypto = require('crypto');
const path = require('path');

function generateManifest(app) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>items</key>
    <array>
        <dict>
            <key>assets</key>
            <array>
                <dict>
                    <key>kind</key>
                    <string>software-package</string>
                    <key>url</key>
                    <string>${app.downloadUrl}</string>
                    <key>md5-size</key>
                    <integer>${app.fileSize}</integer>
                    <key>md5</key>
                    <string>${app.md5 || ''}</string>
                </dict>
                <dict>
                    <key>kind</key>
                    <string>display-image</string>
                    <key>needs-shine</key>
                    <true/>
                    <key>url</key>
                    <string>${app.iconUrl || '/assets/default-icon.png'}</string>
                </dict>
                <dict>
                    <key>kind</key>
                    <string>full-size-image</string>
                    <key>needs-shine</key>
                    <true/>
                    <key>url</key>
                    <string>${app.iconUrl || '/assets/default-icon.png'}</string>
                </dict>
            </array>
            <key>metadata</key>
            <dict>
                <key>bundle-identifier</key>
                <string>${app.bundleId}</string>
                <key>bundle-version</key>
                <string>${app.version}</string>
                <key>kind</key>
                <string>software</string>
                <key>title</key>
                <string>${app.name}</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>`;
}

module.exports = { generateManifest };
