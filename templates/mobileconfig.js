const fs = require('fs');
const path = require('path');

// mobileconfig 模板生成器
function generateMobileConfig(baseURL, bundleId) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <dict>
        <key>PayloadType</key>
        <string>com.apple.device.management</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>PayloadIdentifier</key>
        <string>com.distribup.udid</string>
        <key>DeviceAttributes</key>
        <array>
            <string>UDID</string>
            <string>IMEI</string>
            <string>ICCID</string>
            <string>SerialNumber</string>
            <string>ProductName</string>
        </array>
    </dict>
    <key>PayloadDisplayName</key>
    <string>DistribUp UDID Collector</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadUUID</key>
    <string>${generateUUID()}</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadIdentifier</key>
    <string>com.distribup.profile</string>
    <key>ExpirationDate</key>
    <date>${new Date(Date.now() + 86400000).toISOString()}</date>
</dict>
</plist>`;
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

module.exports = { generateMobileConfig };
