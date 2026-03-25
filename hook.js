/**
 * Usage: frida -U -f com.iberia.android -l hook.js
 *
 * Output:
 *   [AKM] SESSION_KEY: <32 hex chars>   ← paste in decrypt_sensor.py SESSION_KEY
 *   [AKM] HMAC_KEY:    <64 hex chars>   ← paste in decrypt_sensor.py HMAC_KEY
 *   [AKM] HEADER:      6,a,...          ← paste in decrypt_sensor.py HEADER
 */
'use strict';

function hex(buf) {
    var a = new Uint8Array(buf), s = '';
    for (var i = 0; i < a.length; i++) s += ('0' + a[i].toString(16)).slice(-2);
    return s;
}

var dumped = false;

Java.perform(function() {
    // Hook getSensorData — captures the final assembled header
    try {
        var Mon = Java.use('com.cyberfend.cyfsecurity.CYFMonitor');
        Mon.getSensorData.implementation = function() {
            var header = this.getSensorData();

            // Dump crypto context on first call
            if (!dumped) {
                var base = Process.findModuleByName('libakamaibmp.so').base;
                var ctx = base.add(0x246690).readPointer();
                if (!ctx.isNull() && ctx.add(40).readU8() === 1) {
                    var sk = ctx.readPointer().readByteArray(16);
                    var hk = ctx.add(16).readPointer().readByteArray(32);
                    console.log('[AKM] SESSION_KEY: ' + hex(sk));
                    console.log('[AKM] HMAC_KEY:    ' + hex(hk));
                }
                dumped = true;
            }

            console.log('[AKM] HEADER: ' + header);
            return header;
        };
    } catch(e) { console.log('[AKM] hook err: ' + e); }

    console.log('[AKM] Ready — waiting for sensor data...');
});
