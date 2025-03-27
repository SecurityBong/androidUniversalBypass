// Universal Android Bypass Script v1.7 (Persistent)
// Guaranteed to attempt all bypasses without early termination

// ========================
// CONFIGURATION
// ========================
var config = {
    debug: true,
    retryDelay: 500, // ms between retries
    targetLibs: ["libpairipcore.so", "libssl.so", "libtoolchecker.so"],
    rootPackages: [
        "com.topjohnwu.magisk", "eu.chainfire.supersu"
    ],
    securityClasses: [
        "krabcqj.ac", 
        "com.talsec.security.Talsec"
    ]
};

// ========================
// PERSISTENT LOGGER
// ========================
function log(message) {
    try {
        if (!config.debug) return;
        (typeof send !== 'undefined' ? send : console.log)("[BYPS] " + message);
    } catch (e) {
        // Absolute fallback
        Java.perform(function() {
            Java.use("android.util.Log").d("BYPS", message);
        });
    }
}

// ========================
// RESILIENT UTILITIES
// ========================
function safeUse(className, callback) {
    try {
        var clazz = Java.use(className);
        callback(clazz);
        return true;
    } catch (e) {
        log("[!] Class access failed: " + className);
        return false;
    }
}

function hookWhenAvailable(libName, retries = 3) {
    var tries = 0;
    var interval = setInterval(function() {
        try {
            var base = Module.findBaseAddress(libName);
            if (base) {
                clearInterval(interval);
                log("[√] Library loaded: " + libName);
                hookExports(libName);
            } else if (tries++ >= retries) {
                clearInterval(interval);
                log("[!] Library not found: " + libName);
            }
        } catch (e) {
            log("[X] Hook error: " + e);
        }
    }, config.retryDelay);
}

function hookExports(libName) {
    try {
        Module.enumerateExports(libName).forEach(function(exp) {
            try {
                Interceptor.attach(exp.address, {
                    onEnter: function() {
                        log("[→] Called: " + exp.name);
                    }
                });
            } catch (e) {
                log("[!] Failed hook: " + exp.name);
            }
        });
    } catch (e) {
        log("[X] Export hooking failed");
    }
}

// ========================
// PERSISTENT BYPASSES
// ========================
function bypassRootDetection() {
    // 1. System Properties
    safeUse("java.lang.System", function(System) {
        System.getProperty.implementation = function(key) {
            if (["ro.debuggable", "ro.secure"].includes(key)) {
                log("[√] Spoofed: " + key);
                return "0";
            }
            return this.getProperty(key);
        };
    });

    // 2. Package Checks
    safeUse("android.app.ApplicationPackageManager", function(PkgManager) {
        PkgManager.getPackageInfo.implementation = function(pname) {
            if (config.rootPackages.includes(pname)) {
                log("[√] Blocked package: " + pname);
                return null;
            }
            return this.getPackageInfo(pname);
        };
    });

    // 3. Native Checks
    var rootBinaries = ["su", "magisk"];
    rootBinaries.forEach(function(bin) {
        var fopen = Module.findExportByName(null, "fopen");
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter: function(args) {
                    var path = args[0].readCString();
                    if (path && path.includes(bin)) {
                        log("[√] Blocked access to: " + path);
                        args[0] = Memory.allocUtf8String("/dev/null");
                    }
                }
            });
        }
    });
}

function bypassSSLPinning() {
    // 1. Java Layer
    safeUse("javax.net.ssl.X509TrustManager", function(TrustManager) {
        TrustManager.checkServerTrusted.implementation = function() {
            log("[√] SSL validation bypassed");
        };
    });

    // 2. Native Layer
    var sslVerify = Module.findExportByName("libssl.so", "SSL_verify");
    if (sslVerify) {
        Interceptor.attach(sslVerify, {
            onEnter: function(args) {
                args[0] = 0; // Force success
            }
        });
    }

    // 3. OkHttp Bypass
    safeUse("okhttp3.CertificatePinner", function(Pinner) {
        Pinner.check.overload('java.lang.String', 'java.util.List')
        .implementation = function() {
            log("[√] OkHttp pinning bypassed");
        };
    });
}

function bypassAntiTamper() {
    // 1. Debug Detection
    safeUse("android.os.Debug", function(Debug) {
        Debug.isDebuggerConnected.implementation = function() {
            log("[√] Debug check bypassed");
            return false;
        };
    });

    // 2. Security Providers
    config.securityClasses.forEach(function(className) {
        safeUse(className, function(Security) {
            ["isTampered", "isHookDetected"].forEach(function(method) {
                if (Security[method]) {
                    Security[method].implementation = function() {
                        log("[√] Bypassed: " + method);
                        return false;
                    };
                }
            });
        });
    });
}

// ========================
// MAIN EXECUTION FLOW
// ========================
Java.perform(function() {
    log("=== Starting SecurityBong Android Universal Bypass ===");
    
    // 1. Immediate bypass attempts
    bypassRootDetection();
    bypassSSLPinning();
    bypassAntiTamper();
    
    // 2. Continuous library monitoring
    config.targetLibs.forEach(function(lib) {
        hookWhenAvailable(lib);
    });
    
    // 3. Periodic retry mechanism
    setInterval(function() {
        log("[↻] Running periodic bypass checks");
        bypassRootDetection();
        bypassSSLPinning();
    }, 10000); // Retry every 10 seconds
    
    log("[√] Bypass system active");
});

// Ensure Frida compatibility
if (typeof send === 'undefined') {
    var send = console.log;
}
