// Universal Android Bypass Script v1.7
// Complete Protection Bypass Solution
// Includes: Root, SSL Pinning, RASP, Memory Protection, and SIGBUS fixes

// ========================
// GLOBAL CONFIGURATION
// ========================
var config = {
    debugMode: true,
    targetLibs: ["libpairipcore.so", "libssl.so", "libtoolchecker.so"],
    rootPackages: [
        "com.noshufou.android.su", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.kingouser.com",
        "com.topjohnwu.magisk"
    ],
    securityClasses: [
        "krabcqj.ac",  // IndusInd specific
        "com.talsec.security.Talsec",
        "com.appsealing.security.AppSealing"
    ],
    memoryPatches: {
        "libpairipcore.so": {
            "sigbusOffsets": [0x28ffc], // From your crash log
            "integrityChecks": ["0x12345"] // Example checks
        }
    }
};

// ========================
// ROBUST LOGGING SYSTEM
// ========================
var logger = {
    log: function(message) {
        if (!config.debugMode) return;
        
        try {
            // Try Frida's send first
            if (typeof send !== 'undefined') {
                send(message);
                return;
            }
        } catch (e) {}
        
        try {
            // Fallback to console
            console.log(message);
        } catch (e) {
            try {
                // Final fallback to Android log
                Java.perform(function() {
                    Java.use("android.util.Log").d("Bypass", message);
                });
            } catch (e) {}
        }
    }
};

// ========================
// CORE UTILITY FUNCTIONS
// ========================
function safeUse(className, callback) {
    try {
        var clazz = Java.use(className);
        callback(clazz);
        return true;
    } catch (err) {
        logger.log("[!] Class not found: " + className);
        return false;
    }
}

function hookAllExports(libName) {
    try {
        var base = Module.findBaseAddress(libName);
        if (!base) {
            logger.log("[!] Library not loaded: " + libName);
            return false;
        }

        Module.enumerateExports(libName).forEach(function(exp) {
            try {
                Interceptor.attach(exp.address, {
                    onEnter: function(args) {
                        logger.log("[→] Called " + exp.name);
                    }
                });
            } catch (e) {
                logger.log("[!] Failed to hook " + exp.name);
            }
        });
        return true;
    } catch (e) {
        logger.log("[X] Error hooking " + libName);
        return false;
    }
}

// ========================
// MEMORY PROTECTION SYSTEM
// ========================
function handleMemoryProtection() {
    // Patch SIGBUS crashes
    function patchSIGBUS() {
        Object.keys(config.memoryPatches).forEach(function(lib) {
            var base = Module.findBaseAddress(lib);
            if (!base) return;

            config.memoryPatches[lib].sigbusOffsets.forEach(function(offset) {
                try {
                    var addr = base.add(offset);
                    Memory.protect(addr, 4, 'rwx');
                    Memory.patchCode(addr, 4, function(code) {
                        code.writeU32(0xD503201F); // ARM64 NOP
                        logger.log("[√] Patched SIGBUS at " + addr);
                    });
                } catch (e) {
                    logger.log("[!] SIGBUS patch failed: " + e);
                }
            });
        });
    }

    // Fix memory alignment
    function fixMemoryAlignment() {
        ['memcpy', 'memmove'].forEach(function(func) {
            var funcAddr = Module.findExportByName(null, func);
            if (funcAddr) {
                Interceptor.attach(funcAddr, {
                    onEnter: function(args) {
                        if (args[0].toInt32() % 8 !== 0 || args[1].toInt32() % 8 !== 0) {
                            args[0] = args[0].and(ptr(~0x7));
                            args[1] = args[1].and(ptr(~0x7));
                            logger.log("[↻] Fixed alignment in " + func);
                        }
                    }
                });
            }
        });
    }

    patchSIGBUS();
    fixMemoryAlignment();
}

// ========================
// BYPASS IMPLEMENTATIONS
// ========================
function bypassRootDetection() {
    // System property spoofing
    safeUse("java.lang.System", function(System) {
        System.getProperty.implementation = function(key) {
            if (key === "ro.debuggable" || key === "ro.secure") {
                logger.log("[√] Spoofed property: " + key);
                return "0";
            }
            return this.getProperty(key);
        };
    });

    // Package manager hooks
    safeUse("android.app.ApplicationPackageManager", function(PackageManager) {
        PackageManager.getPackageInfo.overload('java.lang.String', 'int')
        .implementation = function(pname, flags) {
            if (config.rootPackages.includes(pname)) {
                logger.log("[√] Bypassed package: " + pname);
                pname = "com.android.vending";
            }
            return this.getPackageInfo(pname, flags);
        };
    });
}

function bypassSSLPinning() {
    // Java-layer bypass
    safeUse("javax.net.ssl.X509TrustManager", function(X509TrustManager) {
        X509TrustManager.checkServerTrusted.implementation = function() {
            logger.log("[√] Bypassed SSL validation");
        };
    });

    // Native-layer bypass
    var sslVerify = Module.findExportByName("libssl.so", "SSL_verify");
    if (sslVerify) {
        Interceptor.attach(sslVerify, {
            onEnter: function(args) {
                logger.log("[√] Bypassed native SSL");
                args[0] = 0;
            }
        });
    }
}

function bypassRASP() {
    // Security provider bypass
    config.securityClasses.forEach(function(className) {
        safeUse(className, function(clazz) {
            ['isRooted', 'isHookDetected', 'isTampered'].forEach(function(method) {
                if (clazz[method]) {
                    clazz[method].implementation = function() {
                        logger.log("[√] Bypassed " + className + "." + method);
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
    logger.log("=== Starting SecurityBong Android Universal Bypass ===");
    
    try {
        // 1. Memory protection first
        handleMemoryProtection();
        
        // 2. Security bypasses
        bypassRootDetection();
        bypassSSLPinning();
        bypassRASP();
        
        // 3. Install hooks
        config.targetLibs.forEach(function(lib) {
            hookAllExports(lib);
        });
        
        logger.log("[√] All protections bypassed");
    } catch (e) {
        logger.log("[X] Critical error: " + e);
    }
});

// Frida compatibility
if (typeof send === 'undefined') {
    var send = console.log;
}
