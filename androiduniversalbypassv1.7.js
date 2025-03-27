// Universal Android Bypass Script v1.7
// Created by SecurityBong
// Enhanced with comprehensive error handling

var config = {
    debugMode: true,
    targetLibs: ["libpairipcore.so", "libssl.so"],
    rootPackages: [
        "com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"
    ],
    rootBinaries: ["su", "busybox", "magisk"]
};

// ========================
// LOGGING SYSTEM
// ========================
var logger = (function() {
    function logToConsole(message) {
        console.log(message);
    }
    
    function logToAndroid(message) {
        Java.perform(function() {
            Java.use("android.util.Log").d("UniversalBypass", message);
        });
    }
    
    function logToFrida(message) {
        try {
            if (typeof send !== 'undefined') {
                send(message);
                return true;
            }
            return false;
        } catch (e) {
            return false;
        }
    }
    
    return {
        log: function(message) {
            try {
                if (config.debugMode) {
                    if (!logToFrida(message)) {
                        if (!logToConsole(message)) {
                            logToAndroid(message);
                        }
                    }
                }
            } catch (e) {
                // Last resort
                console.log("[FALLBACK] " + message);
            }
        }
    };
})();

// ========================
// UTILITY FUNCTIONS
// ========================
function safeUse(className, callback) {
    try {
        var clazz = Java.use(className);
        callback(clazz);
        return true;
    } catch (err) {
        logger.log("[!] Class " + className + " not present: " + err);
        return false;
    }
}

function hookAllExports(libName) {
    try {
        var moduleBase = Module.findBaseAddress(libName);
        if (!moduleBase) {
            logger.log("[!] Library not loaded: " + libName);
            return false;
        }

        Module.enumerateExports(libName).forEach(function(exp) {
            if (exp.type === 'function') {
                try {
                    Interceptor.attach(exp.address, {
                        onEnter: function(args) {
                            logger.log("[+] Called " + exp.name + " in " + libName);
                        },
                        onLeave: function(retval) {
                            // Optional return value logging
                        }
                    });
                } catch (e) {
                    logger.log("[!] Failed to hook " + exp.name + ": " + e);
                }
            }
        });
        return true;
    } catch (e) {
        logger.log("[X] Error hooking exports for " + libName + ": " + e);
        return false;
    }
}

// ========================
// MAIN BYPASS FUNCTIONS
// ========================
function bypassRootDetection() {
    // System property spoofing
    safeUse("java.lang.System", function(System) {
        System.getProperty.implementation = function(key) {
            if (key === "ro.debuggable" || key === "ro.secure") {
                logger.log("[+] Spoofing property: " + key);
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
                logger.log("[+] Bypassing package check: " + pname);
                pname = "com.android.vending"; // Spoof as Play Store
            }
            return this.getPackageInfo(pname, flags);
        };
    });

    // Command execution hooks
    safeUse("java.lang.Runtime", function(Runtime) {
        var execOverloads = [
            Runtime.exec.overload('[Ljava.lang.String;'),
            Runtime.exec.overload('java.lang.String')
        ];

        execOverloads.forEach(function(exec) {
            exec.implementation = function() {
                var cmd = arguments[0];
                var cmdStr = Array.isArray(cmd) ? cmd.join(" ") : cmd.toString();
                
                if (/su|magisk|getprop|mount/.test(cmdStr)) {
                    logger.log("[+] Bypassing command: " + cmdStr);
                    return Runtime.getRuntime().exec("echo bypassed");
                }
                return exec.apply(this, arguments);
            };
        });
    });

    logger.log("[√] Root detection bypass complete");
}

function bypassSSLPinning() {
    // Java-layer bypass
    safeUse("javax.net.ssl.X509TrustManager", function(X509TrustManager) {
        X509TrustManager.checkServerTrusted.implementation = function() {
            logger.log("[+] Bypassing SSL validation");
        };
    });

    // Native-layer bypass
    config.targetLibs.forEach(function(lib) {
        if (lib === "libssl.so") {
            var sslVerify = Module.findExportByName(lib, "SSL_verify");
            if (sslVerify) {
                Interceptor.attach(sslVerify, {
                    onEnter: function(args) {
                        logger.log("[+] Bypassing native SSL");
                        args[0] = 0;
                    }
                });
            }
        }
    });

    logger.log("[√] SSL pinning bypass complete");
}

function bypassRASP() {
    var raspProviders = [
        { name: 'Talsec', class: 'com.talsec.security.Talsec' },
        { name: 'RootBeer', class: 'com.scottyab.rootbeer.RootBeer' }
    ];

    // Module detection
    Process.enumerateModulesSync().forEach(function(module) {
        if (/talsec|rootbeer|appsealing/i.test(module.name)) {
            logger.log("[+] Detected RASP: " + module.name);
        }
    });

    // Provider bypasses
    raspProviders.forEach(function(provider) {
        safeUse(provider.class, function(clazz) {
            ['isRooted', 'checkHook', 'checkEmulator'].forEach(function(method) {
                if (clazz[method]) {
                    clazz[method].implementation = function() {
                        logger.log("[+] Bypassing " + provider.name + " " + method);
                        return false;
                    };
                }
            });
        });
    });

    logger.log("[√] RASP protection bypass complete");
}

// ========================
// SCRIPT INITIALIZATION
// ========================
Java.perform(function() {
    logger.log("=== SecurityBong Android Universal Bypass Starting ===");
    
    try {
        bypassRootDetection();
        bypassSSLPinning();
        bypassRASP();
        
        // Hook target libraries
        config.targetLibs.forEach(function(lib) {
            if (hookAllExports(lib)) {
                logger.log("[√] Hooks installed for " + lib);
            }
        });
        
        logger.log("[√] All bypasses completed successfully");
    } catch (e) {
        logger.log("[X] Critical error: " + e);
    }
});

// ========================
// FRIDA COMPATIBILITY
// ========================
if (typeof send === 'undefined') {
    // Provide dummy send if not in Frida
    var send = function(message) {
        console.log("[FRIDA] " + message);
    };
}
