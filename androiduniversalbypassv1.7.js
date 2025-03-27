// Universal Android Bypass Script v1.7

// ========================
// GLOBAL CONFIGURATION
// ========================
var config = {
    debugMode: true,
    targetLibs: ["libpairipcore.so", "libssl.so", "libtoolchecker.so"],
    rootPackages: [
        "com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"
    ],
    securityClasses: [
        "krabcqj.ac",  
        "com.talsec.security.Talsec",
        "com.appsealing.security.AppSealing"
    ]
};

// ========================
// LOGGING SYSTEM
// ========================
var logger = (function() {
    var logMethods = [];
    
    // Try to initialize Frida send first
    try {
        if (typeof send !== 'undefined') {
            logMethods.push(function(msg) { send(msg); });
        }
    } catch (e) {}
    
    // Then console
    try {
        logMethods.push(function(msg) { console.log(msg); });
    } catch (e) {}
    
    // Finally Android log
    try {
        Java.perform(function() {
            var AndroidLog = Java.use("android.util.Log");
            logMethods.push(function(msg) { 
                AndroidLog.d("UniversalBypass", msg); 
            });
        });
    } catch (e) {}
    
    return {
        log: function(message) {
            if (!config.debugMode) return;
            
            var logged = false;
            for (var i = 0; i < logMethods.length; i++) {
                try {
                    logMethods[i](message);
                    logged = true;
                    break;
                } catch (e) {}
            }
            
            if (!logged) {
                // Ultimate fallback
                (function(){}).constructor("console.log('" + message + "')")();
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
                            // Modify return values if needed
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
// BYPASS IMPLEMENTATIONS
// ========================

// 1. APPLICATION CONTEXT BYPASS
function bypassAppContextChecks() {
    // Generic Application class bypass
    safeUse('android.app.Application', function(Application) {
        Application.attachBaseContext.implementation = function(context) {
            logger.log("[+] Bypassing attachBaseContext security");
            try {
                return this.attachBaseContext(context);
            } catch (e) {
                logger.log("[!] Error in attachBaseContext: " + e);
            }
        };
    });

    // Bank specific bypass
    config.securityClasses.forEach(function(className) {
        safeUse(className, function(securityClass) {
            // Hook all methods starting with 'a' (common obfuscation pattern)
            securityClass.class.getDeclaredMethods().forEach(function(method) {
                if (method.getName().startsWith('a')) {
                    method.setAccessible(true);
                    securityClass[method.getName()].implementation = function() {
                        logger.log("[+] Bypassing " + className + "." + method.getName());
                        return true; // Or appropriate return value
                    };
                }
            });
        });
    });
}

// 2. ROOT DETECTION BYPASS
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
}

// 3. SSL PINNING BYPASS
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
}

// 4. RASP & ANTI-TAMPER BYPASS
function bypassRASP() {
    // Module detection bypass
    Process.enumerateModulesSync().forEach(function(module) {
        if (/talsec|security|sealing|toolchecker/i.test(module.name)) {
            logger.log("[+] Found security module: " + module.name);
            
            // Patch common security checks
            var patterns = {
                "isDebugged": "B8 00 00 00 00 C3",  // mov eax, 0; ret
                "isHooked": "B8 00 00 00 00 C3"
            };
            
            for (var pattern in patterns) {
                var matches = Memory.scanSync(module.base, module.size, pattern);
                matches.forEach(function(match) {
                    Memory.patchCode(match.address, 6, function(code) {
                        code.writeByteArray(patterns[pattern].split(' ').map(function(x) {
                            return parseInt(x, 16);
                        }));
                    });
                });
            }
        }
    });
}

// ========================
// MAIN EXECUTION
// ========================
Java.perform(function() {
    logger.log("=== Starting Universal Bypass v2.1 ===");
    
    try {
        // 1. First bypass application context checks (critical for IndusInd)
        bypassAppContextChecks();
        
        // 2. Standard bypasses
        bypassRootDetection();
        bypassSSLPinning();
        bypassRASP();
        
        // 3. Hook target libraries
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
