// Universal Android Bypass Script v1.7
// Created by SecurityBong
// Enhanced with comprehensive error handling

// Global variables and functions
var scriptCreator = "SecurityBong";

// Unified logging system with multiple fallbacks
function globalLog(message) {
    try {
        console.log(message);
    } catch (e) {
        try {
            Java.perform(function() {
                Java.use("android.util.Log").d("UniversalBypass", message);
            });
        } catch (e2) {
            try {
                send(message);
            } catch (e3) {
                // Ultimate fallback if everything fails
            }
        }
    }
}

// Main execution block
Java.perform(function () {
    // Local logging function with context-specific fallbacks
    function log(message) {
        try {
            console.log(message);
        } catch (e) {
            try {
                Java.use("android.util.Log").d("UniversalBypass", message);
            } catch (e2) {
                globalLog(message);
            }
        }
    }

    // Safe Java class usage with error handling
    function safeUse(className, callback) {
        try {
            var clazz = Java.use(className);
            callback(clazz);
            return true;
        } catch (err) {
            log("[!] Class " + className + " not present: " + err);
            return false;
        }
    }

    log("Script initialized - Universal Bypass v1.7 by " + scriptCreator);

    /* ==================== */
    /*  ROOT DETECTION BYPASS */
    /* ==================== */
    function bypassRootDetection() {
        try {
            // System property spoofing
            safeUse("java.lang.System", function(System) {
                System.getProperty.implementation = function(key) {
                    try {
                        if (key === "ro.debuggable" || key === "ro.secure") {
                            log("[+] Spoofing system property: " + key);
                            return "0";
                        }
                        return this.getProperty(key);
                    } catch (e) {
                        log("[!] Error in getProperty: " + e);
                        return this.getProperty(key);
                    }
                };
            });

            // Secure settings spoofing
            safeUse("android.provider.Settings$Secure", function(SecureSettings) {
                SecureSettings.getInt.overload("android.content.ContentResolver", "java.lang.String")
                    .implementation = function(resolver, name) {
                    try {
                        if (name === "adb_enabled") {
                            log("[+] Spoofing ADB enabled status");
                            return 0;
                        }
                        return this.getInt(resolver, name);
                    } catch (e) {
                        log("[!] Error in getInt: " + e);
                        return this.getInt(resolver, name);
                    }
                };
            });

            // Root package/binary detection bypass
            var rootPackages = [
                "com.noshufou.android.su", "eu.chainfire.supersu",
                "com.koushikdutta.superuser", "com.kingouser.com",
                "com.topjohnwu.magisk"
            ];

            var rootBinaries = ["su", "busybox", "magisk"];

            // Package manager hooks
            safeUse("android.app.ApplicationPackageManager", function(PackageManager) {
                PackageManager.getPackageInfo.overload('java.lang.String', 'int')
                    .implementation = function(pname, flags) {
                    try {
                        if (rootPackages.includes(pname)) {
                            log("[+] Bypassing root package check: " + pname);
                            pname = "com.android.vending"; // Spoof as Play Store
                        }
                        return this.getPackageInfo(pname, flags);
                    } catch (e) {
                        log("[!] Error in getPackageInfo: " + e);
                        return this.getPackageInfo(pname, flags);
                    }
                };
            });

            // File existence checks
            safeUse("java.io.File", function(NativeFile) {
                NativeFile.exists.implementation = function() {
                    try {
                        var name = this.getName();
                        if (rootBinaries.includes(name)) {
                            log("[+] Bypassing binary check: " + name);
                            return false;
                        }
                        return this.exists();
                    } catch (e) {
                        log("[!] Error in exists: " + e);
                        return this.exists();
                    }
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
                        try {
                            var cmd = arguments[0];
                            var cmdStr = Array.isArray(cmd) ? cmd.join(" ") : cmd.toString();
                            
                            if (cmdStr.includes("su") || cmdStr.includes("magisk") || 
                               cmdStr.includes("getprop") || cmdStr.includes("mount")) {
                                log("[+] Bypassing command: " + cmdStr);
                                return Runtime.getRuntime().exec("echo bypassed");
                            }
                            return exec.apply(this, arguments);
                        } catch (e) {
                            log("[!] Error in exec: " + e);
                            return exec.apply(this, arguments);
                        }
                    };
                });
            });

            log("[√] Root detection bypass complete");
        } catch (e) {
            log("[X] Root detection bypass failed: " + e);
        }
    }

    /* ==================== */
    /*  SSL PINNING BYPASS  */
    /* ==================== */
    function bypassSSLPinning() {
        try {
            // X509TrustManager bypass
            safeUse("javax.net.ssl.X509TrustManager", function(X509TrustManager) {
                X509TrustManager.checkServerTrusted.implementation = function() {
                    log("[+] Bypassing SSL certificate validation");
                };
            });

            // HostnameVerifier bypass
            safeUse("javax.net.ssl.HostnameVerifier", function(HostnameVerifier) {
                HostnameVerifier.verify.implementation = function() {
                    log("[+] Bypassing hostname verification");
                    return true;
                };
            });

            // Custom TrustManager
            try {
                var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                Java.registerClass({
                    name: 'com.example.CustomTrustManager',
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function() {},
                        checkServerTrusted: function() {},
                        getAcceptedIssuers: function() { return []; }
                    }
                });

                safeUse('javax.net.ssl.SSLContext', function(SSLContext) {
                    SSLContext.init.implementation = function() {
                        log("[+] Overriding SSLContext with custom TrustManager");
                        var CustomTrustManager = Java.use('com.example.CustomTrustManager');
                        this.init(arguments[0], [CustomTrustManager.$new()], arguments[2]);
                    };
                });
            } catch (e) {
                log("[!] Custom TrustManager failed: " + e);
            }

            // OkHTTP3 bypass
            safeUse('okhttp3.CertificatePinner', function(CertificatePinner) {
                CertificatePinner.check.overload('java.lang.String', 'java.util.List')
                    .implementation = function() {
                    log("[+] Bypassing OkHTTP certificate pinning");
                };
            });

            // Native SSL bypass
            try {
                var sslVerify = Module.findExportByName("libssl.so", "SSL_verify");
                if (sslVerify) {
                    Interceptor.attach(sslVerify, {
                        onEnter: function(args) {
                            log("[+] Bypassing native SSL verification");
                            args[0] = 0;
                        }
                    });
                }
            } catch (e) {
                log("[!] Native SSL bypass failed: " + e);
            }

            log("[√] SSL pinning bypass complete");
        } catch (e) {
            log("[X] SSL pinning bypass failed: " + e);
        }
    }

    /* ==================== */
    /*  RASP PROTECTION BYPASS */
    /* ==================== */
    function bypassRASP() {
        var raspProviders = [
            { name: 'Talsec', class: 'com.talsec.security.Talsec' },
            { name: 'RootBeer', class: 'com.scottyab.rootbeer.RootBeer' }
        ];

        try {
            // Module detection
            Process.enumerateModulesSync().forEach(function(module) {
                if (/talsec|rootbeer|appsealing/i.test(module.name)) {
                    log("[+] Detected RASP module: " + module.name);
                }
            });

            // Provider-specific bypasses
            raspProviders.forEach(function(provider) {
                safeUse(provider.class, function(clazz) {
                    if (clazz.isRooted) {
                        clazz.isRooted.implementation = function() {
                            log("[+] Bypassing " + provider.name + " root check");
                            return false;
                        };
                    }
                    if (clazz.checkHook) {
                        clazz.checkHook.implementation = function() {
                            log("[+] Bypassing " + provider.name + " hook detection");
                            return false;
                        };
                    }
                });
            });

            log("[√] RASP protection bypass complete");
        } catch (e) {
            log("[X] RASP bypass failed: " + e);
        }
    }

    /* ==================== */
    /*  MAIN EXECUTION FLOW */
    /* ==================== */
    try {
        log("[*] Starting bypass procedures...");
        bypassRootDetection();
        bypassSSLPinning();
        bypassRASP();
        log("[√] All bypass procedures completed successfully");
    } catch (e) {
        log("[X] Critical error in main execution: " + e);
    }
});

// Global send function for Frida compatibility
function send(message) {
    try {
        console.log(message);
    } catch (e) {
        try {
            Java.perform(function() {
                Java.use("android.util.Log").d("UniversalBypass", message);
            });
        } catch (e2) {
            // Final fallback
        }
    }
}
