// Universal Android Bypass Script v1.7
// Enhanced with immediate execution and comprehensive protection

// ========================
// CONFIGURATION
// ========================
var config = {
    debug: true,
    retryDelay: 300,
    targetLibs: ["libssl.so", "libtoolchecker.so", "librootcheck.so"],
    rootPackages: [
        "com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su",
        "com.koushikdutta.rommanager", "com.koushikdutta.rommanager.license",
        "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro",
        "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate",
        "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium",
        "com.formyhm.hideroot", "me.phh.superuser", "eu.chainfire.supersu.pro",
        "com.kingouser.com", "com.topjohnwu.magisk"
    ],
    rootBinaries: ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk"],
    rootProperties: {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1"
    },
    securityProviders: [
        "com.talsec.security.Talsec",
        "com.proguard.security.ProGuard",
        "com.appsealing.security.AppSealing",
        "com.scottyab.rootbeer.RootBeer"
    ],
    sensitiveCommands: ["getprop", "mount", "build.prop", "id", "sh", "su", "which", "pm", "am"]
};

// ========================
// ENHANCED LOGGER
// ========================
function log(message, level = "INFO") {
    try {
        var timestamp = new Date().toISOString();
        var logMsg = `[${timestamp}] [${level}] ${message}`;
        
        // Try Frida's send first
        if (typeof send !== 'undefined') {
            send(logMsg);
            return;
        }
        
        // Fallback to console
        if (typeof console !== 'undefined') {
            switch(level) {
                case "ERROR": console.error(logMsg); break;
                case "WARN": console.warn(logMsg); break;
                case "DEBUG": console.debug(logMsg); break;
                default: console.log(logMsg);
            }
            return;
        }
        
        // Final fallback to Android log
        Java.perform(function() {
            Java.use("android.util.Log").d("BYPASS", logMsg);
        });
    } catch (e) {
        // If everything fails
        print(logMsg);
    }
}

// ========================
// CORE BYPASS FUNCTIONS
// ========================
function applyRootBypasses() {
    log("Applying root detection bypasses", "DEBUG");
    
    // 1. Package Manager Bypass
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
        if (config.rootPackages.includes(pname)) {
            log(`Bypassed package check: ${pname}`, "SUCCESS");
            throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
        }
        return this.getPackageInfo(pname, flags);
    };

    // 2. File Existence Checks
    var NativeFile = Java.use('java.io.File');
    NativeFile.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (config.rootBinaries.some(bin => path.includes(bin))) {
            log(`Bypassed file check: ${path}`, "SUCCESS");
            return false;
        }
        return this.exists.call(this);
    };

    // 3. System Property Spoofing
    safeUse("android.os.SystemProperties", function(SystemProperties) {
        SystemProperties.get.overload('java.lang.String').implementation = function(key) {
            if (key in config.rootProperties) {
                log(`Spoofed system property: ${key}`, "SUCCESS");
                return config.rootProperties[key];
            }
            return this.get(key);
        };
    });

    // 4. Runtime.exec Command Bypass (All Overloads)
    var Runtime = Java.use('java.lang.Runtime');
    var execOverloads = [
        Runtime.exec.overload('[Ljava.lang.String;'),
        Runtime.exec.overload('java.lang.String'),
        Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;'),
        Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;'),
        Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File'),
        Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File')
    ];

    execOverloads.forEach(function(exec) {
        exec.implementation = function() {
            var cmd = arguments[0];
            var cmdStr = Array.isArray(cmd) ? cmd.join(' ') : cmd.toString();
            
            if (config.sensitiveCommands.some(c => cmdStr.includes(c))) {
                log(`Bypassed command execution: ${cmdStr}`, "SUCCESS");
                throw Java.use('java.io.IOException').$new("Command not found");
            }
            return exec.apply(this, arguments);
        };
    });

    // 5. Native fopen Hook for Binary Detection
    var fopen = Module.findExportByName(null, "fopen");
    if (fopen) {
        Interceptor.attach(fopen, {
            onEnter: function(args) {
                var path = args[0].readCString();
                if (path && config.rootBinaries.some(bin => path.includes(bin))) {
                    log(`Blocked native access to: ${path}`, "SUCCESS");
                    args[0] = Memory.allocUtf8String("/dev/null");
                }
            }
        });
    }
}

function applySSLBypasses() {
    log("Applying SSL pinning bypasses", "DEBUG");
    
    try {
        // 1. Java SSLContext Bypass
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        
        var CustomTrustManager = Java.registerClass({
            name: 'com.security.bypass.CustomTrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function() { log("Bypassed client cert check", "SUCCESS"); },
                checkServerTrusted: function() { log("Bypassed server cert check", "SUCCESS"); },
                getAcceptedIssuers: function() { return []; }
            }
        });
        
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
            .implementation = function(km, tm, sr) {
                log("Overriding SSLContext with custom TrustManager", "SUCCESS");
                return this.init(km, [CustomTrustManager.$new()], sr);
            };
        
        // 2. OkHttp CertificatePinner Bypass
        safeUse('okhttp3.CertificatePinner', function(CertificatePinner) {
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
                log("Bypassed OkHttp certificate pinning", "SUCCESS");
            };
        });
        
        // 3. Native SSL Verification Bypass
        var sslVerify = Module.findExportByName("libssl.so", "SSL_verify");
        if (sslVerify) {
            Interceptor.attach(sslVerify, {
                onEnter: function(args) {
                    log("Bypassing native SSL verification", "SUCCESS");
                    args[0] = 0;
                }
            });
        }
        
    } catch (e) {
        log(`SSL bypass failed: ${e}`, "ERROR");
    }
}

function applyBiometricBypasses() {
    log("Applying biometric authentication bypasses", "DEBUG");
    
    try {
        // 1. BiometricPrompt Bypass
        safeUse('android.hardware.biometrics.BiometricPrompt', function(BiometricPrompt) {
            var AuthResult = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
            
            BiometricPrompt.authenticate.overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback')
                .implementation = function(cs, ex, cb) {
                    log("Bypassed BiometricPrompt authentication", "SUCCESS");
                    var result = AuthResult.$new(null, null, 0);
                    cb.onAuthenticationSucceeded(result);
                };
        });
        
        // 2. FingerprintManager Bypass
        safeUse('android.hardware.fingerprint.FingerprintManager', function(FingerprintManager) {
            var AuthResult = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
            
            FingerprintManager.authenticate.overload(
                'android.hardware.fingerprint.FingerprintManager$CryptoObject',
                'android.os.CancellationSignal',
                'int',
                'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback',
                'android.os.Handler'
            ).implementation = function(co, cs, flags, cb, handler) {
                log("Bypassed FingerprintManager authentication", "SUCCESS");
                var result = AuthResult.$new(co, null, 0);
                cb.onAuthenticationSucceeded(result);
            };
        });
        
    } catch (e) {
        log(`Biometric bypass failed: ${e}`, "ERROR");
    }
}

function applyAntiTamperBypasses() {
    log("Applying anti-tamper bypasses", "DEBUG");
    
    // 1. Debugger Detection Bypass
    safeUse('android.os.Debug', function(Debug) {
        Debug.isDebuggerConnected.implementation = function() {
            log("Bypassed debugger detection", "SUCCESS");
            return false;
        };
    });
    
    // 2. Google Play Integrity Bypass
    safeUse('com.google.android.gms.common.GoogleApiAvailability', function(GoogleAPI) {
        GoogleAPI.isGooglePlayServicesAvailable.overload('android.content.Context').implementation = function(ctx) {
            log("Bypassed Google Play Integrity check", "SUCCESS");
            return 0; // SUCCESS
        };
    });
    
    // 3. Security Provider Bypasses
    config.securityProviders.forEach(function(provider) {
        safeUse(provider, function(Security) {
            var methods = ['isRooted', 'isTampered', 'isHookDetected', 'isDebugged'];
            methods.forEach(function(method) {
                if (Security[method]) {
                    Security[method].implementation = function() {
                        log(`Bypassed ${provider}.${method}()`, "SUCCESS");
                        return false;
                    };
                }
            });
        });
    });
}

// ========================
// UTILITY FUNCTIONS
// ========================
function safeUse(className, callback) {
    try {
        var clazz = Java.use(className);
        callback(clazz);
        return true;
    } catch (e) {
        log(`Class ${className} not found: ${e}`, "DEBUG");
        return false;
    }
}

function hookWhenAvailable(libName, callback, retries = 5) {
    var tries = 0;
    var interval = setInterval(function() {
        try {
            var base = Module.findBaseAddress(libName);
            if (base) {
                clearInterval(interval);
                log(`Library ${libName} loaded, applying hooks`, "DEBUG");
                callback(base);
            } else if (tries++ >= retries) {
                clearInterval(interval);
                log(`Library ${libName} not found after ${retries} attempts`, "WARN");
            }
        } catch (e) {
            log(`Error checking for ${libName}: ${e}`, "ERROR");
        }
    }, config.retryDelay);
}

// ========================
// MAIN EXECUTION
// ========================
Java.perform(function() {
    log("=== Starting Universal Bypass ===", "INFO");
    
    // 1. Apply all critical bypasses immediately
    applyRootBypasses();
    applySSLBypasses();
    applyBiometricBypasses();
    applyAntiTamperBypasses();
    
    // 2. Set up library monitoring
    config.targetLibs.forEach(function(lib) {
        hookWhenAvailable(lib, function(base) {
            // Apply specific native hooks when library loads
            if (lib.includes("ssl")) {
                var sslVerify = Module.findExportByName(lib, "SSL_verify");
                if (sslVerify) {
                    Interceptor.attach(sslVerify, {
                        onEnter: function(args) {
                            args[0] = 0; // Force success
                        }
                    });
                }
            }
        });
    });
    
    // 3. Set up periodic verification
    setInterval(function() {
        log("=== Verifying Bypass Integrity ===", "DEBUG");
        
        // Verify root bypasses
        try {
            if (!Java.use("android.app.ApplicationPackageManager").getPackageInfo.overload('java.lang.String', 'int').implementation) {
                log("Root package bypass missing! Reapplying...", "WARN");
                applyRootBypasses();
            }
        } catch (e) {}
        
        // Verify SSL bypasses
        try {
            if (!Java.use('javax.net.ssl.SSLContext').init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation) {
                log("SSL bypass missing! Reapplying...", "WARN");
                applySSLBypasses();
            }
        } catch (e) {}
        
    }, 10000); // Check every 10 seconds
    
    log("=== Bypass System Active ===", "SUCCESS");
});

// Fallback for Frida compatibility
if (typeof send === 'undefined') {
    var send = console.log;
}
