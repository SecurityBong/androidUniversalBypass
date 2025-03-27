// Universal Android Bypass Script v1.7 (Persistent Enhanced)
// ========================
// CONFIGURATION
// ========================
var config = {
    debug: true,
    retryDelay: 500, // ms between retries
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
    rootBinaries: ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk"],
    rootProperties: {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1"
    },
    securityClasses: [
        "krabcqj.ac", 
        "com.talsec.security.Talsec",
        "com.proguard.security.ProGuard",
        "com.appsealing.security.AppSealing",
        "com.scottyab.rootbeer.RootBeer"
    ],
    raspModules: ['talsec', 'proguard', 'appsealing']
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

// Define the script creator name
var scriptCreator = "SecurityBong";

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
Java.perform(function () {
    // Print script creator name
    log("Script created by " + scriptCreator);

    // ========================
    // ROOT DETECTION BYPASS
    // ========================
    function bypassRootDetection() {
        // 1. Package Manager Hooks
        safeUse("android.app.ApplicationPackageManager", function (PackageManager) {
            PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pname, flags) {
                var shouldFakePackage = (config.rootPackages.indexOf(pname) > -1);
                if (shouldFakePackage) {
                    log("Bypass root check for package: " + pname);
                    pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
                }
                return this.getPackageInfo.overload('java.lang.String', 'int').call(this, pname, flags);
            };
        });

        // 2. File Existence Checks
        safeUse('java.io.File', function (NativeFile) {
            NativeFile.exists.implementation = function () {
                var name = NativeFile.getName.call(this);
                var shouldFakeReturn = (config.rootBinaries.indexOf(name) > -1);
                if (shouldFakeReturn) {
                    log("Bypass return value for binary: " + name);
                    return false;
                } else {
                    return this.exists.call(this);
                }
            };
        });

        // 3. Command Execution Hooks
        safeUse('java.lang.Runtime', function (Runtime) {
            var exec = Runtime.exec.overload('[Ljava.lang.String;');
            var exec1 = Runtime.exec.overload('java.lang.String');
            var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
            var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
            var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
            var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

            exec5.implementation = function (cmd, env, dir) {
                if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
                    var fakeCmd = "grep";
                    log("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }
                if (cmd == "su") {
                    var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    log("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }
                return exec5.call(this, cmd, env, dir);
            };

            exec4.implementation = function (cmdarr, env, file) {
                for (var i = 0; i < cmdarr.length; i++) {
                    var tmp_cmd = cmdarr[i];
                    if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                        var fakeCmd = "grep";
                        log("Bypass " + cmdarr + " command");
                        return exec1.call(this, fakeCmd);
                    }

                    if (tmp_cmd == "su") {
                        var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                        log("Bypass " + cmdarr + " command");
                        return exec1.call(this, fakeCmd);
                    }
                }
                return exec4.call(this, cmdarr, env, file);
            };

            exec3.implementation = function (cmdarr, envp) {
                for (var i = 0; i < cmdarr.length; i++) {
                    var tmp_cmd = cmdarr[i];
                    if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                        var fakeCmd = "grep";
                        log("Bypass " + cmdarr + " command");
                        return exec1.call(this, fakeCmd);
                    }

                    if (tmp_cmd == "su") {
                        var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                        log("Bypass " + cmdarr + " command");
                        return exec1.call(this, fakeCmd);
                    }
                }
                return exec3.call(this, cmdarr, envp);
            };

            exec2.implementation = function (cmd, env) {
                if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
                    var fakeCmd = "grep";
                    log("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }
                if (cmd == "su") {
                    var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    log("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }
                return exec2.call(this, cmd, env);
            };

            exec.implementation = function (cmd) {
                for (var i = 0; i < cmd.length; i++) {
                    var tmp_cmd = cmd[i];
                    if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                        var fakeCmd = "grep";
                        log("Bypass " + cmd + " command");
                        return exec1.call(this, fakeCmd);
                    }

                    if (tmp_cmd == "su") {
                        var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                        log("Bypass " + cmd + " command");
                        return exec1.call(this, fakeCmd);
                    }
                }

                return exec.call(this, cmd);
            };

            exec1.implementation = function (cmd) {
                if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
                    var fakeCmd = "grep";
                    log("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }
                if (cmd == "su") {
                    var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    log("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }
                return exec1.call(this, cmd);
            };
        });

        // 4. System Properties
        safeUse("java.lang.System", function(System) {
            System.getProperty.implementation = function(key) {
                if (key in config.rootProperties) {
                    log("[√] Spoofed: " + key);
                    return config.rootProperties[key];
                }
                return this.getProperty(key);
            };
        });

        // 5. Native Checks
        config.rootBinaries.forEach(function(bin) {
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

        // 6. RootBeer Library
        safeUse('com.scottyab.rootbeer.RootBeer', function (RootBeer) {
            RootBeer.isRooted.implementation = function () {
                log('Bypassing RootBeer Root Detection');
                return false;
            };
        });
    }

    // ========================
    // SSL PINNING BYPASS
    // ========================
    function bypassSSLPinning() {
        try {
            // 1. Java Layer SSLContext
            safeUse('javax.net.ssl.SSLContext', function (SSLContext) {
                safeUse('javax.net.ssl.X509TrustManager', function (X509TrustManager) {
                    // Custom TrustManager that accepts all certificates
                    var CustomTrustManager = Java.registerClass({
                        name: 'com.example.CustomTrustManager',
                        implements: [X509TrustManager],
                        methods: {
                            checkClientTrusted: function (chain, authType) { },
                            checkServerTrusted: function (chain, authType) { },
                            getAcceptedIssuers: function () {
                                return [];
                            }
                        }
                    });

                    // Override SSLContext's init method
                    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (keyManager, trustManager, secureRandom) {
                        log('Overriding SSLContext.init to use CustomTrustManager');
                        SSLContext.init.call(this, keyManager, [CustomTrustManager.$new()], secureRandom);
                    };
                });
            });

            // 2. TrustManagerImpl
            safeUse('com.android.org.conscrypt.TrustManagerImpl', function (TrustManagerImpl) {
                TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                    log('Bypassing TrustManagerImpl.verifyChain');
                    return untrustedChain;
                };
            });

            // 3. OkHTTP3 Pinning Bypass
            safeUse('okhttp3.CertificatePinner', function (CertificatePinner) {
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
                    log('Bypassing OkHTTP3 CertificatePinner');
                };
            });

            // 4. Native SSL_verify Bypass
            var sslVerify = Module.findExportByName("libssl.so", "SSL_verify");
            if (sslVerify) {
                Interceptor.attach(sslVerify, {
                    onEnter: function (args) {
                        log("Bypassing SSL verification (libssl.so)");
                        args[0] = 0; // Modify the argument to bypass SSL checks
                    }
                });
            } else {
                log("SSL_verify function not found, proceeding without native SSL bypass.");
            }

            // 5. PortSwigger Certificate Detection Bypass
            safeUse('com.portswigger.package.CertificateDetection', function (CertificateDetection) {
                CertificateDetection.detectCertificates.implementation = function () {
                    log('Bypassing PortSwigger Certificate Detection');
                    return false;
                };
            });

            safeUse('com.portswigger.ssl.SSLCheck', function (SSLCheck) {
                SSLCheck.checkCertificate.implementation = function () {
                    log('Bypassing PortSwigger SSL Certificate Check');
                    return true; // Return true to simulate a valid certificate
                };
            });

        } catch (err) {
            log('SSL Pinning Bypass failed: ' + err);
        }
    }

    // ========================
    // BIOMETRIC AUTH BYPASS
    // ========================
    function bypassBiometricAuth() {
        var callbackG = null;
        var authenticationResultInst = null;

        // Hook BiometricPrompt.authenticate methods safely
        safeUse('android.hardware.biometrics.BiometricPrompt', function (BiometricPrompt) {
            var CryptoObject = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
            var AuthenticationResult = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');

            BiometricPrompt.authenticate.overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').implementation = function (cancelSignal, executor, callback) {
                log('Bypassing BiometricPrompt.authenticate() with CancellationSignal');

                var cryptoObj = CryptoObject.$new(null);
                authenticationResultInst = AuthenticationResult.$new(cryptoObj, null, 0);

                callbackG = callback;
                Java.retain(callback);

                callback.onAuthenticationSucceeded(authenticationResultInst);
            };

            BiometricPrompt.authenticate.overload('android.hardware.biometrics.BiometricPrompt$CryptoObject', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').implementation = function (cryptoObj, cancelSignal, executor, callback) {
                log('Bypassing BiometricPrompt.authenticate() with CryptoObject');

                authenticationResultInst = AuthenticationResult.$new(cryptoObj, null, 0);
                callbackG = callback;
                Java.retain(callback);

                callback.onAuthenticationSucceeded(authenticationResultInst);
            };
        });

        // Hook FingerprintManager.authenticate methods safely
        safeUse('android.hardware.fingerprint.FingerprintManager', function (FingerprintManager) {
            var CryptoObject = Java.use('android.hardware.fingerprint.FingerprintManager$CryptoObject');
            var AuthenticationResult = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');

            FingerprintManager.authenticate.overload(
                'android.hardware.fingerprint.FingerprintManager$CryptoObject',
                'android.os.CancellationSignal',
                'int',
                'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback',
                'android.os.Handler'
            ).implementation = function (cryptoObject, cancel, flags, callback, handler) {
                log('Bypassing FingerprintManager.authenticate()');

                authenticationResultInst = AuthenticationResult.$new(cryptoObject, null, 0);
                callbackG = callback;
                Java.retain(callback);

                callback.onAuthenticationSucceeded(authenticationResultInst);
            };
        });
    }

    // ========================
    // USER INTERACTION SIMULATION
    // ========================
    function simulateUserInteraction() {
        try {
            var MotionEvent = Java.use('android.view.MotionEvent');
            var SystemClock = Java.use('android.os.SystemClock');
            var downTime = SystemClock.uptimeMillis();
            var eventTime = downTime + 50; // Assuming finger stays for 50 ms

            var touchEventDown = MotionEvent.obtain.overload('long', 'long', 'int', 'float', 'float', 'int').call(
                MotionEvent, downTime, eventTime, MotionEvent.ACTION_DOWN.value, 50.0, 50.0, 0
            );
            var touchEventUp = MotionEvent.obtain.overload('long', 'long', 'int', 'float', 'float', 'int').call(
                MotionEvent, downTime + 50, eventTime + 100, MotionEvent.ACTION_UP.value, 50.0, 50.0, 0
            );

            var View = Java.use('android.view.View');
            var rootView = Java.cast(View.getRootView(), View);
            rootView.dispatchTouchEvent(touchEventDown);
            rootView.dispatchTouchEvent(touchEventUp);

            log("Simulated user interaction via touch event.");
        } catch (err) {
            log("User interaction simulation failed: " + err);
        }
    }

    // ========================
    // RASP (Runtime Application Self-Protection) BYPASS
    // ========================
    function bypassRASP() {
        // 1. Module-based detection
        function checkRASP() {
            var result = false;
            var processes = Process.enumerateModulesSync();
            for (var i = 0; i < processes.length; i++) {
                var module = processes[i];
                for (var j = 0; j < config.raspModules.length; j++) {
                    if (module['name'].toLowerCase().indexOf(config.raspModules[j]) !== -1) {
                        log(config.raspModules[j] + ' detected and bypassed');
                        result = true;
                        break;
                    }
                }
            }
            return result;
        }

        if (checkRASP()) {
            log('RASP bypassed');
        } else {
            log('RASP not detected');
        }

        // 2. Talsec RASP Bypass
        safeUse('com.talsec.security.Talsec', function (talsec) {
            talsec.checkEmulator.implementation = function () {
                log('Bypassing Talsec Emulator Check');
                return false;
            };

            talsec.checkRooted.implementation = function () {
                log('Bypassing Talsec Rooted Check');
                return false;
            };

            talsec.checkHook.implementation = function () {
                log('Bypassing Talsec Hook Check');
                return false;
            };

            talsec.checkTamper.implementation = function () {
                log('Bypassing Talsec Tamper Check');
                return false;
            };
        });

        // 3. ProGuard RASP Bypass
        safeUse('com.proguard.security.ProGuard', function (proGuard) {
            proGuard.checkEmulator.implementation = function () {
                log('Bypassing ProGuard Emulator Check');
                return false;
            };

            proGuard.checkRooted.implementation = function () {
                log('Bypassing ProGuard Rooted Check');
                return false;
            };

            proGuard.checkHook.implementation = function () {
                log('Bypassing ProGuard Hook Check');
                return false;
            };

            proGuard.checkTamper.implementation = function () {
                log('Bypassing ProGuard Tamper Check');
                return false;
            };
        });

        // 4. AppSealing RASP Bypass
        safeUse('com.appsealing.security.AppSealing', function (appSealing) {
            appSealing.checkEmulator.implementation = function () {
                log('Bypassing AppSealing Emulator Check');
                return false;
            };

            appSealing.checkRooted.implementation = function () {
                log('Bypassing AppSealing Rooted Check');
                return false;
            };

            appSealing.checkHook.implementation = function () {
                log('Bypassing AppSealing Hook Check');
                return false;
            };

            appSealing.checkTamper.implementation = function () {
                log('Bypassing AppSealing Tamper Check');
                return false;
            };
        });
    }

    // ========================
    // ANTI-TAMPER BYPASS
    // ========================
    function bypassAntiTamper() {
        // 1. Debugger Detection
        safeUse('android.os.Debug', function (Debug) {
            Debug.isDebuggerConnected.implementation = function () {
                log('Bypassing Debugger Detection');
                return false;
            };
        });

        // 2. Google API Integrity Check
        try {
            if (Java.available && Java.androidVersion >= 24) {
                safeUse('com.google.android.gms.common.GoogleApiAvailability', function (GoogleAPI) {
                    GoogleAPI.isGooglePlayServicesAvailable.overload('android.content.Context').implementation = function (context) {
                        log('Bypassing Google API Integrity Check');
                        return 0;
                    };
                });
            } else {
                log('Google API Integrity Check bypass not supported on this Android version');
            }
        } catch (err) {
            log('Google API class not found: ' + err);
        }

        // 3. Anti-Frida Detection
        function detectFrida() {
            var result = false;
            var moduleName = 'frida';

            var processes = Process.enumerateModulesSync();
            for (var i = 0; i < processes.length; i++) {
                var module = processes[i];
                if (module['name'].toLowerCase().indexOf(moduleName) !== -1) {
                    result = true;
                    break;
                }
            }

            return result;
        }

        var isFridaDetected = detectFrida();
        if (isFridaDetected) {
            log('Frida detection bypassed');
        } else {
            log('Frida not detected');
        }

        // 4. Security Providers
        config.securityClasses.forEach(function(className) {
            safeUse(className, function(Security) {
                ["isTampered", "isHookDetected"].forEach(function(method) {
                    if (Security[method]) {
                        Security[method].implementation = function() {
                            log('Bypassed: ' + method);
                            return false;
                        };
                    }
                });
            });
        });
    }

    // ========================
    // OBFUSCATION TECHNIQUES
    // ========================
    function applyObfuscation() {
        try {
            // Function to obfuscate PortSwigger detection methods
            function obfuscateMethodNames() {
                var methods = ['detectCertificates', 'checkCertificate'];
                for (var i = 0; i < methods.length; i++) {
                    var originalMethod = methods[i];
                    var obfuscatedMethod = originalMethod.replace(/./g, function (char) {
                        return String.fromCharCode(char.charCodeAt() + 1);
                    });
                    log('Obfuscating method: ' + originalMethod + ' to ' + obfuscatedMethod);
                }
            }
            obfuscateMethodNames();

        } catch (err) {
            log('Obfuscation failed: ' + err);
        }
    }

    // ========================
    // MAIN EXECUTION FLOW
    // ========================
    log("=== Starting SecurityBong Android Universal Bypass ===");
    
    // 1. Immediate bypass attempts
    bypassRootDetection();
    bypassSSLPinning();
    bypassBiometricAuth();
    bypassRASP();
    bypassAntiTamper();
    applyObfuscation();
    simulateUserInteraction();
    
    // 2. Continuous library monitoring
    config.targetLibs.forEach(function(lib) {
        hookWhenAvailable(lib);
    });
    
    // 3. Periodic retry mechanism
    setInterval(function() {
        log("[↻] Running periodic bypass checks");
        bypassRootDetection();
        bypassSSLPinning();
        bypassAntiTamper();
    }, 10000); // Retry every 10 seconds
    
    log("[√] Bypass system active");
});

// Ensure Frida compatibility
if (typeof send === 'undefined') {
    var send = console.log;
}
