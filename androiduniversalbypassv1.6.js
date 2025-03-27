// Define the script creator name
var scriptCreator = "SecurityBong";

// Enhanced logging system with error handling
function log(message) {
    try {
        console.log(message);
    } catch (e) {
        try {
            Java.perform(function() {
                Java.use("android.util.Log").d("UniversalBypass", message);
            });
        } catch (e2) {
            // Ultimate fallback if all logging fails
            send(message);
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

// Main execution
Java.perform(function () {
    log("Script created by " + scriptCreator);
    log("[+] Starting Universal Bypass v1.7");

    // --------------------- Root Detection Bypass ---------------------
    function bypassRootDetection() {
        try {
            // System property checks
            var System = Java.use("java.lang.System");
            System.getProperty.implementation = function (key) {
                try {
                    if (key === "ro.debuggable" || key === "ro.secure") {
                        log("[+] Root detection bypassed for " + key);
                        return "0";
                    }
                    return this.getProperty(key);
                } catch (e) {
                    log("[!] Error in System.getProperty: " + e);
                    return this.getProperty(key);
                }
            };
            log("[+] System property checks bypassed");
        } catch (e) {
            log("[!] Root detection bypass failed: " + e);
        }

        try {
            // Secure settings checks
            var SecureSettings = Java.use("android.provider.Settings$Secure");
            SecureSettings.getInt.overload("android.content.ContentResolver", "java.lang.String").implementation = function (resolver, name) {
                try {
                    if (name === "adb_enabled") {
                        log("[+] ADB detection bypassed");
                        return 0;
                    }
                    return this.getInt(resolver, name);
                } catch (e) {
                    log("[!] Error in SecureSettings.getInt: " + e);
                    return this.getInt(resolver, name);
                }
            };
            log("[+] Secure settings checks bypassed");
        } catch (e) {
            log("[!] Secure settings bypass failed: " + e);
        }

        // Enhanced root package/binary detection bypass
        try {
            var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
                "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
                "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
                "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
                "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
                "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
                "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"
            ];

            var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk"];

            // Package manager hooks
            safeUse("android.app.ApplicationPackageManager", function(PackageManager) {
                PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pname, flags) {
                    try {
                        if (RootPackages.indexOf(pname) > -1) {
                            log("[+] Bypass root check for package: " + pname);
                            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
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
                NativeFile.exists.implementation = function () {
                    try {
                        var name = this.getName();
                        if (RootBinaries.indexOf(name) > -1) {
                            log("[+] Bypass return value for binary: " + name);
                            return false;
                        }
                        return this.exists();
                    } catch (e) {
                        log("[!] Error in File.exists: " + e);
                        return this.exists();
                    }
                };
            });

            // Command execution hooks
            safeUse("java.lang.Runtime", function(Runtime) {
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
                        try {
                            var cmd = arguments[0];
                            var cmdStr = Array.isArray(cmd) ? cmd.join(" ") : cmd.toString();
                            
                            if (cmdStr.indexOf("getprop") != -1 || cmdStr.indexOf("mount") != -1 || 
                                cmdStr.indexOf("build.prop") != -1 || cmdStr === "id" || 
                                cmdStr === "sh" || cmdStr === "su") {
                                log("[+] Bypassing command: " + cmdStr);
                                return Runtime.getRuntime().exec("echo");
                            }
                            return exec.apply(this, arguments);
                        } catch (e) {
                            log("[!] Error in exec hook: " + e);
                            return exec.apply(this, arguments);
                        }
                    };
                });
            });

            log("[+] Root package/binary checks bypassed");
        } catch (e) {
            log("[!] Root package/binary bypass failed: " + e);
        }
    }
    bypassRootDetection();

    // --------------------- SSL Pinning Bypass ---------------------
    function bypassSSLPinning() {
        try {
            // X509TrustManager bypass
            safeUse("javax.net.ssl.X509TrustManager", function(X509TrustManager) {
                X509TrustManager.checkServerTrusted.implementation = function (chain, authType) {
                    log("[+] SSL Pinning bypassed");
                };
            });

            // HostnameVerifier bypass
            safeUse("javax.net.ssl.HostnameVerifier", function(HostnameVerifier) {
                HostnameVerifier.verify.implementation = function (hostname, session) {
                    log("[+] Hostname verification bypassed for: " + hostname);
                    return true;
                };
            });

            // Custom TrustManager implementation
            try {
                var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                var CustomTrustManager = Java.registerClass({
                    name: 'com.example.CustomTrustManager',
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function (chain, authType) {},
                        checkServerTrusted: function (chain, authType) {},
                        getAcceptedIssuers: function () { return []; }
                    }
                });

                safeUse('javax.net.ssl.SSLContext', function(SSLContext) {
                    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (keyManager, trustManager, secureRandom) {
                        log('[+] Overriding SSLContext.init with CustomTrustManager');
                        SSLContext.init.call(this, keyManager, [CustomTrustManager.$new()], secureRandom);
                    };
                });

                // OkHTTP3 bypass
                safeUse('okhttp3.CertificatePinner', function (CertificatePinner) {
                    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
                        log('[+] Bypassing OkHTTP3 CertificatePinner');
                    };
                });
            } catch (e) {
                log("[!] Custom TrustManager setup failed: " + e);
            }

            // Native SSL verification bypass
            try {
                var SSL_verify = Module.findExportByName("libssl.so", "SSL_verify");
                if (SSL_verify) {
                    Interceptor.attach(SSL_verify, {
                        onEnter: function (args) {
                            log("[+] Bypassing native SSL verification");
                            args[0] = 0;
                        }
                    });
                }
            } catch (e) {
                log("[!] Native SSL bypass failed: " + e);
            }

            log("[+] SSL pinning bypasses completed");
        } catch (e) {
            log("[!] SSL pinning bypass failed: " + e);
        }
    }
    bypassSSLPinning();

    // --------------------- OTP/SMS Hooking ---------------------
    function hookOTP() {
        try {
            safeUse("android.telephony.SmsManager", function(SmsManager) {
                SmsManager.sendTextMessage.overload("java.lang.String", "java.lang.String", "java.lang.String", "android.app.PendingIntent", "android.app.PendingIntent").implementation = function (dest, sc, text, sentIntent, deliveryIntent) {
                    try {
                        log("[+] OTP Intercepted: " + text);
                    } catch (e) {
                        log("[!] Error logging OTP: " + e);
                    }
                    return this.sendTextMessage(dest, sc, text, sentIntent, deliveryIntent);
                };
            });

            safeUse('android.telephony.ims.aidl.ITmsSmsListener$Stub$Proxy', function(TmsSmsListenerStubProxy) {
                TmsSmsListenerStubProxy.onSmsReceived.implementation = function (sms) {
                    log("[+] OTP Intercepted (IMS): " + sms);
                    return this.onSmsReceived(sms);
                };
            });

            log("[+] SMS/OTP hooks installed");
        } catch (e) {
            log("[!] SMS hook failed: " + e);
        }
    }
    hookOTP();

    // --------------------- Native Library Hooking ---------------------
    function hookNativeLibraries() {
        var libName = "libpairipcore.so";
        
        try {
            var moduleBase = Module.findBaseAddress(libName);
            if (moduleBase) {
                log("[+] " + libName + " loaded at " + moduleBase);
                
                // Hook all exported functions
                Module.enumerateExports(libName).forEach(function (exported) {
                    if (exported.type === "function") {
                        try {
                            Interceptor.attach(exported.address, {
                                onEnter: function (args) {
                                    log("[+] Hooked " + exported.name + " at " + exported.address);
                                    for (var i = 0; i < 4; i++) {
                                        try {
                                            log("    Arg" + i + ": " + args[i].toInt32());
                                        } catch (e) {
                                            log("    Arg" + i + ": [unreadable]");
                                        }
                                    }
                                },
                                onLeave: function (retval) {
                                    try {
                                        log("[+] " + exported.name + " returned: " + retval.toInt32());
                                    } catch (e) {
                                        log("[+] " + exported.name + " returned: [unreadable]");
                                    }
                                }
                            });
                        } catch (e) {
                            log("[!] Failed to hook " + exported.name + ": " + e);
                        }
                    }
                });

                // Patch faulty instructions if found
                try {
                    var faultyInstructionAddress = ptr(moduleBase.add(0x67844));
                    if (Memory.isReadable(faultyInstructionAddress, 4)) {
                        Memory.protect(faultyInstructionAddress, 4, "rwx");
                        Memory.patchCode(faultyInstructionAddress, 4, function (code) {
                            code.writeU32(0xE320F000); // NOP to prevent crash
                            log("[+] Patched faulty instruction at 0x67844");
                        });
                    }
                } catch (e) {
                    log("[!] Faulty instruction patching failed: " + e);
                }
            } else {
                log("[!] " + libName + " not loaded");
            }
        } catch (e) {
            log("[!] Native library hooking failed: " + e);
        }
    }
    hookNativeLibraries();

    // --------------------- Memory Operations Hooking ---------------------
    function hookMemoryOperations() {
        var memoryFunctions = ["malloc", "memcpy", "memmove"];
        
        memoryFunctions.forEach(function(funcName) {
            try {
                var funcAddress = Module.findExportByName(null, funcName);
                if (funcAddress) {
                    Interceptor.attach(funcAddress, {
                        onEnter: function(args) {
                            log("[+] " + funcName + " called");
                            if (funcName === "memcpy" || funcName === "memmove") {
                                try {
                                    if ((args[0].toInt32() & 0x3) !== 0 || (args[1].toInt32() & 0x3) !== 0) {
                                        log("[!] Misaligned " + funcName + " detected");
                                    }
                                } catch (e) {
                                    log("[!] Error checking alignment: " + e);
                                }
                            }
                        },
                        onLeave: function(retval) {
                            if (funcName === "malloc" && (retval.toInt32() & 0x3) !== 0) {
                                log("[!] Unaligned memory allocated at: " + retval);
                            }
                        }
                    });
                }
            } catch (e) {
                log("[!] Failed to hook " + funcName + ": " + e);
            }
        });
    }
    hookMemoryOperations();

    // --------------------- Advanced Bypass Techniques ---------------------
    function applyAdvancedBypasses() {
        // Biometric Authentication Bypass
        try {
            safeUse('android.hardware.biometrics.BiometricPrompt', function(BiometricPrompt) {
                var AuthenticationResult = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');
                
                BiometricPrompt.authenticate.overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').implementation = function(cancelSignal, executor, callback) {
                    log('[+] Bypassing BiometricPrompt.authenticate()');
                    try {
                        var result = AuthenticationResult.$new(null, null, 0);
                        callback.onAuthenticationSucceeded(result);
                    } catch (e) {
                        log('[!] Error in biometric bypass: ' + e);
                    }
                };
            });

            safeUse('android.hardware.fingerprint.FingerprintManager', function(FingerprintManager) {
                var AuthenticationResult = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationResult');
                
                FingerprintManager.authenticate.overload(
                    'android.hardware.fingerprint.FingerprintManager$CryptoObject',
                    'android.os.CancellationSignal',
                    'int',
                    'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback',
                    'android.os.Handler'
                ).implementation = function(cryptoObject, cancel, flags, callback, handler) {
                    log('[+] Bypassing FingerprintManager.authenticate()');
                    try {
                        var result = AuthenticationResult.$new(cryptoObject, null, 0);
                        callback.onAuthenticationSucceeded(result);
                    } catch (e) {
                        log('[!] Error in fingerprint bypass: ' + e);
                    }
                };
            });
        } catch (e) {
            log('[!] Biometric bypass failed: ' + e);
        }

        // Debugger Detection Bypass
        try {
            safeUse('android.os.Debug', function(Debug) {
                Debug.isDebuggerConnected.implementation = function() {
                    log('[+] Bypassing Debugger Detection');
                    return false;
                };
            });
        } catch (e) {
            log('[!] Debugger detection bypass failed: ' + e);
        }

        // Google Play Integrity Bypass
        try {
            safeUse('com.google.android.gms.common.GoogleApiAvailability', function(GoogleAPI) {
                GoogleAPI.isGooglePlayServicesAvailable.overload('android.content.Context').implementation = function(context) {
                    log('[+] Bypassing Google API Integrity Check');
                    return 0;
                };
            });
        } catch (e) {
            log('[!] Google API integrity bypass failed: ' + e);
        }

        // User interaction simulation
        try {
            safeUse('android.view.MotionEvent', function(MotionEvent) {
                safeUse('android.os.SystemClock', function(SystemClock) {
                    safeUse('android.view.View', function(View) {
                        var downTime = SystemClock.uptimeMillis();
                        var eventTime = downTime + 50;
                        
                        var touchEventDown = MotionEvent.obtain.overload('long', 'long', 'int', 'float', 'float', 'int').call(
                            MotionEvent, downTime, eventTime, MotionEvent.ACTION_DOWN.value, 50.0, 50.0, 0
                        );
                        var touchEventUp = MotionEvent.obtain.overload('long', 'long', 'int', 'float', 'float', 'int').call(
                            MotionEvent, downTime + 50, eventTime + 100, MotionEvent.ACTION_UP.value, 50.0, 50.0, 0
                        );
                        
                        var rootView = Java.cast(View.getRootView(), View);
                        rootView.dispatchTouchEvent(touchEventDown);
                        rootView.dispatchTouchEvent(touchEventUp);
                        
                        log("[+] Simulated user interaction via touch event");
                    });
                });
            });
        } catch (e) {
            log("[!] User interaction simulation failed: " + e);
        }
    }
    applyAdvancedBypasses();

    // --------------------- RASP Bypass ---------------------
    function bypassRASP() {
        var raspProviders = [
            { name: 'Talsec', class: 'com.talsec.security.Talsec' },
            { name: 'ProGuard', class: 'com.proguard.security.ProGuard' },
            { name: 'AppSealing', class: 'com.appsealing.security.AppSealing' },
            { name: 'RootBeer', class: 'com.scottyab.rootbeer.RootBeer' },
            { name: 'PortSwigger', class: 'com.portswigger.package.CertificateDetection' }
        ];

        // Check for RASP modules in memory
        try {
            var processes = Process.enumerateModulesSync();
            processes.forEach(function(module) {
                if (module.name.toLowerCase().includes('talsec')) {
                    log('[+] Talsec RASP detected');
                }
                if (module.name.toLowerCase().includes('proguard')) {
                    log('[+] ProGuard RASP detected');
                }
                if (module.name.toLowerCase().includes('appsealing')) {
                    log('[+] AppSealing RASP detected');
                }
            });
        } catch (e) {
            log('[!] RASP module detection failed: ' + e);
        }

        // Hook RASP provider methods
        raspProviders.forEach(function(provider) {
            safeUse(provider.class, function(clazz) {
                if (clazz.isRooted) {
                    clazz.isRooted.implementation = function() {
                        log('[+] Bypassing ' + provider.name + ' Root Detection');
                        return false;
                    };
                }
                if (clazz.checkEmulator) {
                    clazz.checkEmulator.implementation = function() {
                        log('[+] Bypassing ' + provider.name + ' Emulator Check');
                        return false;
                    };
                }
                if (clazz.checkHook) {
                    clazz.checkHook.implementation = function() {
                        log('[+] Bypassing ' + provider.name + ' Hook Check');
                        return false;
                    };
                }
                if (clazz.checkTamper) {
                    clazz.checkTamper.implementation = function() {
                        log('[+] Bypassing ' + provider.name + ' Tamper Check');
                        return false;
                    };
                }
                if (provider.name === 'PortSwigger' && clazz.detectCertificates) {
                    clazz.detectCertificates.implementation = function() {
                        log('[+] Bypassing PortSwigger Certificate Detection');
                        return false;
                    };
                }
            });
        });

        // Enhanced obfuscation techniques
        try {
            function obfuscateMethodNames() {
                var methods = ['detectCertificates', 'checkCertificate'];
                methods.forEach(function(method) {
                    var obfuscated = method.split('').map(function(c) {
                        return String.fromCharCode(c.charCodeAt(0) + 1);
                    }).join('');
                    log('[+] Obfuscating method: ' + method + ' to ' + obfuscated);
                });
            }
            obfuscateMethodNames();
        } catch (e) {
            log('[!] Method obfuscation failed: ' + e);
        }
    }
    bypassRASP();

    // --------------------- Frida Detection Bypass ---------------------
    function bypassFridaDetection() {
        try {
            // Check for Frida in memory
            var isFridaPresent = false;
            try {
                var modules = Process.enumerateModulesSync();
                modules.forEach(function(module) {
                    if (module.name.toLowerCase().includes('frida')) {
                        isFridaPresent = true;
                    }
                });
            } catch (e) {
                log('[!] Frida detection check failed: ' + e);
            }

            if (isFridaPresent) {
                log('[+] Frida detected, attempting bypass');
                
                // Common Frida detection bypass techniques
                safeUse('java.lang.System', function(System) {
                    System.getenv.implementation = function(key) {
                        if (key === "FRIDA_SERVER") {
                            log('[+] Bypassing Frida environment detection');
                            return null;
                        }
                        return this.getenv(key);
                    };
                });
            }
        } catch (e) {
            log('[!] Frida detection bypass failed: ' + e);
        }
    }
    bypassFridaDetection();

    log("[+] All bypass techniques attempted. Script completed successfully.");
});

// Fallback send function if console.log fails
function send(message) {
    try {
        Java.perform(function() {
            Java.use("java.lang.System").out.println(message);
        });
    } catch (e) {
        // If all else fails, just do nothing
    }
}
