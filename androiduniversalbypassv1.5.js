// Define the script creator name
var scriptCreator = "SecurityBong";

Java.perform(function () {
    function send(message) {
        console.log(message);
    }

    // Function to safely use Java classes and handle missing classes gracefully
    function safeUse(className, callback) {
        try {
            var clazz = Java.use(className);
            callback(clazz);
        } catch (err) {
            send("Class " + className + " not present, proceeding with other checks.");
        }
    }

    // Print script creator name
    send("Script created by " + scriptCreator);

    // Root detection bypass
    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"
    ];

    var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk"];

    var RootProperties = {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1"
    };

    var RootPropertiesKeys = Object.keys(RootProperties);

    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    var Runtime = Java.use('java.lang.Runtime');
    var NativeFile = Java.use('java.io.File');
    var String = Java.use('java.lang.String');
    var SystemProperties = Java.use('android.os.SystemProperties');
    var BufferedReader = Java.use('java.io.BufferedReader');
    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
    var StringBuffer = Java.use('java.lang.StringBuffer');

    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pname, flags) {
        var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
        if (shouldFakePackage) {
            send("Bypass root check for package: " + pname);
            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
        }
        return this.getPackageInfo.overload('java.lang.String', 'int').call(this, pname, flags);
    };

    NativeFile.exists.implementation = function () {
        var name = NativeFile.getName.call(this);
        var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
        if (shouldFakeReturn) {
            send("Bypass return value for binary: " + name);
            return false;
        } else {
            return this.exists.call(this);
        }
    };

    // Command hooks for root detection bypass
    var exec = Runtime.exec.overload('[Ljava.lang.String;');
    var exec1 = Runtime.exec.overload('java.lang.String');
    var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
    var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
    var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
    var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

    exec5.implementation = function (cmd, env, dir) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec5.call(this, cmd, env, dir);
    };

    exec4.implementation = function (cmdarr, env, file) {
        for (var i = 0; i < cmdarr.length; i++) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmdarr + " command");
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
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec3.call(this, cmdarr, envp);
    };

    exec2.implementation = function (cmd, env) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec2.call(this, cmd, env);
    };

    exec.implementation = function (cmd) {
        for (var i = 0; i < cmd.length; i++) {
            var tmp_cmd = cmd[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
        }

        return exec.call(this, cmd);
    };

    exec1.implementation = function (cmd) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec1.call(this, cmd);
    };

    // SSL Pinning Bypass
    try {
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

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
            send('Overriding SSLContext.init to use CustomTrustManager');
            SSLContext.init.call(this, keyManager, [CustomTrustManager.$new()], secureRandom);
        };

        // Additional detection for TrustManagerImpl
        safeUse('com.android.org.conscrypt.TrustManagerImpl', function (TrustManagerImpl) {
            TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                send('Bypassing TrustManagerImpl.verifyChain');
                return untrustedChain;
            };
        });

        // OkHTTP3 Pinning Bypass with Safe Hooking
        safeUse('okhttp3.CertificatePinner', function (CertificatePinner) {
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
                send('Bypassing OkHTTP3 CertificatePinner');
            };
        });

    } catch (err) {
        send('SSL Pinning Bypass failed, proceeding with other checks.');
    }

    // **SSL_verify Bypass**
    // Try hooking into native SSL pinning method if available
    try {
        var SSL_verify = Module.findExportByName("libssl.so", "SSL_verify");
        if (SSL_verify) {
            Interceptor.attach(SSL_verify, {
                onEnter: function (args) {
                    send("Bypassing SSL verification (libssl.so)");
                    args[0] = 0; // Modify the argument to bypass SSL checks
                }
            });
        } else {
            send("SSL_verify function not found, proceeding without native SSL bypass.");
        }
    } catch (err) {
        send("Error attempting to hook SSL_verify: " + err);
    }

    // Biometric Authentication Bypass
    var callbackG = null;
    var authenticationResultInst = null;

    // Hook BiometricPrompt.authenticate methods safely
    safeUse('android.hardware.biometrics.BiometricPrompt', function (BiometricPrompt) {
        var CryptoObject = Java.use('android.hardware.biometrics.BiometricPrompt$CryptoObject');
        var AuthenticationResult = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');

        BiometricPrompt.authenticate.overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').implementation = function (cancelSignal, executor, callback) {
            send('Bypassing BiometricPrompt.authenticate() with CancellationSignal');

            var cryptoObj = CryptoObject.$new(null);
            authenticationResultInst = AuthenticationResult.$new(cryptoObj, null, 0);

            callbackG = callback;
            Java.retain(callback);

            callback.onAuthenticationSucceeded(authenticationResultInst);
        };

        BiometricPrompt.authenticate.overload('android.hardware.biometrics.BiometricPrompt$CryptoObject', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').implementation = function (cryptoObj, cancelSignal, executor, callback) {
            send('Bypassing BiometricPrompt.authenticate() with CryptoObject');

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
            send('Bypassing FingerprintManager.authenticate()');

            authenticationResultInst = AuthenticationResult.$new(cryptoObject, null, 0);
            callbackG = callback;
            Java.retain(callback);

            callback.onAuthenticationSucceeded(authenticationResultInst);
        };
    });

    // Simulate user interaction with improved handling
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

            send("Simulated user interaction via touch event.");
        } catch (err) {
            send("User interaction simulation failed, continuing without interaction.");
        }
    }

    simulateUserInteraction();

    // RASP (Runtime Application Self-Protection) Bypass
    function checkRASP() {
        var result = false;
        var moduleName = ['talsec', 'proguard', 'appsealing'];
        var processes = Process.enumerateModulesSync();
        for (var i = 0; i < processes.length; i++) {
            var module = processes[i];
            for (var j = 0; j < moduleName.length; j++) {
                if (module['name'].toLowerCase().indexOf(moduleName[j]) !== -1) {
                    send(moduleName[j] + ' detected and bypassed');
                    result = true;
                    break;
                }
            }
        }
        return result;
    }

    if (checkRASP()) {
        send('RASP bypassed');
    } else {
        send('RASP not bypassed');
    }

    // Google API Integrity Bypass
    try {
        if (Java.available && Java.androidVersion >= 24) {
            var GoogleAPI = Java.use('com.google.android.gms.common.GoogleApiAvailability');
            GoogleAPI.isGooglePlayServicesAvailable.overload('android.content.Context').implementation = function (context) {
                send('Bypassing Google API Integrity Check');
                return 0;
            };
        } else {
            send('Google API Integrity Check bypass not supported on this Android version');
        }
    } catch (err) {
        send('Google API class not found, proceeding.');
    }

    // Debugger Detection Bypass
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            send('Bypassing Debugger Detection');
            return false;
        };
    } catch (err) {
        send('Debugger Detection Bypass failed, proceeding without changes.');
    }

    // Anti-Frida Detection Bypass
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
        send('Frida detection bypassed');
    } else {
        send('Frida detection not bypassed');
    }

    // Talsec RASP Bypass
    safeUse('com.talsec.security.Talsec', function (talsec) {
        talsec.checkEmulator.implementation = function () {
            send('Bypassing Talsec Emulator Check');
            return false;
        };

        talsec.checkRooted.implementation = function () {
            send('Bypassing Talsec Rooted Check');
            return false;
        };

        talsec.checkHook.implementation = function () {
            send('Bypassing Talsec Hook Check');
            return false;
        };

        talsec.checkTamper.implementation = function () {
            send('Bypassing Talsec Tamper Check');
            return false;
        };
    });

    // ProGuard RASP Bypass
    safeUse('com.proguard.security.ProGuard', function (proGuard) {
        proGuard.checkEmulator.implementation = function () {
            send('Bypassing ProGuard Emulator Check');
            return false;
        };

        proGuard.checkRooted.implementation = function () {
            send('Bypassing ProGuard Rooted Check');
            return false;
        };

        proGuard.checkHook.implementation = function () {
            send('Bypassing ProGuard Hook Check');
            return false;
        };

        proGuard.checkTamper.implementation = function () {
            send('Bypassing ProGuard Tamper Check');
            return false;
        };
    });

    // AppSealing RASP Bypass
    safeUse('com.appsealing.security.AppSealing', function (appSealing) {
        appSealing.checkEmulator.implementation = function () {
            send('Bypassing AppSealing Emulator Check');
            return false;
        };

        appSealing.checkRooted.implementation = function () {
            send('Bypassing AppSealing Rooted Check');
            return false;
        };

        appSealing.checkHook.implementation = function () {
            send('Bypassing AppSealing Hook Check');
            return false;
        };

        appSealing.checkTamper.implementation = function () {
            send('Bypassing AppSealing Tamper Check');
            return false;
        };
    });

    // Root detection bypass using RootBeer library
    safeUse('com.scottyab.rootbeer.RootBeer', function (RootBeer) {
        RootBeer.isRooted.implementation = function () {
            send('Bypassing RootBeer Root Detection');
            return false;
        };
    });
});
