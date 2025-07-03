// =======================================
// Android Universal Bypass v1.7
// Combining Command Blocking + Root / SSL / Biometric / Anti-Tamper
// =======================================

// ========== CONFIG ==========
var config = {
    debug: true,
    retryDelay: 300,
    verifyInterval: 10000,
    targetLibs: ["libssl.so", "libtoolchecker.so", "librootcheck.so"],
    blockedCommands: ["su", "busybox", "sh", "id", "mount", "getprop", "pm", "am"],
    rootPackages: [
        "com.noshufou.android.su", "eu.chainfire.supersu", "com.topjohnwu.magisk",
        "de.robv.android.xposed.installer", "com.koushikdutta.superuser",
        "com.thirdparty.superuser", "com.yellowes.su", "com.saurik.substrate",
        "me.phh.superuser", "com.chelpus.luckypatch", "com.devadvance.rootcloak"
    ],
    rootBinaries: ["su", "busybox", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk"],
    rootProperties: {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1"
    },
    securityProviders: [
        "com.talsec.security.Talsec", "com.scottyab.rootbeer.RootBeer"
    ]
};

// ========== LOGGING ==========
function log(message, level = "INFO") {
    try {
        const timestamp = new Date().toISOString();
        const full = `[${timestamp}] [${level}] ${message}`;
        if (typeof send !== "undefined") {
            send(full);
        } else if (console) {
            switch(level) {
                case "ERROR": console.error(full); break;
                case "WARN": console.warn(full); break;
                case "DEBUG": console.debug(full); break;
                case "SUCCESS": console.info(full); break;
                default: console.log(full);
            }
        } else {
            Java.perform(() => Java.use("android.util.Log").d("BYPASS", full));
        }
    } catch (e) {
        console.log("[log-fallback] " + message);
    }
}

// ========== UTILS ==========
function safeUse(className, cb) {
    try {
        const cls = Java.use(className);
        cb(cls);
        return true;
    } catch (e) {
        log(`Class not found: ${className}`, "DEBUG");
        return false;
    }
}

// ========== HOOKS ==========

function applyRootBypasses() {
    log("Applying Root detection bypasses", "DEBUG");

    // PackageManager hook
    safeUse("android.app.ApplicationPackageManager", (PackageManager) => {
        PackageManager.getPackageInfo.overloads.forEach(overload => {
            overload.implementation = function(pkg) {
                if (config.rootPackages.includes(pkg)) {
                    log(`Blocked root package check: ${pkg}`, "SUCCESS");
                    throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
                }
                return overload.apply(this, arguments);
            };
        });
    });

    // File existence
    safeUse("java.io.File", (File) => {
        File.exists.implementation = function() {
            const path = this.getAbsolutePath();
            if (config.rootBinaries.some(bin => path.includes(bin))) {
                log(`Faked non-existence: ${path}`, "SUCCESS");
                return false;
            }
            return this.exists.call(this);
        };
    });

    // System properties
    safeUse("android.os.SystemProperties", (SystemProperties) => {
        SystemProperties.get.overload("java.lang.String").implementation = function(key) {
            if (config.rootProperties[key]) {
                log(`Spoofed system property: ${key}`, "SUCCESS");
                return config.rootProperties[key];
            }
            return this.get(key);
        };
    });
    safeUse("java.lang.System", (SystemClass) => {
        SystemClass.getProperty.overload("java.lang.String").implementation = function(key) {
            if (config.rootProperties[key]) {
                log(`Spoofed java.lang.System property: ${key}`, "SUCCESS");
                return config.rootProperties[key];
            }
            return this.getProperty.call(this, key);
        };
    });

    // RootBeer
    safeUse("com.scottyab.rootbeer.RootBeerNative", (RootBeerNative) => {
        RootBeerNative.a.implementation = () => false;
        RootBeerNative.checkForRoot.implementation = () => 0;
        log("RootBeer bypassed", "SUCCESS");
    });

    // Xposed
    safeUse("de.robv.android.xposed.XposedBridge", (XposedBridge) => {
        XposedBridge.hasOwnProperty.implementation = () => false;
        log("XposedBridge spoofed", "SUCCESS");
    });
}

function applyCommandBypasses() {
    log("Applying Runtime and ProcessBuilder hooks", "DEBUG");

    safeUse("java.lang.Runtime", (Runtime) => {
        Runtime.exec.overloads.forEach(overload => {
            overload.implementation = function() {
                const cmd = arguments[0].toString();
                if (config.blockedCommands.some(p => cmd.includes(p))) {
                    log(`Blocked exec command: ${cmd}`, "SUCCESS");
                    throw Java.use("java.io.IOException").$new("Command not allowed");
                }
                return overload.apply(this, arguments);
            };
        });
    });

    safeUse("java.lang.ProcessBuilder", (ProcessBuilder) => {
        ProcessBuilder.start.implementation = function() {
            const cmdList = this.command();
            if (cmdList.some(c => config.blockedCommands.some(p => c.includes(p)))) {
                log(`Blocked ProcessBuilder: ${cmdList.join(" ")}`, "SUCCESS");
                throw Java.use("java.io.IOException").$new("Command blocked");
            }
            return this.start.call(this);
        };
    });
}

function applySSLBypasses() {
    log("Applying SSL pinning bypasses", "DEBUG");

    safeUse("javax.net.ssl.SSLContext", (SSLContext) => {
        const TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        const CustomTM = Java.registerClass({
            name: "CustomTrustManager",
            implements: [TrustManager],
            methods: {
                checkClientTrusted: () => {},
                checkServerTrusted: () => {},
                getAcceptedIssuers: () => []
            }
        });
        SSLContext.init.implementation = function(km, tm, sr) {
            log("Injected custom TrustManager", "SUCCESS");
            return this.init(km, [CustomTM.$new()], sr);
        };
    });

    safeUse("okhttp3.CertificatePinner", (Pinner) => {
        Pinner.check.overload("java.lang.String", "java.util.List").implementation = function() {
            log("Bypassed OkHttp pinning", "SUCCESS");
        };
    });
}

function applyBiometricBypasses() {
    log("Applying Biometric bypasses", "DEBUG");

    safeUse("android.hardware.biometrics.BiometricPrompt", (BiometricPrompt) => {
        BiometricPrompt.authenticate.implementation = function(cs, ex, cb) {
            log("BiometricPrompt bypassed", "SUCCESS");
            cb.onAuthenticationSucceeded(null);
        };
    });
}

function applyNativeBypasses() {
    log("Applying Native layer hooks", "DEBUG");

    const libcSystem = Module.findExportByName("libc.so", "system");
    if (libcSystem) {
        Interceptor.attach(libcSystem, {
            onEnter(args) {
                const cmd = Memory.readCString(args[0]);
                if (config.blockedCommands.some(p => cmd.includes(p))) {
                    log(`Blocked native system(): ${cmd}`, "SUCCESS");
                    args[0] = Memory.allocUtf8String(":");
                }
            }
        });
    }

    const execve = Module.findExportByName("libc.so", "execve");
    if (execve) {
        Interceptor.attach(execve, {
            onEnter(args) {
                const cmd = Memory.readCString(args[0]);
                if (config.blockedCommands.some(p => cmd.includes(p))) {
                    log(`Blocked native execve(): ${cmd}`, "SUCCESS");
                    args[0] = Memory.allocUtf8String("/system/bin/false");
                }
            }
        });
    }

    const popen = Module.findExportByName("libc.so", "popen");
    if (popen) {
        Interceptor.attach(popen, {
            onEnter(args) {
                const cmd = Memory.readCString(args[0]);
                if (cmd.includes("mount")) {
                    log(`Spoofed native popen(): ${cmd}`, "SUCCESS");
                    args[0] = Memory.allocUtf8String("echo 'fake mount output'");
                }
            }
        });
    }
}

function applyAntiTamperBypasses() {
    log("Applying anti-tamper bypasses", "DEBUG");

    safeUse("android.os.Debug", (Debug) => {
        Debug.isDebuggerConnected.implementation = () => {
            log("Debugger bypassed", "SUCCESS");
            return false;
        };
    });
}

function applyZygiskBypasses() {
    log("Applying Zygisk / Magisk bypasses", "DEBUG");

    Interceptor.attach(Module.findExportByName(null, "open"), {
        onEnter(args) {
            const path = Memory.readCString(args[0]);
            if (path.includes("/proc/self/maps")) {
                log("Spoofed open() on /proc/self/maps", "SUCCESS");
            }
        }
    });

    Interceptor.attach(Module.findExportByName(null, "fopen"), {
        onEnter(args) {
            const path = Memory.readCString(args[0]);
            if (path.includes("/proc/self/maps")) {
                log("Redirected fopen() for /proc/self/maps", "SUCCESS");
                args[0] = Memory.allocUtf8String("/dev/null");
            }
        }
    });
}

// ========== MAIN ==========
Java.perform(() => {
    log("=== Starting Combined Universal Bypass ===", "INFO");

    applyRootBypasses();
    applyCommandBypasses();
    applySSLBypasses();
    applyBiometricBypasses();
    applyNativeBypasses();
    applyAntiTamperBypasses();
    applyZygiskBypasses();

    config.targetLibs.forEach((lib) => {
        const tries = 0;
        const interval = setInterval(() => {
            const base = Module.findBaseAddress(lib);
            if (base) {
                clearInterval(interval);
                log(`Hooking native functions in ${lib}`, "DEBUG");
                if (lib.includes("ssl")) {
                    const sslVerify = Module.findExportByName(lib, "SSL_verify");
                    if (sslVerify) {
                        Interceptor.attach(sslVerify, {
                            onEnter(args) {
                                args[0] = 0;
                                log("Bypassed native SSL_verify", "SUCCESS");
                            }
                        });
                    }
                }
            }
        }, config.retryDelay);
    });

    setInterval(() => {
        log("Verifying bypass integrity...", "DEBUG");
        try {
            if (!Java.use("android.app.ApplicationPackageManager").getPackageInfo.overloads[0].implementation) {
                log("Re-applying root bypass", "WARN");
                applyRootBypasses();
            }
        } catch {}
    }, config.verifyInterval);

    log("=== Universal Bypass System ACTIVE ===", "SUCCESS");
});

// fallback for frida-trace
if (typeof send === "undefined") { var send = console.log; }
