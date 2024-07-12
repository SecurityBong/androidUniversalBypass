// Helper function to safely replace methods with error handling and detailed logging
function safeReplace(klassName, methodName, overloads, newImplementation) {
    try {
        var klass = Java.use(klassName);
        var method = klass[methodName];
        if (method) {
            var overloadedMethod = method.overload.apply(method, overloads);
            if (overloadedMethod) {
                overloadedMethod.implementation = newImplementation;
                console.log("[+] Hook successfully replaced: " + klassName + "." + methodName);
                return true;
            } else {
                console.log("[-] Overload not found: " + klassName + "." + methodName + "(" + overloads.join(", ") + ")");
            }
        } else {
            console.log("[-] Method not found: " + klassName + "." + methodName);
        }
    } catch (e) {
        console.log("[-] Failed to replace " + klassName + "." + methodName + ": " + e.message);
    }
    return false;
}

// Bypass Root Detection
var RootPackages = [
    "com.noshufou.android.su",
    "com.thirdparty.superuser",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.zachspong.temprootremovejb",
    "com.ramdroid.appquarantine"
];

var RootBinaries = [
    "su", "busybox", "magisk"
];

var RootProperties = [
    "ro.debuggable", "ro.secure", "ro.build.tags"
];

var RootFiles = [
    "/system/app/Superuser.apk", 
    "/sbin/su", 
    "/system/bin/su", 
    "/system/xbin/su", 
    "/data/local/xbin/su", 
    "/data/local/bin/su", 
    "/system/sd/xbin/su", 
    "/system/bin/failsafe/su", 
    "/data/local/su"
];

RootPackages.forEach(function(packageName) {
    var success = safeReplace("android.app.ApplicationPackageManager", 'getPackageInfo', ['java.lang.String', 'int'], function(pkg, flags) {
        if (pkg === packageName) {
            console.log("[!] Root package detected: " + pkg);
            return null;
        }
        return this.getPackageInfo(pkg, flags);
    });
    if (!success) {
        console.log("[-] Cannot bypass Root package detection for: " + packageName);
    }
});

RootBinaries.forEach(function(binary) {
    var success = safeReplace("java.lang.Runtime", 'exec', ['[Ljava.lang.String;'], function(args) {
        for (var i = 0; i < args.length; i++) {
            if (args[i].indexOf(binary) >= 0) {
                console.log("[!] Root binary detected: " + binary);
                args[i] = "invalid_command";
            }
        }
        return this.exec(args);
    });
    if (!success) {
        console.log("[-] Cannot bypass Root binary detection for: " + binary);
    }
});

RootProperties.forEach(function(property) {
    var success = safeReplace("android.os.SystemProperties", 'get', ['java.lang.String'], function(name) {
        if (name === property) {
            console.log("[!] Root property detected: " + property);
            return "0";  // Return safe value
        }
        return this.get(name);
    });
    if (!success) {
        console.log("[-] Cannot bypass Root property detection for: " + property);
    }
});

RootFiles.forEach(function(filePath) {
    var success = safeReplace("java.io.File", 'exists', [], function() {
        if (this.getPath() === filePath) {
            console.log("[!] Root file detected: " + filePath);
            return false;
        }
        return this.exists();
    });
    if (!success) {
        console.log("[-] Cannot bypass Root file detection for: " + filePath);
    }
});

// Bypass SSL Pinning
try {
    var sslPinningSuccess = safeReplace('okhttp3.CertificatePinner', 'check', ['java.lang.String', 'java.util.List'], function(a, b) {
        console.log('[+] Bypassing SSL Pinning for: ' + a);
        return;
    });
    if (!sslPinningSuccess) {
        console.log('[-] Cannot bypass SSL Pinning');
    }
} catch (e) {
    console.log("[-] SSL Pinning bypass failed: " + e.message);
}

try {
    var httpsURLConnectionSuccess = safeReplace('javax.net.ssl.HttpsURLConnection', 'setDefaultHostnameVerifier', ['javax.net.ssl.HostnameVerifier'], function(hostnameVerifier) {
        console.log('[+] Bypassing SSL Pinning with HttpsURLConnection');
        return;
    });
    if (!httpsURLConnectionSuccess) {
        console.log('[-] Cannot bypass SSL Pinning with HttpsURLConnection');
    }
} catch (e) {
    console.log("[-] SSL Pinning bypass failed: " + e.message);
}

// Bypass Biometric Checks
try {
    var biometricSuccess = safeReplace("android.hardware.fingerprint.FingerprintManager", 'authenticate', ['android.hardware.fingerprint.FingerprintManager$CryptoObject', 'android.os.CancellationSignal', 'int', 'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback', 'android.os.Handler'], function(obj, cancel, flags, callback, handler) {
        console.log("[+] Bypassing Biometric Authentication");
        callback.onAuthenticationSucceeded(obj);
    });
    if (!biometricSuccess) {
        console.log("[-] Cannot bypass Biometric Authentication");
    }
} catch (e) {
    console.log("[-] Biometric check bypass failed: " + e.message);
}

// Bypass Emulator Detection
try {
    var buildModelSuccess = safeReplace("android.os.Build", 'MODEL', [], function() {
        console.log("[+] Bypassing Emulator Build.MODEL");
        return "Pixel 3";
    });
    if (!buildModelSuccess) {
        console.log("[-] Cannot bypass Emulator Build.MODEL");
    }
} catch (e) {
    console.log("[-] Failed to bypass emulator Build.MODEL: " + e.message);
}

try {
    var buildManufacturerSuccess = safeReplace("android.os.Build", 'MANUFACTURER', [], function() {
        console.log("[+] Bypassing Emulator Build.MANUFACTURER");
        return "Google";
    });
    if (!buildManufacturerSuccess) {
        console.log("[-] Cannot bypass Emulator Build.MANUFACTURER");
    }
} catch (e) {
    console.log("[-] Failed to bypass emulator Build.MANUFACTURER: " + e.message);
}

try {
    var deviceIdSuccess = safeReplace('android.telephony.TelephonyManager', 'getDeviceId', [], function() {
        console.log("[+] Bypassing Emulator Detection - Device ID");
        return "012345678912345";
    });
    if (!deviceIdSuccess) {
        console.log("[-] Cannot bypass Emulator Detection - Device ID");
    }
} catch (e) {
    console.log("[-] Failed to bypass emulator detection - Device ID: " + e.message);
}

try {
    var subscriberIdSuccess = safeReplace('android.telephony.TelephonyManager', 'getSubscriberId', [], function() {
        console.log("[+] Bypassing Emulator Detection - Subscriber ID");
        return "310260000000000";
    });
    if (!subscriberIdSuccess) {
        console.log("[-] Cannot bypass Emulator Detection - Subscriber ID");
    }
} catch (e) {
    console.log("[-] Failed to bypass emulator detection - Subscriber ID: " + e.message);
}

// Bypass Debugger Detection
try {
    var debuggerSuccess = safeReplace('android.os.Debug', 'isDebuggerConnected', [], function() {
        console.log("[+] Bypassing Debugger Detection");
        return false;
    });
    if (!debuggerSuccess) {
        console.log("[-] Cannot bypass Debugger Detection");
    }
} catch (e) {
    console.log("[-] Failed to bypass debugger detection: " + e.message);
}

// Bypass RASP (Runtime Application Self-Protection)
try {
    var onResumeSuccess = safeReplace("android.app.Activity", 'onResume', [], function() {
        console.log("[+] Bypassing RASP onResume");
        this.onResume.call(this); // Ensure the superclass method is called
    });
    if (!onResumeSuccess) {
        console.log("[-] Cannot bypass RASP onResume");
    }
} catch (e) {
    console.log("[-] Failed to bypass RASP onResume: " + e.message);
}

try {
    var getRunningAppProcessesSuccess = safeReplace('android.app.ActivityManager', 'getRunningAppProcesses', [], function() {
        console.log("[+] Bypassing RASP getRunningAppProcesses");
        return [];
    });
    if (!getRunningAppProcessesSuccess) {
        console.log("[-] Cannot bypass RASP getRunningAppProcesses");
    }
} catch (e) {
    console.log("[-] Failed to bypass RASP getRunningAppProcesses: " + e.message);
}

// Bypass Anti-Frida
try {
    var openInterceptorSuccess = Interceptor.attach(Module.findExportByName(null, 'open'), {
        onEnter: function(args) {
            this.path = Memory.readCString(args[0]);
        },
        onLeave: function(retval) {
            if (this.path.indexOf("frida") !== -1) {
                console.log("[+] Bypassing Anti-Frida 'open' interceptor");
                retval.replace(-1);
            }
        }
    });
    if (!openInterceptorSuccess) {
        console.log("[-] Cannot bypass Anti-Frida 'open' interceptor");
    }
} catch (e) {
    console.log("[-] Failed to bypass Anti-Frida 'open' interceptor: " + e.message);
}

// Log that Frida script execution has completed
console.log("Frida script execution completed.");
