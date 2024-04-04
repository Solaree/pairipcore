# pairipcore
Public researchings of the Google's Android apps protection

## Disclaimer
The information provided is solely meant for educational purposes and is not intended to encourage malicious practice.

## General Overview
Pairipcore prevents any kind of repacking, tampering, code injecting for the app, usage of such programs as [frida-server](https://frida.re/docs/android/). Optionally, it can prevent usage of the app for rooted users.

### Basics
- [x] Integrity check (Java side, C++ library)
- [x] Pseudo-VM code injection
- [x] C++ library control flow & code obfuscation
- [x] Usage of [`dlopen`](https://man7.org/linux/man-pages/man3/dlopen.3.html), [`dlsym`](https://man7.org/linux/man-pages/man3/dlsym.3.html), [`dlclose`](https://man7.org/linux/man-pages/man3/dlopen.3.html) for dynamic import of bionic libc functions, [`syscall`](https://man7.org/linux/man-pages/man2/syscall.2.html) and [`SVC 0`](https://developer.arm.com/documentation/dui0489/c/arm-and-thumb-instructions/miscellaneous-instructions/svc)-based custom function. All needed to make analysis harder
- [x] Basic anti-debugger ([`prctl`](https://man7.org/linux/man-pages/man2/prctl.2.html), [`clone`](https://man7.org/linux/man-pages/man2/clone.2.html), [`waitpid`](https://man7.org/linux/man-pages/man2/wait.2.html), [`ptrace`](https://man7.org/linux/man-pages/man2/ptrace.2.html))
- [x] `/proc/self/maps`, `/proc/self/status` checks ([`openat`](https://man7.org/linux/man-pages/man2/open.2.html), [`close`](https://man7.org/linux/man-pages/man2/close.2.html), [`read`](https://man7.org/linux/man-pages/man2/read.2.html), [`lseek`](https://man7.org/linux/man-pages/man2/lseek.2.html), [`fstat`](https://man7.org/linux/man-pages/man2/fstat.2.html), [`fstatfs`](https://man7.org/linux/man-pages/man2/fstatfs.2.html))
- [x] [system property functions](https://android.googlesource.com/platform/bionic/+/master/libc/include/sys/system_properties.h), [`access`](https://man7.org/linux/man-pages/man2/access.2.html), [`opendir`](https://man7.org/linux/man-pages/man3/opendir.3.html), [`readddir`](https://man7.org/linux/man-pages/man3/readdir.3.html), [`closedir`](https://man7.org/linux/man-pages/man3/closedir.3.html) directories and properties checks
- [x] Full frida-server check (not only default port, like Promon Shield does)

Most of those and more are done by another famous app protection, [Promon Shiled](https://github.com/KiFilterFiberContext/promon-reversal)

## Technical Overview
### Java Side
The basic code structure looks like this:
![image](https://github.com/Solaree/pairipcore/assets/115794865/cf3235c3-fd97-4926-8b76-8ef481467e1e)
If we will check `Application.java`, we will see something like this:
```java
package com.pairip.application;

import android.content.Context;
import com.pairip.SignatureCheck;
import com.vpn.free.hotspot.secure.vpnify.App; /* the main app package goes here,
											in my case it was Vpnify */

public class Application extends App {
  public void attachBaseContext(Context context)  {
	  SignatureCheck.verifyIntegrity(context);
	  super.attachBaseContext(context);
  }
}
```
As we can see, Pairipcore does integrity check
```java
package com.pairip;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Base64;
import android.util.Log;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SignatureCheck {
	private static final String ALLOWLISTED_SIG = "Vn3kj4pUblROi2S+QfRRL9nhsaO2uoHQg6+dpEtxdTE=";
	private static final String TAG = "SignatureCheck";
	private static String expectedLegacyUpgradedSignature = "ag4imYhJd4ISc+m2klK8n1Oq2WId2REza1aYcssrVwc=";
	private static String expectedSignature = "ag4imYhJd4ISc+m2klK8n1Oq2WId2REza1aYcssrVwc=";
	private static String expectedTestSignature = "ag4imYhJd4ISc+m2klK8n1Oq2WId2REza1aYcssrVwc=";

	private static class SignatureTamperedException extends RuntimeException {
		public SignatureTamperedException(String message) {
			super(message);
		}
	}
  
	public static void verifyIntegrity(Context context) {
		String str;
		try {
			str = Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(context.getPackageManager().getPackageInfo(context.getPackageName(), 64).signatures[0].toByteArray()), 2);
		} catch (PackageManager.NameNotFoundException | NoSuchAlgorithmException unused) {
			str = null;
		} if (!verifySignatureMatches(str) && !expectedTestSignature.equals(str) && !ALLOWLISTED_SIG.equals(str))
			throw new SignatureTamperedException("Apk signature is invalid.");
		Log.i(TAG, "Signature check ok");
	}

	public static boolean verifySignatureMatches(String signature) {
		return expectedSignature.equals(signature) || expectedLegacyUpgradedSignature.equals(signature);
	}

	private SignatureCheck() {
	}
}
```
Actually those aren't interesting and can be easily bypassed with removing call of the `verifyIntegrity` method, let's explore deeper..

In `VMRunner.java` in the corresponding class we can see next:
```java
public class VMRunner {
    private static final int PACKAGE_MANAGER_TRIES = 5;
    private static final String TAG = "VMRunner";
    private static String apkPath = null;
    private static Context context = null;
    private static String loggingEnabled = "false";

    public static native Object executeVM(byte[] vmCode, Object[] args);

    static {
        System.loadLibrary("pairipcore");
    }

    public static class VMRunnerException extends RuntimeException {
        public VMRunnerException(String message) {
            super(message);
        }

        public VMRunnerException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    public static void setContext(Context context2) {
        context = context2;
    }

    public static Object invoke(String vmByteCodeFile, Object[] args) {
        if (isDebuggingEnabled())
            Log.i(TAG, "Executing " + vmByteCodeFile);
        try {
            byte[] readByteCode = readByteCode(vmByteCodeFile);
            long currentTimeMillis = System.currentTimeMillis();
            Object executeVM = executeVM(readByteCode, args);
            if (isDebuggingEnabled())
                Log.i(TAG, String.format("Finished executing %s after %d ms.", vmByteCodeFile, Long.valueOf(System.currentTimeMillis() - currentTimeMillis)));
            return executeVM;
        } catch (IOException e) {
            throw new VMRunnerException("Error while loading bytecode.", e);
        }
    }
  ...
}
```

The code parts we need are 
```java
    public static native Object executeVM(byte[] vmCode, Object[] args);

    static {
        System.loadLibrary("pairipcore");
    }
    ...

    public static Object invoke(String vmByteCodeFile, Object[] args) ...
```
`executeVM` is the native method, which implementation can be found in the native C++ library, `libpairipcore.so`. Problem lies in that symbols are stripped, so we must use our brain and internet to find the address of it. Let's use frida-server for that (of course our application will crash, but before we can hook import of native JNI method.
```javascript
function find_RegisterNatives() {
  let symbols = Module.enumerateSymbolsSync("libart.so");
  let addrRegisterNatives = null;

  for (let i = 0; i < symbols.length; i++) {
    let symbol = symbols[i];

    if (symbol.name.indexOf("art") >= 0 && symbol.name.indexOf("JNI") >= 0 && symbol.name.indexOf("RegisterNatives") >= 0 && symbol.name.indexOf("CheckJNI") < 0) {
      addrRegisterNatives = symbol.address;

      hook_RegisterNatives(addrRegisterNatives);
    }
  }
}

function hook_RegisterNatives(addrRegisterNatives) {
  if (addrRegisterNatives != null) {
    Interceptor.attach(addrRegisterNatives, {
      onEnter(args) {
        // let executeVM = NULL;
        let class_name = Java.vm.tryGetEnv().getClassName(args[1]);
        let methods_ptr = ptr(args[2]);
        let method_count = parseInt(args[3]);
  
        for (let i = 0; i < method_count; i++) {
          let name_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3));
          let sig_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize));
          let fnPtr_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2));

          let name = Memory.readCString(name_ptr);
          let sig = Memory.readCString(sig_ptr);
          let symbol = DebugSymbol.fromAddress(fnPtr_ptr);

          if (name == "executeVM") {
            // executeVM = parseInt(symbol.toString().split("!")[1]);
            console.log(`[RegisterNatives] class: ${class_name}, name: ${name} signature: ${sig}, fnPtr: ${fnPtr_ptr}, fnOffset: ${symbol}, callee: ${DebugSymbol.fromAddress(this.returnAddress)}`);
            break;
          }
        }
      }
    });
  }
}

rpc.exports.init = find_RegisterNatives;
```
Output will be like this:
`[RegisterNatives] class: com.pairip.VMRunner, name: executeVM signature: ([B[Ljava/lang/Object;)Ljava/lang/Object;, fnPtr: 0x701ef730c8, fnOffset: 0x701ef730c8 libpairipcore.so!0x560c8, callee: 0x701ef71414 libpairipcore.so!0x54414`

In `fnOffset` at the end we see offset of `exeecuteVM` in pairipcore native library.
Now many people will say:
> We can just strip the Java code, C++ library and everything is ready!

No, Google aren't stupid and the pairipcore mechanism is complicated: to prevent removing of the Java code and binary they used neat trick: pairipcore creates pseudo-VM files which are needed for program work, those files typically lie in `assets` folder. Program uses the `invoke` method which accordingly calls the `executeVM` function, offset of which we found before:
![image_2024-04-03_19-33-27](https://github.com/Solaree/pairipcore/assets/115794865/4402e086-de0c-40a5-b9a6-799d575bd4f1)

Congratulations! The Java part is finished! What's next?

### Native Library

Now we are moving into the deep `libpairipcore.so`. If you will try to find the `executeVM` function by its offset in untouched library, you will find nothing. But why? The technique is that the library fixes up functions and changes offset in runtime (probably code decryption too) to prevent static analysis. You can use [PADumper](https://github.com/BryanGIG/PADumper) to dump the binary from process. After we open the dumped binary in [IDA Pro](https://hex-rays.com/ida-pro/) or other interactive disassembler.

*For comfort i renamed some functions with meaningful names*

We can find 2 interesting functions in `executeVM`:
![image_2024-04-03_19-38-28](https://github.com/Solaree/pairipcore/assets/115794865/d825c993-7591-42e6-bbbc-65f4c4084f9a)
![image_2024-04-03_19-38-06](https://github.com/Solaree/pairipcore/assets/115794865/01e96066-e41d-4806-b495-68e52b2a5419)

First one is near the function start, second lies at the end. First one does some kind of iteration through [`/proc/self/maps`](https://stackoverflow.com/questions/1401359/understanding-linux-proc-pid-maps-or-proc-self-maps). It's very big and not actually useful for now, we will back to it later. We are interested in the second function, let's open it:
```c
__int64 __fastcall protections_main(__int64 a1, __int16 a2)
{
  unsigned int v2; // w8
  int v4; // w0

  v2 = 0;
  switch ( a2 )
  {
    case 0:
      v4 = sub_3347C(a1);
      goto LABEL_100;
    case 3:
      v4 = sub_357E0(a1);
      goto LABEL_100;
    case 5:
      v4 = sub_355D8(a1);
      goto LABEL_100;
    case 6:
      v4 = openat_1(a1);
      goto LABEL_100;
    case 8:
      v4 = sub_3A03C(a1);
      goto LABEL_100;
    case 10:
      v4 = sub_3DD6C(a1);
      goto LABEL_100;
    case 11:
      v4 = sub_32084(a1);
      goto LABEL_100;
    case 13:
      v4 = sub_31D00(a1);
      goto LABEL_100;
    case 16:
      v4 = sub_3E08C(a1);
      goto LABEL_100;
    case 17:
      v4 = sub_3804C(a1);
      goto LABEL_100;
    case 18:
      v4 = sub_36260(a1);
      goto LABEL_100;
    case 19:
      v4 = sub_3B33C(a1);
      goto LABEL_100;
    case 20:
      v4 = sub_31E34(a1);
      goto LABEL_100;
    case 21:
      v4 = sub_3AD48(a1);
      goto LABEL_100;
    case 22:
      v4 = sub_37F18(a1);
      goto LABEL_100;
    case 24:
      v4 = sub_32318(a1);
      goto LABEL_100;
    case 26:
      v4 = lseek_iter_1(a1);
      goto LABEL_100;
    case 27:
      v4 = sub_3F608(a1);
      goto LABEL_100;
    case 28:
      v4 = sub_3B0FC(a1);
      goto LABEL_100;
    case 30:
      v4 = sub_3840C(a1);
      goto LABEL_100;
    case 31:
      v4 = sub_3129C(a1);
      goto LABEL_100;
    case 32:
      v4 = sub_338E0(a1);
      goto LABEL_100;
    case 33:
      v4 = sub_30504(a1);
      goto LABEL_100;
    case 34:
      v4 = sub_3A194(a1);
      goto LABEL_100;
    case 35:
      v4 = sub_40098(a1);
      goto LABEL_100;
    case 36:
      v4 = sub_325EC(a1);
      goto LABEL_100;
    case 37:
      v4 = sub_35904(a1);
      goto LABEL_100;
    case 38:
      v4 = sub_36784(a1);
      goto LABEL_100;
    case 39:
      v4 = sub_30194(a1);
      goto LABEL_100;
    case 40:
      v4 = close_1(a1);
      goto LABEL_100;
    case 41:
      v4 = sub_31F58(a1);
      goto LABEL_100;
    case 42:
      v4 = sub_3247C(a1);
      goto LABEL_100;
    case 43:
      v4 = sub_3B230(a1);
      goto LABEL_100;
    case 46:
      v4 = sub_350BC(a1);
      goto LABEL_100;
    case 47:
      v4 = sub_32A18(a1);
      goto LABEL_100;
    case 48:
      v4 = sub_378A8(a1);
      goto LABEL_100;
    case 49:
      v4 = antidebugger(a1);
      goto LABEL_100;
    case 50:
      v4 = close_2(a1);
      goto LABEL_100;
    case 51:
      v4 = sub_3AFB8(a1);
      goto LABEL_100;
    case 53:
      v4 = sub_34E50(a1);
      goto LABEL_100;
    case 54:
      v4 = sub_35C84(a1);
      goto LABEL_100;
    case 55:
      v4 = sub_313D0(a1);
      goto LABEL_100;
    case 57:
      v4 = sub_36650(a1);
      goto LABEL_100;
    case 58:
      v4 = sub_3F4B0(a1);
      goto LABEL_100;
    case 62:
      v4 = dlsym_sysprop_check_3(a1);
      goto LABEL_100;
    case 63:
      v4 = fstatfs_check(a1);
      goto LABEL_100;
    case 65:
      v4 = sub_3F760(a1);
      goto LABEL_100;
    case 66:
      v4 = lseek_iter_2(a1);
      goto LABEL_100;
    case 70:
      v4 = sub_35B50(a1);
      goto LABEL_100;
    case 72:
      v4 = sub_33A4C(a1);
      goto LABEL_100;
    case 73:
      v4 = dlclose_libc(a1);
      goto LABEL_100;
    case 74:
      v4 = getdents64_check(a1);
      goto LABEL_100;
    case 75:
      v4 = sub_34690(a1);
      goto LABEL_100;
    case 76:
      v4 = sub_38538(a1);
      goto LABEL_100;
    case 77:
      v4 = sub_34C6C(a1);
      goto LABEL_100;
    case 79:
      v4 = fstat_check(a1);
      goto LABEL_100;
    case 80:
      v4 = dlopen_libc(a1);
      goto LABEL_100;
    case 82:
      v4 = sub_30B3C(a1);
      goto LABEL_100;
    case 83:
      v4 = sub_34180(a1);
      goto LABEL_100;
    case 84:
      v4 = sub_37A74(a1);
      goto LABEL_100;
    case 85:
      v4 = sub_302C0(a1);
      goto LABEL_100;
    case 87:
      v4 = sub_35438(a1);
      goto LABEL_100;
    case 88:
      v4 = sub_39214(a1);
      goto LABEL_100;
    case 89:
      v4 = sub_37538(a1);
      goto LABEL_100;
    case 91:
      v4 = sub_37DD0(a1);
      goto LABEL_100;
    case 92:
      v4 = dlsym_check_2(a1);
      goto LABEL_100;
    case 93:
      v4 = read_check_1(a1);
      goto LABEL_100;
    case 94:
      v4 = sub_37664(a1);
      goto LABEL_100;
    case 95:
      v4 = sub_30A74(*(_QWORD *)(a1 + 8));
      goto LABEL_100;
    case 96:
      v4 = sub_37C30(a1);
      goto LABEL_100;
    case 97:
      v4 = sub_382D8(a1);
      goto LABEL_100;
    case 99:
      v4 = sub_36C00(a1);
      goto LABEL_100;
    case 100:
      v4 = sub_36890(a1);
      goto LABEL_100;
    case 101:
      v4 = sub_32720(a1);
      goto LABEL_100;
    case 103:
      v4 = dlsym_check_1(a1);
      goto LABEL_100;
    case 104:
      v4 = unknown_syscall(a1);
      goto LABEL_100;
    case 106:
      v4 = sub_3F358(a1);
      goto LABEL_100;
    case 107:
      v4 = lseek_iter_3(a1);
      goto LABEL_100;
    case 108:
      v4 = sub_351C8(a1);
      goto LABEL_100;
    case 109:
      v4 = sub_39704(a1);
      goto LABEL_100;
    case 112:
      v4 = sub_32CEC(a1);
      goto LABEL_100;
    case 117:
      v4 = sub_369BC(a1);
      goto LABEL_100;
    case 118:
      v4 = sub_34F84(a1);
      goto LABEL_100;
    case 119:
      v4 = sub_3651C(a1);
      goto LABEL_100;
    case 120:
      v4 = sub_3ABCC(a1);
      goto LABEL_100;
    case 121:
      v4 = sub_35A3C(a1);
      goto LABEL_100;
    case 122:
      v4 = sub_321DC(a1);
      goto LABEL_100;
    case 123:
      v4 = sub_33F3C(a1);
      goto LABEL_100;
    case 126:
      v4 = openat_2(a1);
      goto LABEL_100;
    case 127:
      v4 = sub_34074(a1);
      goto LABEL_100;
    case 128:
      v4 = clock_gettime_check(a1);
      goto LABEL_100;
    case 129:
      v4 = sub_3779C(a1);
      goto LABEL_100;
    case 130:
      v4 = sub_3DC58(a1);
      goto LABEL_100;
    case 131:
      v4 = sub_352F8(a1);
      goto LABEL_100;
    case 132:
      v4 = sub_38180(a1);
      goto LABEL_100;
    case 133:
      v4 = sub_33BAC(a1);
      goto LABEL_100;
    case 136:
      v4 = sub_3AE7C(a1);
      goto LABEL_100;
    case 137:
      v4 = sub_3B448(a1);
LABEL_100:
      v2 = 1;
      *(_DWORD *)(*(_QWORD *)(a1 + 8) + 20LL) = v4;
      break;
    default:
      return v2;
  }
  return v2;
}
```
Looks very suspicious. In fact it's another Google's attempt to prevent reverse engineer make code analysis. The `switch` statement contains security checks mixed up with some obfuscated code which will be executed in runtime. To better understand how control flow works there, i suggest you to try yourself emulation, which can be done with both [QEMU](https://www.qemu.org/) or [Unicorn](https://www.unicorn-engine.org/).

---
Let's explore the initial function passed here
```c
    case 49:
      v4 = antidebugger(a1);
      goto LABEL_100;
```

The anit-debugger function is partially obfuscated, so I will show here only the needed code
```c
  v16 = syscall(167LL, 3LL);
  syscall(167LL, 4LL, 1LL);
  syscall(167LL, 1499557217LL, -1LL);
  v17 = syscall(220LL, 0LL, 0LL, 0LL, 0LL);
  v18 = v17;
  v31 = v11;
  if ( (v17 & 0x80000000) != 0 )
    goto LABEL_21;
  if ( v17 )
  {
    LODWORD(v37[0]) = 0;
    while ( 1 )
    {
      v19 = syscall(260LL, v18, v37, 0x80000000LL, 0LL);
      if ( v19 != -1 )
        break;
      if ( *(_DWORD *)_errno() != 4 )
        goto LABEL_21;
    }
    if ( (v19 & 0x80000000) != 0 )
      goto LABEL_21;
    if ( !v19 || (v37[0] & 0x7F) != 0 )
    {
      syscall(129LL, v18, 9LL);
LABEL_21:
      v23 = -1;
      goto LABEL_22;
    }
    v23 = -BYTE1(v37[0]);
  }
  else
  {
    v20 = syscall(173LL);
    v21 = syscall(117LL, 16LL, v20);
    if ( (v21 & 0x80000000) != 0 )
      syscall(93LL, (unsigned int)-v21);
    LODWORD(v37[0]) = 0;
    do
    {
      while ( 1 )
      {
        while ( (unsigned int)syscall(260LL, v20, v37, 0x40000000LL, 0LL) == -1 && *(_DWORD *)_errno() == 4 )
          ;
        if ( (~LODWORD(v37[0]) & 0x7F) == 0 )
          break;
        syscall(93LL, 1LL);
      }
      v22 = BYTE1(v37[0]);
      if ( BYTE1(v37[0]) == 19 )
        break;
      syscall(117LL, 7LL, v20, 0LL, BYTE1(v37[0]));
    }
    while ( v22 != 19 );
    v37[0] = 0LL;
    syscall(117LL, 2LL, v20, &v34, v37);
    syscall(117LL, 5LL, v20, &v35, v37[0]);
    syscall(117LL, 17LL, v20, 0LL, 0LL);
    syscall(93LL, 0LL);
    v23 = 0;
  }
LABEL_22:
  syscall(167LL, 1499557217LL, 0LL);
  syscall(167LL, 4LL, v16);
```

At first you might not understand something, but actually here all the anti-debugger code. I've made simple hook script with frida and let's check what actually executed from there
```c
prctl(PR_GET_DUMPABLE, 0x7fd7ccaf80);
prctl(PR_SET_DUMPABLE, 1);
prctl(PR_SET_PTRACER, -1);
clone(0, 0, 0, 0);
waitpid(31085, -674451440, -2147483648);
prctl(PR_SET_PTRACER, 0);
prctl(PR_SET_DUMPABLE, 0);
```
This is old technique with different variations so I wont stop just there, if you are interested how that works you might look at Promon Shield [reversal analysis](https://github.com/KiFilterFiberContext/promon-reversal/blob/main/README.md#anti-debugging).

After the child cloned, it's process used for executing `/proc/self/maps` and `/proc/self/status` checks, more detailed about calls in the [*basics*](https://github.com/Solaree/pairipcore/edit/master/README.md#basics) block. After read/lseek iteration it crashes, if it finds injected Frida in own process. Unlike Promon Shield, its easily bypassable with just sending `SIGKILL` signal to the child after `waitpid`:
```c
wait(21595, -117863808, -2147483648);
kill(21595, 9);
```
If we will do this, stuff execution from main process will be continued, and we will see the first `dlopen`/`dlsym` calls
```c
dlopen(libc.so, 1) -> 0x9a2e2c9d02c6298b
dlsym(0x9a2e2c9d02c6298b, __system_property_read_callback) -> 0x758a0bd314
```
Pairipcore dynamically imports system prop function from libc which used after for a **VERY** big iteration of `access`/`__system_property_read_callback` functions, it checks all your device properties to make sured its real device and not some kind of emulator
```c
access(/dev/__properties__/u:object_r:aaudio_config_prop:s0, 4) -> 0
__system_property_read_callback(aaudio.mmap_policy, 2, 16777216)
__system_property_read_callback(aaudio.hw_burst_min_usec, 2000, 67108864)
__system_property_read_callback(aaudio.mmap_exclusive_policy, 2, 16777216)
access(/dev/__properties__/u:object_r:adbd_config_prop:s0, 4) -> 0
access(/dev/__properties__/u:object_r:apexd_select_prop:s0, 4) -> 0
access(/dev/__properties__/u:object_r:arm64_memtag_prop:s0, 4) -> 0
access(/dev/__properties__/u:object_r:audio_prop:s0, 4) -> 0
access(/dev/__properties__/u:object_r:binder_cache_bluetooth_server_prop:s0, 4) -> 0
__system_property_read_callback(cache_key.display_info, 184545039018960877, 301990044)
__system_property_read_callback(cache_key.package_info, 184545039018961014, 301990440)
__system_property_read_callback(cache_key.system_server.accounts_data, 184545039018960757, 301989936)
__system_property_read_callback(cache_key.system_server.account_user_data, 184545039018961002, 301990468)
__system_property_read_callback(cache_key.system_server.get_credential_type, 184545039018960539, 301989920)
__system_property_read_callback(cache_key.system_server.device_policy_manager_caches, 184545039018960221, 301989894)
__system_property_read_callback(cache_key.is_interactive, 184545039018960875, 301989902)
__system_property_read_callback(cache_key.is_user_unlocked, 184545039018960230, 301989902)
__system_property_read_callback(cache_key.location_enabled, 184545039018960148, 301989888)
__system_property_read_callback(cache_key.has_system_feature, 184545039018960135, 301989888)
__system_property_read_callback(cache_key.is_power_save_mode, 184545039018960149, 301989890)
__system_property_read_callback(cache_key.get_packages_for_uid, 184545039018960981, 301990426)
__system_property_read_callback(cache_key.is_compat_change_enabled, 184545039018961011, 301990012)
access(/dev/__properties__/u:object_r:binder_cache_telephony_server_prop:s0, 4) -> 0
...
```
In same function after go others checks with usage of `opendir`, `readdir`, `closedir`, `__system_property_read` for critical directories check.
 
Finally, goes frida-server check. Funny that it doesnt check for port or `progname` but probably uses some kind of messaging/sending packets to the server. I didn't finish exploring those checks because I used interesting trick of rebuilding binary and reconstructing `executeVM` function to strip those calls, I guess pairipcore does root check too .

## Final
I hope you enjoyed this journey and liked this kind of security researching, see you again! Someday...

### Help
Questions? **solarnik** (Discord)
My discord server: [https://discord.gg/qeGbmR6b9b](https://discord.gg/qeGbmR6b9b "https://discord.gg/qeGbmR6b9b")
