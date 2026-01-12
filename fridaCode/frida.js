

function hooken(){
    // frida-hook.js
    Java.perform(function() {
        // Hook Coded 类
        var Coded = Java.use('com.immomo.momo.util.jni.Coded');

        // Hook aesEncode 方法
        Coded["aesEncode"].implementation = function (inputData, inputLen, keyData, keyLen, outputBuffer) {

            console.log("\n===== AES ENCODE HOOK =====");
            console.log("Input Data: " + bytesToHex(inputData).substring(0, 100) + "...");
            console.log("Input Data: " + inputData);


            console.log("Input Length: " + inputLen);
            console.log("Key Data: " + bytesToHex(keyData).substring(0, 50) + "...");
            console.log("Key Data: " + keyData);

            console.log("Key Length: " + keyLen);

            // 调用原始方法
            var result = this.aesEncode(inputData, inputLen, keyData, keyLen, outputBuffer);

            // 提取加密结果
            // var encryptedData = outputBuffer.slice(0, result);
            // console.log("Encrypted Data: " + bytesToHex(encryptedData).substring(0, 100) + "...");
            console.log("Output Length: " + result);

            return result;
        };

        // // Hook sign 方法
        // Coded.sign.overload('[B', '[B').implementation = function(data, key) {
        //     console.log("\n===== SIGN HOOK =====");
        //     console.log("Sign Data: " + bytesToHex(data).substring(0, 100) + "...");
        //     console.log("Sign Key: " + bytesToHex(key).substring(0, 50) + "...");

        //     // 调用原始方法
        //     var result = this.sign(data, key);

        //     console.log("Signature: " + result);
        //     return result;
        // };

        // // Hook c() 方法
        // var TargetClass = Java.use('com.immomo.momoenc.TargetClass'); // 替换为实际类名
        // TargetClass.c.implementation = function() {
        //     console.log("\n===== c() METHOD HOOK =====");
        //     console.log("Secret Key (f75235d): " + this.f75235d.value);
        //     console.log("Params (j): " + JSON.stringify(this.j.value));

        //     // 调用原始方法
        //     this.c();
        // };

        // 辅助函数：字节数组转十六进制
        function bytesToHex(buffer) {
            return Array.from(new Uint8Array(buffer))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        }
    });
}


/*
* frida检测绕过
* 1.获取pthread的函数地址
* 2.定义pthread的NativaFuncaiton
* 3.进行函数替换,将原函数替换为自己写的函数
*    自己写的函数里对参数2进行判断;参数2就是线程回调函数地址
*    如果出现目标地址,则直接返回,也就是不进行线程的创建
*    如果未出现目标函数,则调用原函数,创建线程
* 4.进行hook,同时打印函数地址,查看那个函数执行完毕frida会退出
*/
function hook_pthread() {
    var pt_create_func = Module.findExportByName(null,'pthread_create');//获取函数地址
    //console.log('pt_create_func:',pt_create_func);
    var pthread_create = new NativeFunction(pt_create_func,"int",["pointer","pointer","pointer","pointer"])
    Interceptor.replace( //替换函数
        pt_create_func,new NativeCallback(function(arg0,arg1,arg2,arg3)
        {
            // console.log(arg2.toString())          //打印函数地址，找到frida检测的线程就可以不用输出函数地址了
            if (arg2.toString().indexOf("ee4") != -1)//对每个可疑地址进行试错
            {
                console.log("success") //如果返回成功且主程序未退出则表示找到frida检测的线程
                return 1; //有可能返回0
            }
            return pthread_create(arg0,arg1,arg2,arg3) //其他的正常调用原来的
        },"int",["pointer","pointer","pointer","pointer"])
    )
}

//hook dlopen函数
function hook_dlopenExt(soName) {
    //找到dlopen的函数地址
    var addr = Module.findExportByName(null, "android_dlopen_ext");
    Interceptor.attach(addr, {
        onEnter: function(args){
            //得到so的路径(路径里包含so的name);dlopen的第一个参数就是so的路径
            var soPath = args[0].readCString();
            //判断路径是否包含目标so名称
            if(soPath.indexOf(soName) != -1){
                //给一个标识,代表可以hook了,不能在onEnter里做hook,因为这时候so还没被加载;
                this.hook = true;
            }
        }, onLeave: function(retval){
            //这时候so已经被加载了,所以可以开始hook了
            if(this.hook){
                console.log("123");
                //hook函数
                //hookFunc(soName);
            }
        }
    });
}

//hook okhttp3的证书检测方法,绕过证书检测,让它可以抓包
function hook_ssl(){

    Java.perform(function() {
        /*
            抓包检测的话有些是vpn检测,有些就是通过系统证书来进行检测的
            主要对一些证书检测的函数做hook,这样可以让程序不检测证书
            hook list:
            1.SSLcontext
            2.okhttp
            3.webview
            4.XUtils
            5.httpclientandroidlib
            6.JSSE
            7.network\_security\_config (android 7.0+)
            8.Apache Http client (support partly)
            9.OpenSSLSocketImpl
            10.TrustKit
            11.Cronet
        */

            // Attempts to bypass SSL pinning implementations in a number of
            // ways. These include implementing a new TrustManager that will
            // accept any SSL certificate, overriding OkHTTP v3 check()
            // method etc.
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            var quiet_output = false;

            // Helper method to honor the quiet flag.

            function quiet_send(data) {

                if (quiet_output) {

                    return;
                }

                //send(data)
            }


            // Implement a new TrustManager
            // ref: https://gist.github.com/oleavr/3ca67a173ff7d207c6b8c3b0ca65a9d8
            // Java.registerClass() is only supported on ART for now(201803). 所以android 4.4以下不兼容,4.4要切换成ART使用.
            /*
        06-07 16:15:38.541 27021-27073/mi.sslpinningdemo W/System.err: java.lang.IllegalArgumentException: Required method checkServerTrusted(X509Certificate[], String, String, String) missing
        06-07 16:15:38.542 27021-27073/mi.sslpinningdemo W/System.err:     at android.net.http.X509TrustManagerExtensions.<init>(X509TrustManagerExtensions.java:73)
                at mi.ssl.MiPinningTrustManger.<init>(MiPinningTrustManger.java:61)
        06-07 16:15:38.543 27021-27073/mi.sslpinningdemo W/System.err:     at mi.sslpinningdemo.OkHttpUtil.getSecPinningClient(OkHttpUtil.java:112)
                at mi.sslpinningdemo.OkHttpUtil.get(OkHttpUtil.java:62)
                at mi.sslpinningdemo.MainActivity$1$1.run(MainActivity.java:36)
        */
            var X509Certificate = Java.use("java.security.cert.X509Certificate");
            var TrustManager;
            try {
                TrustManager = Java.registerClass({
                    name: 'org.wooyun.TrustManager',
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function(chain, authType) {},
                        checkServerTrusted: function(chain, authType) {},
                        getAcceptedIssuers: function() {
                            // var certs = [X509Certificate.$new()];
                            // return certs;
                            return [];
                        }
                    }
                });
            } catch (e) {
                //quiet_send("registerClass from X509TrustManager >>>>>>>> " + e.message);
            }

            // Prepare the TrustManagers array to pass to SSLContext.init()
            var TrustManagers = [TrustManager.$new()];

            try {
                // Prepare a Empty SSLFactory
                var TLS_SSLContext = SSLContext.getInstance("TLS");
                TLS_SSLContext.init(null, TrustManagers, null);
                var EmptySSLFactory = TLS_SSLContext.getSocketFactory();
            } catch (e) {
                //quiet_send(e.message);
            }

            //send('Custom, Empty TrustManager ready');

            // Get a handle on the init() on the SSLContext class
            var SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');

            // Override the init method, specifying our new TrustManager
            SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {

                quiet_send('Overriding SSLContext.init() with the custom TrustManager');

                SSLContext_init.call(this, null, TrustManagers, null);
            };

            /*** okhttp3.x unpinning ***/


            // Wrap the logic in a try/catch as not all applications will have
            // okhttp as part of the app.
            try {

                var CertificatePinner = Java.use('okhttp3.CertificatePinner');
                quiet_send('OkHTTP 3.x Found');
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
                    quiet_send('OkHTTP 3.x check() called. Not throwing an exception.');
                }

                var OkHttpClient$Builder = Java.use('okhttp3.OkHttpClient$Builder');
                quiet_send('OkHttpClient$Builder Found');
                //console.log("hostnameVerifier", OkHttpClient$Builder.hostnameVerifier);
                OkHttpClient$Builder.hostnameVerifier.implementation = function () {
                    quiet_send('OkHttpClient$Builder hostnameVerifier() called. Not throwing an exception.');
                    return this;
                }

                var myHostnameVerifier = Java.registerClass({
                    name: 'com.dawang.MyHostnameVerifier',
                    implements: [HostnameVerifier],
                    methods: {
                        verify: function (hostname, session) {
                            return true;
                        }
                    }
                });

                var OkHttpClient = Java.use('okhttp3.OkHttpClient');
                OkHttpClient.hostnameVerifier.implementation = function () {
                    quiet_send('OkHttpClient hostnameVerifier() called. Not throwing an exception.');
                    return myHostnameVerifier.$new();
                }

            } catch (err) {

                // If we dont have a ClassNotFoundException exception, raise the
                // problem encountered.
                if (err.message.indexOf('ClassNotFoundException') === 0) {

                    throw new Error(err);
                }
            }

            // Appcelerator Titanium PinningTrustManager

            // Wrap the logic in a try/catch as not all applications will have
            // appcelerator as part of the app.
            try {

                var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');

                send('Appcelerator Titanium Found');

                PinningTrustManager.checkServerTrusted.implementation = function() {

                    quiet_send('Appcelerator checkServerTrusted() called. Not throwing an exception.');
                }

            } catch (err) {

                // If we dont have a ClassNotFoundException exception, raise the
                // problem encountered.
                if (err.message.indexOf('ClassNotFoundException') === 0) {

                    throw new Error(err);
                }
            }

            /*** okhttp unpinning ***/


            try {
                var OkHttpClient = Java.use("com.squareup.okhttp.OkHttpClient");
                OkHttpClient.setCertificatePinner.implementation = function(certificatePinner) {
                    // do nothing
                    quiet_send("OkHttpClient.setCertificatePinner Called!");
                    return this;
                };

                // Invalidate the certificate pinnet checks (if "setCertificatePinner" was called before the previous invalidation)
                var CertificatePinner = Java.use("com.squareup.okhttp.CertificatePinner");
                CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(p0, p1) {
                    // do nothing
                    quiet_send("okhttp Called! [Certificate]");
                    return;
                };
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(p0, p1) {
                    // do nothing
                    quiet_send("okhttp Called! [List]");
                    return;
                };
            } catch (e) {
                quiet_send("com.squareup.okhttp not found");
            }

            /*** WebView Hooks ***/

            /* frameworks/base/core/java/android/webkit/WebViewClient.java */
            /* public void onReceivedSslError(Webview, SslErrorHandler, SslError) */
            var WebViewClient = Java.use("android.webkit.WebViewClient");

            WebViewClient.onReceivedSslError.implementation = function(webView, sslErrorHandler, sslError) {
                quiet_send("WebViewClient onReceivedSslError invoke");
                //执行proceed方法
                sslErrorHandler.proceed();
                return;
            };

            WebViewClient.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function(a, b, c, d) {
                quiet_send("WebViewClient onReceivedError invoked");
                return;
            };

            WebViewClient.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function() {
                quiet_send("WebViewClient onReceivedError invoked");
                return;
            };

            /*** JSSE Hooks ***/

            /* libcore/luni/src/main/java/javax/net/ssl/TrustManagerFactory.java */
            /* public final TrustManager[] getTrustManager() */
            /* TrustManagerFactory.getTrustManagers maybe cause X509TrustManagerExtensions error  */
            // var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
            // TrustManagerFactory.getTrustManagers.implementation = function(){
            //     quiet_send("TrustManagerFactory getTrustManagers invoked");
            //     return TrustManagers;
            // }

            var HttpsURLConnection = Java.use("com.android.okhttp.internal.huc.HttpsURLConnectionImpl");
            HttpsURLConnection.setSSLSocketFactory.implementation = function(SSLSocketFactory) {
                quiet_send("HttpsURLConnection.setSSLSocketFactory invoked");
            };
            HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
                quiet_send("HttpsURLConnection.setHostnameVerifier invoked");
            };

            /*** Xutils3.x hooks ***/
            //Implement a new HostnameVerifier
            var TrustHostnameVerifier;
            try {
                TrustHostnameVerifier = Java.registerClass({
                    name: 'org.wooyun.TrustHostnameVerifier',
                    implements: [HostnameVerifier],
                    method: {
                        verify: function(hostname, session) {
                            return true;
                        }
                    }
                });

            } catch (e) {
                //java.lang.ClassNotFoundException: Didn't find class "org.wooyun.TrustHostnameVerifier"
                //quiet_send("registerClass from hostnameVerifier >>>>>>>> " + e.message);
            }

            try {
                var RequestParams = Java.use('org.xutils.http.RequestParams');
                RequestParams.setSslSocketFactory.implementation = function(sslSocketFactory) {
                    sslSocketFactory = EmptySSLFactory;
                    return null;
                }

                RequestParams.setHostnameVerifier.implementation = function(hostnameVerifier) {
                    hostnameVerifier = TrustHostnameVerifier.$new();
                    return null;
                }

            } catch (e) {
                quiet_send("Xutils hooks not Found");
            }

            /*** httpclientandroidlib Hooks ***/
            try {
                var AbstractVerifier = Java.use("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier");
                AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String', '[Ljava.lang.String', 'boolean').implementation = function() {
                    quiet_send("httpclientandroidlib Hooks");
                    return null;
                }
            } catch (e) {
                quiet_send("httpclientandroidlib Hooks not found");
            }

            /***
        android 7.0+ network_security_config TrustManagerImpl hook
        apache httpclient partly
        ***/
            var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            // try {
            //     var Arrays = Java.use("java.util.Arrays");
            //     //apache http client pinning maybe baypass
            //     //https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#471
            //     TrustManagerImpl.checkTrusted.implementation = function (chain, authType, session, parameters, authType) {
            //         quiet_send("TrustManagerImpl checkTrusted called");
            //         //Generics currently result in java.lang.Object
            //         return Arrays.asList(chain);
            //     }
            //
            // } catch (e) {
            //     quiet_send("TrustManagerImpl checkTrusted nout found");
            // }

            try {
                // Android 7+ TrustManagerImpl
                TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                    quiet_send("TrustManagerImpl verifyChain called");
                    // Skip all the logic and just return the chain again :P
                    //https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2017/november/bypassing-androids-network-security-configuration/
                    // https://github.com/google/conscrypt/blob/c88f9f55a523f128f0e4dace76a34724bfa1e88c/platform/src/main/java/org/conscrypt/TrustManagerImpl.java#L650
                    return untrustedChain;
                }
            } catch (e) {
                quiet_send("TrustManagerImpl verifyChain nout found below 7.0");
            }
            // OpenSSLSocketImpl
            try {
                var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
                OpenSSLSocketImpl.verifyCertificateChain.implementation = function(certRefs, authMethod) {
                    quiet_send('OpenSSLSocketImpl.verifyCertificateChain');
                }

                quiet_send('OpenSSLSocketImpl pinning')
            } catch (err) {
                quiet_send('OpenSSLSocketImpl pinner not found');
            }
            // Trustkit
            try {
                var Activity = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
                Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(str) {
                    quiet_send('Trustkit.verify1: ' + str);
                    return true;
                };
                Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(str) {
                    quiet_send('Trustkit.verify2: ' + str);
                    return true;
                };

                quiet_send('Trustkit pinning')
            } catch (err) {
                quiet_send('Trustkit pinner not found')
            }

            try {
                //cronet pinner hook
                //weibo don't invoke

                var netBuilder = Java.use("org.chromium.net.CronetEngine$Builder");

                //https://developer.android.com/guide/topics/connectivity/cronet/reference/org/chromium/net/CronetEngine.Builder.html#enablePublicKeyPinningBypassForLocalTrustAnchors(boolean)
                netBuilder.enablePublicKeyPinningBypassForLocalTrustAnchors.implementation = function(arg) {

                    //weibo not invoke
                    console.log("Enables or disables public key pinning bypass for local trust anchors = " + arg);

                    //true to enable the bypass, false to disable.
                    var ret = netBuilder.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
                    return ret;
                };

                netBuilder.addPublicKeyPins.implementation = function(hostName, pinsSha256, includeSubdomains, expirationDate) {
//                    console.log("cronet addPublicKeyPins hostName = " + hostName);

                    //var ret = netBuilder.addPublicKeyPins.call(this,hostName, pinsSha256,includeSubdomains, expirationDate);
                    //this 是调用 addPublicKeyPins 前的对象吗? Yes,CronetEngine.Builder
                    return this;
                };

            } catch (err) {
                //console.log('[-] Cronet pinner not found')
            }
        });

}

// hook WebView的构造和setWebContentsDebuggingEnabled方法,开启调试
function hook_WebView(){
    console.log("hook_WebView Start !!! ");
    Java.perform(function (){
        var WebView = Java.use('android.webkit.WebView');

        WebView.$init.overload('android.content.Context').implementation = function (a){
            console.log("webView.$init is called!");
            var retval = this.$init(a);
            this.setWebContentsDebuggingEnabled(true);
            return retval;
        }
        WebView.$init.overload('android.content.Context', 'android.util.AttributeSet').implementation = function (a,b){
            console.log("webView.$init is called!");
            var retval = this.$init(a,b);
            this.setWebContentsDebuggingEnabled(true);
            return retval;
        }
        WebView.$init.overload('android.content.Context', 'android.util.AttributeSet', 'int').implementation = function (a,b,c){
            console.log("webView.$init is called!");
            var retval = this.$init(a,b,c);
            this.setWebContentsDebuggingEnabled(true);
            return retval;
        }
        WebView.$init.overload('android.content.Context', 'android.util.AttributeSet', 'int', 'int').implementation = function (a,b,c,d){
            console.log("webView.$init is called!");
            var retval = this.$init(a,b,c,d);
            this.setWebContentsDebuggingEnabled(true);
            return retval;
        }
        WebView.setWebContentsDebuggingEnabled.implementation = function (){
            this.setWebContentsDebuggingEnabled(true);
            console.log("setWebContentsDebuggingEnabled is called!");
        }

        // var SysWebView = Java.use("io.dcloud.common.adapter.ui.webview.SysWebView");
        // console.log(SysWebView.setWebViewData);
        // SysWebView.setWebViewData.implementation = function (){
        //     console.log("setWebContentsDebuggingEnabled is called!");
        // }
    });

    Java.perform(function (){
        var WebView = Java.use('android.webkit.WebView');

        WebView.$init.overload('android.content.Context').implementation = function (a){
            console.log("webView.$init is called!");
            var retval = this.$init(a);
            this.setWebContentsDebuggingEnabled(true);
            return retval;
        }
        WebView.$init.overload('android.content.Context', 'android.util.AttributeSet').implementation = function (a,b){
            console.log("webView.$init is called!");
            var retval = this.$init(a,b);
            this.setWebContentsDebuggingEnabled(true);
            return retval;
        }
        WebView.$init.overload('android.content.Context', 'android.util.AttributeSet', 'int').implementation = function (a,b,c){
            console.log("webView.$init is called!");
            var retval = this.$init(a,b,c);
            this.setWebContentsDebuggingEnabled(true);
            return retval;
        }
        WebView.$init.overload('android.content.Context', 'android.util.AttributeSet', 'int', 'int').implementation = function (a,b,c,d){
            console.log("webView.$init is called!");
            var retval = this.$init(a,b,c,d);
            this.setWebContentsDebuggingEnabled(true);
            return retval;
        }
        WebView.setWebContentsDebuggingEnabled.implementation = function (){
            this.setWebContentsDebuggingEnabled(true);
            console.log("setWebContentsDebuggingEnabled is called!");
        }

        // var SysWebView = Java.use("io.dcloud.common.adapter.ui.webview.SysWebView");
        // console.log(SysWebView.setWebViewData);
        // SysWebView.setWebViewData.implementation = function (){
        //     console.log("setWebContentsDebuggingEnabled is called!");
        // }
    });
}

// 监控so的加载
function hook_dlopen(){
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
    {
        onEnter: function (args) {
            // android_dlopen_ext 的第一个参数是so的路径指针
            var pathptr = args[0];
            var path = ptr(pathptr).readCString();
            if(path.indexOf("libmsaoaidsec") > -1){
                hook_constrcutor();
            }
        }
    });
}

// 文件访问监控脚本
function hook_file(){
    // file_monitor.js
    Java.perform(function() {
        var FileInputStream = Java.use("java.io.FileInputStream");
        var File = Java.use("java.io.File");

        // Hook 文件创建
        File.$init.overload('java.lang.String').implementation = function(path) {
            console.log("[File Created] " + path);
            if (path.indexOf("/proc") >= 0 || path.indexOf("/system") >= 0) {
                console.log("[!] Accessing system file: " + path);
                send(JSON.stringify({
                    type: 'file_access',
                    path: path,
                    timestamp: new Date().toISOString()
                }));
            }
            return this.$init(path);
        };

        // Hook 文件读取
        FileInputStream.$init.overload('java.io.File').implementation = function(file) {
            var path = file.getAbsolutePath();
            console.log("[File Read] " + path);
            if (path.indexOf("/proc") >= 0) {
                var stack = Java.use("android.util.Log").getStackTraceString(
                    Java.use("java.lang.Exception").$new()
                );
                console.log("[!] Reading proc file: " + path);
                console.log(stack);
            }
            return this.$init(file);
        };
    });
}


// Java层hook方法示例
function hookTest(){
    console.log(`HookTest ! `)
    Java.perform(function(){
        let NetworkParams = Java.use("com.bytedance.frameworks.baselib.network.http.NetworkParams");
        console.log(`NetworkParams ${NetworkParams}`)

        //调用目标函数
        var instance = NetworkParams.$new();
        var retval = NetworkParams.tryAddSecurityFactor.overload('java.lang.String', 'java.util.Map').call(instance, s1, s2);
        console.log(`ret : ${retval}`);

        //转为Java的Map对象
        var hashmap = Java.cast(retval,Java.use("java.util.HashMap"))
        //直接toString方法输出
        console.log(hashmap.toString())
    })
}


/**
    这也是一个frida绕过的方法;
    Hook Android linker 中的 call_constructors 函数
    当目标 SO 库 libmsaoaidsec.so 被加载时，替换其内部偏移 0x123F0 处的函数为一个空函数
**/
// 标志位，防止多次替换
var isHooked = false;
// 方法开始
function hook_constrcutor(){
    // 枚举linker64的符号表，找到 call_constructor 函数
    // var symbols = Process.findModuleByName("linker").enumerateSymbols();
    var linker = Process.findModuleByName("linker64") ||
                    Process.findModuleByName("linker");

    if (!linker) {
        console.error("[-] Failed to find linker module!");
        return;
    }
    // 找linker模块
    var symbols = linker.enumerateSymbols();

    // 在这里开始找函数(这是SO初始化时调用的构造函数;负责执行 .init_array 等)
    var call_constructors = null;
    for (let i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        if (symbol.name.indexOf("_dl__ZN6soinfo17call_constructorsEv") > -1){
            call_constructors = symbol.address;
        }
    }
    console.log("find call_constructors func arr:\t", call_constructors);

    Interceptor.attach(call_constructors,{
        // 必须要在执行前做
        onEnter:function (args){
        // 这里判断了一下,检查当前hook的so是否是libmsaoaidsec.so
        var target_soAddr = Module.findBaseAddress("libmsaoaidsec.so");
            if(target_soAddr != null){
                if (!isHooked){
                    isHooked = true;
                    // 这里直接使用NativeCallback,来创建了一个空函数替代原函数
                    Interceptor.replace(target_soAddr.add(0x123F0), new NativeCallback(function (){
                        // 替换成功后打印一下日志
                        console.log(`0x123F0 replace Success！`)
                    },"void",[]))
                }
            }
        }
    });
}

function hook_doPost(){
    // 定位目标类
    var httpClass = Java.use("com.immomo.momo.protocol.http.a.a");
    console.log('Hello !! ')
    // Hook post 方法
    httpClass.post.overload(
        'java.lang.String',
        'java.util.Map',
        '[Lcom.immomo.http.a;',
        'java.util.Map',
        'int',
        'boolean'
    ).implementation = function(url, params, processors, headers, timeout, flag) {
        console.log("\n===== [HTTP POST REQUEST] =====");

        // 打印基本参数
        console.log("URL: " + url);
        console.log("Timeout: " + timeout);
        console.log("Flag: " + flag);

        // 打印请求参数
        console.log("\n[Request Parameters]");
        if (params) {
            var paramKeys = params.keySet().toArray();
            for (var i = 0; i < paramKeys.length; i++) {
                var key = paramKeys[i];
                var value = params.get(key);
                console.log("  " + key + ": " + value);
            }
        } else {
            console.log("  (null)");
        }

        // 打印请求头
        if (headers) {
            try {
                console.log("\n[Request Headers----------------------]");
                // 更安全的遍历方式
                var headerIterator = headers.entrySet().iterator();
                while (headerIterator.hasNext()) {
                    var entry = headerIterator.next();
                    console.log("  " + entry.getKey() + ": " + entry.getValue());
                }
            } catch (e) {
                console.log("  Error printing headers: " + e);

                // 备选方法
                try {
                    console.log("  Headers content: " + headers.toString());
                } catch (e2) {
                    console.log("  Failed to print headers");
                }
            }
        } else {
            console.log("  (null)");
        }
    }
}

function post() {
    Java.perform(function () {
        let a = Java.use("com.immomo.momo.protocol.http.a.a");
        var stringBuilder = Java.use("java.lang.StringBuilder");
        a["doPost"].overload('java.lang.String', 'java.util.Map', '[Lcom.immomo.http.a;', 'java.util.Map', 'int', 'boolean', 'boolean').implementation = function (str, map, aVarArr, map2, i, z, z2) {
            console.log(`a.doPost is called: str=${str}, map=${map}, aVarArr=${aVarArr}, map2=${map2}, i=${i}, z=${z}, z2=${z2}`);
            //自己遍历HashMap
            var key  = map.keySet(); //得到HashMap里面所有的key值
            var it = key.iterator(); //得到迭代器
            var resultMap  = stringBuilder.$new();//
            while(it.hasNext()){ //迭代器循环
                var keystr = it.next(); //取出key
                var valuestr = map.get(keystr);//获取对应的值
                resultMap.append(valuestr);//将值放到stringBuilder
            }
            // 由于Map它已经定义好了toString的方法,所以可以直接打印
            console.log("shufferMap\t",resultMap.toString());


            let result = this["doPost"](str, map, aVarArr, map2, i, z, z2);
            console.log(`a.doPost result=${result}`);
            return result;
        };
    });
}

function main(){
    Java.perform(function(){
        hook_dlopen()
        // hook_ssl();
        // hook_doPost()
        //hook_pthread()
    })
}

setImmediate(main)

// frida -U -f com.immomo.momo -l momo.js -o log.txt
// frida -H 127.0.0.1:2333 -l momo.js -f com.immomo.momo -o log.txt


// frida -U -f com.whty.wicity.china -l momo.js -o log.txt

