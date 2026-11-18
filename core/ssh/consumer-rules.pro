# Consumer R8/ProGuard rules for :core:ssh (sshj + BouncyCastle).
# sshj instantiates algorithms through named factories, so its classes must survive shrinking.
-keep class net.schmizz.sshj.** { *; }
-keep class com.hierynomus.** { *; }

# BouncyCastle looks algorithm implementations up by class name, but only the provider packages
# need that. The rest of the library is reached by normal references and can be shrunk.
-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }
-keep class org.bouncycastle.pqc.jcajce.provider.** { *; }

# Optional / JVM-only references that do not exist on Android.
-dontwarn javax.naming.**
-dontwarn org.ietf.jgss.**
-dontwarn javax.security.auth.login.**
-dontwarn com.sun.jna.**
-dontwarn com.jcraft.jzlib.**
# slf4j-api 1.x looked up this binder class; slf4j 2.x (used here) does not, so this is only a
# safety net for an older slf4j-api arriving transitively. Other slf4j warnings stay visible.
-dontwarn org.slf4j.impl.**
