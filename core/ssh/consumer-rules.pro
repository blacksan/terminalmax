# Consumer R8/ProGuard rules for :core:ssh (sshj + BouncyCastle).
# sshj instantiates algorithms through named factories and BouncyCastle looks
# up implementations by class name, so both must survive shrinking.
-keep class net.schmizz.sshj.** { *; }
-keep class com.hierynomus.** { *; }
-keep class org.bouncycastle.** { *; }

# Optional / JVM-only references that do not exist on Android.
-dontwarn javax.naming.**
-dontwarn org.ietf.jgss.**
-dontwarn javax.security.auth.login.**
-dontwarn com.sun.jna.**
-dontwarn com.jcraft.jzlib.**
-dontwarn org.slf4j.impl.**
-dontwarn org.slf4j.**
