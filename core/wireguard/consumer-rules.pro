# JNI: the C side looks these methods up by their exact names.
-keep class org.terminalmax.core.wireguard.WgBridgeNative {
    native <methods>;
}
