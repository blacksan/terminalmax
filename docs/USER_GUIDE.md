# TerminalMax user guide

TerminalMax is **pre-alpha**. Do not store real credentials yet; see [SECURITY.md](../SECURITY.md).

## 1. Create a vault

The first time you start the app you see the welcome screen.

1. Choose **Create vault**.
2. Enter a vault password twice. The hint under the first field is only a rough estimate; a long passphrase of
   several words is best. **There is no way to recover the vault if you forget the password.**
3. Tap **Create vault**. Creating and later unlocking takes a few seconds on purpose.

Your hosts, keys and WireGuard profiles are stored in this vault, encrypted, in the app's private storage.
On Android the vault locks by itself after 5 minutes in the background (unless a session is open). Use
**Settings > Lock** to lock it yourself; that also disconnects all sessions. Quick unlock with a fingerprint
or the system keychain is not part of this release.

**Joining a vault you already have on another device** (after you set up WebDAV sync there): choose **Join
from WebDAV**, enter the WebDAV address, user name and password and the vault password, and tap **Download and
check**. The app shows a fingerprint and a revision number. Open TerminalMax on the other device and compare
them; tick the box and join only if they match. This comparison is the only protection against a server that
serves an old or foreign vault.

## 2. Add a WireGuard profile from a MikroTik client config

You need a WireGuard interface on the router and a peer entry for this device. On the router
(`/interface/wireguard/peers`), add a peer for the app with its own key pair and an `allowed-address` that
is a free address of the tunnel network, for example `10.99.0.2/32`. Write the client config for that peer from
the values on the router (or use a config generator you trust). It looks like this:

```
[Interface]
PrivateKey = <the peer's private key>
Address = 10.99.0.2/32

[Peer]
PublicKey = <the router interface's public key>
Endpoint = router.example.org:13231
AllowedIPs = 10.99.0.0/24
PersistentKeepalive = 25
```

In the app:

1. Open the **WireGuard** tab and tap **Import**.
2. Give the profile a name and paste the configuration, or tap **Choose file...**
3. Tap **Import**. The app checks that `[Interface]` has `PrivateKey` and `Address` and that every `[Peer]` has
   `PublicKey`, `Endpoint` and `AllowedIPs`, and tells you what is missing. The private key is stored encrypted
   and is never shown again.

The tunnel runs inside the app: no VPN permission, no administrator rights, and other apps do not use it.
`AllowedIPs` must include the address of the router you want to reach.

## 3. Add a router host

1. Open the **Hosts** tab and tap **Add host**.
2. **Name**: anything you like.
3. **WireGuard**: pick the profile if the router is only reachable through the tunnel. The address must then
   be an **IP address** inside the tunnel (for example `10.99.0.1`), not a name.
4. **Port** (22 unless you changed it), **user name**, and the login: a password (leave it empty for an
   account without one, such as the RouterOS `admin` default) or a pasted private key with an optional
   passphrase.
5. **SSH algorithms**: leave **Modern**. Only a very old router that fails with "no common algorithms" needs
   **Legacy**; it allows old, weaker algorithms, so prefer a tunnel for such a device. The app never switches
   to Legacy by itself.
6. **RouterOS console options** (optional): added to the user name, for example `+ct80w` gives a plain
   terminal 80 columns wide (the router then logs in as `admin+ct80w`).
7. Tap **Save**.

## 4. Connect

Tap the host. On the first connection the app shows the host key's type and SHA-256 fingerprint. Compare it
with the fingerprint of the router's host key, obtained by a means you trust (for example on the router's console), and tap **Trust and
connect**; the key is stored in the vault and checked on every later connection. If the key of a known host
ever changes, you get a red warning whose default action is **Cancel**; replace the stored key only if you
know why it changed (for example you reset the router).

Android shows the soft keyboard with a row of extra keys above it: Esc, Tab, Ctrl and Alt (tap once, they
apply to the next key only), the arrows, Home, End, PgUp, PgDn and `|`, `-`, `/`. The **Keyboard** button
shows or hides the keyboard. While sessions are open, a notification shows how many there are; keep it so that
Android does not stop the connections in the background. On the desktop, sessions show as tabs and Esc goes
back from every screen except a terminal.

**Sessions** lists everything that is open. **Disconnect** ends the connection but keeps the tab so that you
can **Reconnect**; **Close** removes it.

## 5. Sync with a WebDAV server

1. Open **Settings > Sync**.
2. Enter the WebDAV address (use https), the user name and the password. They are stored in the vault.
3. Tap **Test server**: it tells you whether the server works and supports safe conditional writes.
4. Tap **Sync now**. The first sync on the first device uploads the vault. On another device use **Join from
   WebDAV** (section 1).
5. Optionally turn on **Sync automatically** (when unlocking and 10 seconds after an edit). It is off by default.

The server only ever sees the encrypted vault file. The result of the last sync is shown in plain words. When
a sync needs a decision (a large change from the server, an older server copy, a changed vault key, replacing
the server copy) a dialog explains the situation and the cost of the action; the action is applied for that
one retry only. **Export backup...** saves the sealed vault file; keep it as carefully as the server copy,
because anyone who has it can try to guess your password offline.

If a device is lost, changing the vault password revokes it for everything written afterwards, and you must
also change the WebDAV password. (A screen for changing the password is not part of this release.)
