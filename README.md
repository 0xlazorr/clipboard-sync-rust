# Local Bi-Directional Clipboard Sync (Rust Edition)

I built this highly optimized, memory-efficient native Rust daemon to automatically sync text and images between my Linux host (X11 or Wayland) and my Android phone running Termux.

This repository contains the compiled native implementation, consuming only **~2MB of RAM** with zero runtime interpreter overhead.

---

## Features
*   **Automatic Text Sync:** Bi-directional clipboard syncing (Linux to Android, Android to Linux).
*   **Linux-to-Android Image Sync:** Copies images on Linux and saves them directly to your Android device's `/sdcard/Pictures/Clipboard_Sync/` folder, spawning a notification to open them.
*   **Native Performance:** Written in standard Rust using std threads, raw TCP streams, and minimal dependency footprint.
*   **Anti-Feedback loop logic:** Utilizes SHA-256 data hashing to ensure content received from a peer isn't echoed back, preventing infinite loops.
*   **Systemd Integration:** Out-of-the-box systemd user service templates for background execution.

---

## 1. Linux Setup (Host)

### Prerequisites
Install the required command-line clipboard manager for your windowing system:

```bash
# For Ubuntu/Debian/Linux Mint:
# If you are on Wayland:
sudo apt install wl-clipboard

# If you are on X11:
sudo apt install xclip
```

### Build the Project
Compile the project in release mode to generate the optimized binary:
```bash
cargo build --release
```
The compiled binary will be located at `./target/release/clipboard-sync`.

### Configuration
1. Locate your Android phone's local IP address (e.g. `192.168.1.100` via Wi-Fi Settings).
2. Edit [config.json](config.json):
   ```json
   {
       "peer_ip": "<ANDROID_PHONE_IP>",
       "port": 9999,
       "poll_interval": 1.0
   }
   ```

### Running the Daemon
You can run it manually:
```bash
./target/release/clipboard-sync
```

### Running as a Systemd Service (Background Daemon)
To configure it to run automatically on startup in the background:
1. Create the user systemd folder if it doesn't exist:
   ```bash
   mkdir -p ~/.config/systemd/user/
   ```
2. Copy the systemd service file:
   ```bash
   cp clipboard-sync.service ~/.config/systemd/user/clipboard-sync.service
   ```
3. Reload systemd and enable the service:
   ```bash
   systemctl --user daemon-reload
   systemctl --user enable --now clipboard-sync.service
   ```
4. Verify it is running:
   ```bash
   systemctl --user status clipboard-sync.service
   ```

---

## 2. Android Setup (Termux Client)

Since cross-compiling Rust binaries to target Android ARM64 architecture can be complex, the Android receiver runs a lightweight companion Python client inside Termux.

### Steps:
1.  Install **Termux** and the **Termux:API** companion app from F-Droid.
2.  Open Termux and install Python and the Termux API utilities:
    ```bash
    pkg update && pkg install python termux-api
    ```
3.  Grant Termux storage permissions:
    ```bash
    termux-setup-storage
    ```
4.  Copy [android_sync.py](android_sync.py) and [config.json](config.json) to your Android device.
5.  On the Android device, edit `config.json` to point `peer_ip` to your Linux machine's local IP address.
6.  Execute the script in Termux:
    ```bash
    python android_sync.py
    ```
7.  In the Termux notification dropdown, click **Acquire Wake Lock** and set Termux battery usage to **Unrestricted** in Android settings to prevent it from being killed in the background.

---

## 3. Security Guidelines

This utility is designed for trusted local connections and does not implement built-in transport encryption or authorization checks. 

*   **Do Not Run on Public Wi-Fi:** Avoid exposing the daemon port (`9999`) to untrusted physical subnets. Anyone on the same network could potentially intercept clipboard packets or write data to your clipboard.
*   **Expose Only via Secure VPNs (Tailscale):** The safest deployment is over an encrypted mesh network like **Tailscale**. Instead of listening on all interfaces (`0.0.0.0`), you can modify the socket listener in the code to bind only to your device's Tailscale interface IP.
*   **Local SSH Tunneling Forwarding:** For remote access, bind the listeners to localhost (`127.0.0.1`) and map them using an SSH port forward:
    ```bash
    ssh -L 9999:127.0.0.1:9999 user@your-linux-host
    ```
*   **DoS Mitigation:** To prevent Denial-of-Service attacks, the daemons (both Python and Rust versions) enforce a strict **25 MB payload size limit** to avoid arbitrary memory allocation exhaustion crashes.
