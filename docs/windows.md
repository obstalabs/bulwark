# Bulwark on Windows

## Status

Bulwark does not run on native Windows. It runs unchanged inside a Linux guest on a
Windows host, because the gate lives in the Linux kernel of that guest. If a Windows
machine is all you have, the agent goes into a Linux guest and Bulwark guards it
there; an agent started natively on Windows is not gated by anything on this page.

Everything below was measured on a Windows 11 Pro workstation in November 2026. What
we did not measure is listed at the end, not written as an instruction.

## Why not native Windows

Bulwark decides at the moment a file is opened, inside the kernel. On Linux that is
fanotify or Landlock, on macOS Endpoint Security. On Windows the same decision point
is a file-system minifilter driver, and what stands between that and a product is
set by Microsoft, not by Bulwark:

- **A kernel driver must be signed through the Hardware Dev Center.** Since
  Windows 10 1607, Windows loads no new kernel-mode driver the portal did not sign,
  and an EV certificate is required to open the account.
- **Attestation signing covers desktop editions and is for testing.** Microsoft's driver
  signing page says it "only works on Windows 10 Desktop and later versions of
  Windows" and is offered "for testing purposes only".
- **Windows Server loads only drivers that passed the Hardware Lab Kit.** "Windows
  Server 2016 and greater doesn't accept attested device and filter driver signing
  submissions" and "only loads dashboard signed drivers that successfully pass the
  HLK tests".
- **A minifilter altitude is allocated by email.** Microsoft asks for "30 business
  days to process" and offers "no mechanism to request an altitude outside of the
  process".
- **The code is not portable yet.** Building for Windows fails on the Unix-only
  calls that every platform shares today.

So native Windows is a second kernel product with its own signing program. It is
research, not a port, and nothing here promises it.

Sources: Microsoft Learn, "Driver Signing Options", "Driver Signing Policy",
"Request a Filter Altitude Identifier".

## How to run agents on a Windows machine today

Two profiles. Start with the first; the second is a convenience with limits you
should read before you rely on it.

### Profile A: a Hyper-V Linux guest (start here)

Windows 11 Pro includes Hyper-V. The agent, its login and Bulwark all live in a
Linux guest; your editor on Windows attaches to it over SSH. From nothing to a
working guest took us under ten minutes, most of it the image download.

1. **Check that Hyper-V is on** (elevated PowerShell). It should answer `Enabled`.

   ```powershell
   (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All).State
   ```

2. **Get a Linux disk in Hyper-V's format.** We took the official Debian 13 cloud
   image (`debian-13-generic-amd64.qcow2` from cloud.debian.org, checked against its
   `SHA512SUMS`), converted it, and built a small first-boot disk that creates one
   user with your SSH public key. Both commands run on any Linux:

   ```sh
   qemu-img convert -f qcow2 -O vhdx -o subformat=dynamic \
     debian-13-generic-amd64.qcow2 agent-guest.vhdx
   genisoimage -output seed.iso -volid cidata -joliet -rock user-data meta-data
   ```

   `user-data` (put your own public key in):

   ```yaml
   #cloud-config
   hostname: agent-guest
   users:
     - name: dev
       groups: sudo
       shell: /bin/bash
       sudo: "ALL=(ALL) NOPASSWD:ALL"
       lock_passwd: true
       ssh_authorized_keys:
         - ssh-ed25519 AAAA...your-key
   ssh_pwauth: false
   ```

   `meta-data`:

   ```yaml
   instance-id: agent-guest-001
   local-hostname: agent-guest
   ```

3. **Create and start the guest** (PowerShell; no elevation needed if your user is
   in the Hyper-V Administrators group):

   ```powershell
   Resize-VHD -Path C:\vm\agent-guest.vhdx -SizeBytes 12GB
   New-VM -Name agent-guest -Generation 2 -MemoryStartupBytes 4GB `
     -VHDPath C:\vm\agent-guest.vhdx -SwitchName 'Default Switch'
   Set-VMProcessor -VMName agent-guest -Count 2
   Set-VMMemory -VMName agent-guest -DynamicMemoryEnabled $false
   Set-VMFirmware -VMName agent-guest -EnableSecureBoot On `
     -SecureBootTemplate MicrosoftUEFICertificateAuthority
   Add-VMDvdDrive -VMName agent-guest -Path C:\vm\seed.iso
   Set-VM -Name agent-guest -AutomaticCheckpointsEnabled $false -CheckpointType Standard
   Start-VM -Name agent-guest
   ```

4. **Find its address and log in.** The image does not report its address to
   Hyper-V, so read it from the neighbour table by the guest's MAC:

   ```powershell
   $mac = (Get-VMNetworkAdapter -VMName agent-guest).MacAddress -replace '(..)(?!$)', '$1-'
   Get-NetNeighbor -AddressFamily IPv4 | Where-Object LinkLayerAddress -eq $mac
   ssh dev@<address>
   ```

5. **Install Bulwark and the agent in the guest.** Bulwark from the
   [Releases page](https://github.com/obstalabs/bulwark/releases), checked against
   its published checksum:

   ```sh
   V=0.11.0; B=bulwark-$V-x86_64-unknown-linux-gnu.tar.gz
   curl -fsSLO https://github.com/obstalabs/bulwark/releases/download/v$V/$B
   curl -fsSLO https://github.com/obstalabs/bulwark/releases/download/v$V/$B.sha256
   sha256sum -c $B.sha256
   tar -xzf $B && sudo install -m 755 bulwark-$V-x86_64-unknown-linux-gnu/bulwark /usr/local/bin/bulwark
   ```

   The agent by its own instructions; log it in from inside the guest.

6. **Attach your editor directly from Windows.** Add a `Host agent-guest` entry
   with that address, user and key to your SSH configuration, then:

   ```powershell
   code --remote ssh-remote+agent-guest /home/dev/project
   ```

   The first attach installs the editor's server in the guest and took about two
   minutes; after that `git status` answered in 2 to 3 ms and the terminal felt
   immediate.

7. **Run the agent under the gate.** Name what it must not read:

   ```sh
   sudo env HOME=$HOME bulwark run \
     --protect /srv/keys \
     --receipts ~/receipts.jsonl \
     -- <your agent command>
   ```

   Pass `HOME` through as shown: under plain `sudo` the agent is dropped back to
   your user but keeps root's home directory, and then cannot find its own login.
   In the Linux guest a protected directory covers what is nested below it and
   files added or moved into it during the run; we did not test hard links made
   from outside, symlinks, a bind mount over the directory, or files the agent
   writes there itself.
   A read of a protected file fails inside the agent with
   `Operation not permitted`; the gate prints a `deny` line and writes a receipt.
   The receipts file belongs to root, so read it with `sudo cat ~/receipts.jsonl`:

   ```json
   {"ts_ms":1794807762472,"pid":1258,"dev":2049,"ino":133454,"decision":"deny","source":"static","path":"/srv/keys/deploy.key","ancestry":"cat(1258) <- sh(1257) <- bulwark(1252) <- sudo(1248) <- bash(1204) <- sshd-session(1203) <- sshd-session(1183) <- sshd(790)","reason":"denied"}
   ```

8. **Keep a clean checkpoint and go back to it.** Take it before the agent's first
   job; reverting took under 20 seconds until the guest answered on SSH again.

   ```powershell
   Checkpoint-VM -Name agent-guest -SnapshotName clean
   Restore-VMCheckpoint -VMName agent-guest -Name clean -Confirm:$false
   ```

With the editor attached and a job running, the guest used about 0.8 GB of the 4 GB
we gave it.

### Profile B: a dedicated WSL2 distribution (a convenience profile)

A WSL2 distribution starts in seconds and needs no virtual machine of its own. It
also shares more with the rest of the machine than it looks; read the next section
before you put anything valuable in it. Use a distribution of its own for agents,
never the one you do other work in.

1. **Import a root filesystem as its own distribution** (PowerShell). We used the
   official Ubuntu 24.04 WSL image from cloud-images.ubuntu.com, checked against
   its `SHA256SUMS`.

   ```powershell
   wsl --import agents D:\wsl\agents ubuntu-noble-wsl-amd64-24.04lts.rootfs.tar.gz
   ```

2. **Keep the Windows drives and Windows programs out, and stop being root.** A
   fresh import starts every session as root. The image ships a regular user,
   `ubuntu`; name it (or your own) as the default. In the distribution's
   `/etc/wsl.conf` (root-owned), then `wsl --terminate agents` and start it again:

   ```ini
   [boot]
   systemd=true

   [automount]
   enabled=false
   mountFsTab=false

   [interop]
   enabled=false
   appendWindowsPath=false

   [user]
   default=ubuntu
   ```

3. **Give agents their own user.** Your user holds your logins; the agent user holds
   none of them and is in no privileged group. Both get a group-friendly umask, so
   a project tree can be shared by group:

   ```sh
   sudo groupadd dev
   sudo useradd -m -s /bin/bash -U -G dev agent
   sudo usermod -aG dev "$USER"
   sudo install -d -o root -g dev -m 2775 /srv/dev
   echo 'umask 002' | sudo tee /etc/profile.d/umask-dev.sh
   sudo git config --system --add safe.directory /srv/dev/project
   ```

   Open a new session so the new group and umask apply (in the same session the
   next line fails with `Permission denied`), then:

   ```sh
   git init --shared=group /srv/dev/project
   ```

4. **Attach the editor over SSH, not through the drive share.** With the drives
   unmounted, VS Code's WSL attach does not work and the `\\wsl.localhost` share is
   gone; an SSH server inside the distribution, bound to loopback and key-only,
   does work. The image has no SSH server, and the package opens port 22 on every
   address the moment it is installed, so switch that off straight away:

   ```sh
   sudo apt-get update && sudo apt-get install -y openssh-server
   sudo systemctl disable --now ssh.socket ssh.service
   mkdir -p ~/.ssh && chmod 700 ~/.ssh
   echo 'ssh-ed25519 AAAA...your-key' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
   ```

   A separate configuration file, `/etc/ssh/sshd_agents.conf`:

   ```
   Port 2222
   ListenAddress 127.0.0.1
   PasswordAuthentication no
   AllowAgentForwarding no
   AllowUsers ubuntu
   UsePAM yes
   ```

   Start it. The directory is on a temporary filesystem, so both commands are
   needed again after every restart of the distribution:

   ```sh
   sudo mkdir -p /run/sshd && sudo /usr/sbin/sshd -f /etc/ssh/sshd_agents.conf
   ```

   From Windows: `code --remote ssh-remote+<host entry for localhost port 2222> /srv/dev/project`.

5. **Start agents as the agent user, with the shared mount point hidden.** Every
   WSL2 distribution sees the same `/mnt/wsl`; an unprivileged wrapper hides it:

   ```sh
   sudo apt-get install -y bubblewrap
   bwrap --dev-bind / / --tmpfs /mnt/wsl --remount-ro /mnt/wsl -- <your agent command>
   ```

6. **Close the Windows host to the distribution** (elevated PowerShell):

   ```powershell
   New-NetFirewallRule -DisplayName 'Block inbound from WSL' -Direction Inbound `
     -Action Block -Profile Any -InterfaceAlias 'vEthernet (WSL (Hyper-V firewall))'
   ```

7. **Check the state at the start of a session.** As the agent user, all of these
   must hold: `ls /mnt/c` is empty; `grep -E '9p|drvfs' /proc/mounts` shows only the
   read-only driver store; `echo ${WSL_INTEROP:-unset}` prints `unset`; `id -Gn`
   lists only the user's own group and `dev`; `sudo -n true` fails.

Bulwark itself starts and denies inside a WSL2 distribution the same way it does on
any Linux. The limits below are about the distribution, and they are why this
profile is a convenience and the guest is the answer.

## What each profile does not protect

### The Hyper-V guest

- **A guest you keep keeps everything.** Whatever the agent wrote, installed or
  changed is still there next session. Only a revert undoes it.
- **A reverted guest loses logins and work.** The checkpoint we took predated the
  agent's login, so the revert removed the login and the agent's commits with it.
  Copy work out, and expect to log in again, before every revert.
- **An attached editor follows the guest.** Our editor window reconnected by itself
  seconds after the revert and reinstalled its server.
- **Inside the guest, the agent is your user, and your user's service manager is
  outside the gate.** In the steps above the agent runs as the one guest user.
  Bulwark denies the agent's own reads of the files you named, but the agent can
  ask that user's systemd to run a command for it, and that command is not
  supervised: in our test a single `systemd-run --user` call read a protected file
  in full, and no receipt was written. A named secret is therefore not safe from a
  determined agent in this setup. `sudo` inside a run is refused (the agent runs
  with no-new-privileges). Running the agent as a separate user with
  `--worker-uid <uid>` closed the route in our test, as long as that user had no
  service manager of its own running (no login session for it). The route needs
  the user D-Bus session (`dbus-user-session` on Debian), which most installs
  have.

### The WSL2 distribution

- **One network stack for every distribution.** A listener on loopback in any
  distribution is reachable from the agent's, including your editor's own listener.
  A packet filter loaded "inside" one distribution applies to all of them, and
  root in any of them can remove it.
- **One shared mount point.** `/mnt/wsl` is the same directory in every
  distribution and writable by any user; with Docker Desktop running it holds that
  product's control sockets. The agent's own sandbox, where it has one, did not
  hide it; the wrapper in step 5 does.
- **A check at session start says nothing about later.** The configuration file
  and the running state can differ in both directions until the next restart, and
  another distribution or a host change can widen things mid-session. Nothing in
  this profile watches continuously.
- **The Windows host's LAN address.** The firewall rule closes the host on the
  WSL adapter. The host's address on your network, and other machines on it,
  stayed reachable from the distribution; a filter listing private address ranges
  stopped working the moment the Wi-Fi network changed.
- **Credentials inside the distribution.** A login the agent's user can read is a
  login the agent can use. One of the three agents we ran has no sandbox of its
  own, one keeps provider keys in the environment of every tool call, and another
  one's sandbox reads every credential file. Keep forge and other push credentials
  out of the agent's user altogether.
- **The shared project tree.** With a tree shared by group, the agent's user can
  write the repository's git configuration and hooks, which your own `git` then
  runs.
- **The same service-manager route.** The distribution runs systemd, and a user's
  systemd runs commands outside the gate. With Bulwark in this profile, an agent
  running as your user read a protected file through one `systemd-run --user`
  call. Run as the separate `agent` user (`--worker-uid`), it could not, until a
  shell was open as that user (`wsl -u agent`), which starts that user's own
  service manager; then it could.
- **Windows-native processes.** Nothing here touches a program started on Windows
  itself.

## Use cases: why not just a VM for everything

A plain guest already gives you two things: the agent cannot reach the Windows
host's files, and a revert resets it. If the guest holds nothing worth protecting,
that is enough and Bulwark adds nothing. Bulwark matters once the work needs
secrets *inside* the guest.

| Situation | A plain VM | With Bulwark in the guest |
| --- | --- | --- |
| The job needs a deploy key, cloud credentials or an `.env` in the guest, and the agent works in the same tree | The agent can read all of it | The files you name are denied by inode while the rest of the tree stays usable ([Usage](../README.md#usage), [choosing a mode](modes-and-wrapping.md)) |
| You want to know afterwards what the agent went for | Nothing records it | A receipts file names the protected file, the process chain that asked, and that it was denied ([policy and receipts](policy-receipts.md)) |
| The agent legitimately needs one protected file, once | All or nothing: mount the secret or do not | You are asked over a channel the agent cannot answer, and can allow that single read ([off-band consent](offband-consent.md)) |
| An unattended job, where the gate process itself might be killed | Not applicable | `--hardened` puts the read floor in the kernel, so killing the launcher does not widen access ([hardened mode](hardened-mode.md)) |
| The work runs on a remote or CI Linux host, where no VM stands between the job and that host's secrets | A VM on your desk does not help there | `bulwark ssh` enforces on the remote kernel and asks you locally ([remote enforcement](remote.md)) |
| You do not know yet what an agent reads | Nothing shows you | `bulwark watch` enforces nothing and reports every open and what you would protect ([Quick start](../README.md#quick-start)) |
| A throwaway guest with no secrets in it, reverted after every job | Enough | Nothing to add |
| Keeping the agent away from the Windows host's own files | Enough: the guest cannot see them | Nothing to add |
| Getting back to a known-clean state | Enough: revert the checkpoint | Nothing to add |

## Known limits and what is not yet measured

- **One machine, one edition.** Windows 11 Pro, a Debian 13 guest on kernel 6.12,
  WSL 2.2.4 with its 5.15 kernel and NAT networking. Other editions, Windows
  Server and mirrored WSL networking are not measured.
- **Not built: a hand-over of credentials to a fresh guest, and a path for work
  out of it.** Today that is you logging in and copying out by hand.
- **Not measured: a separate agent user inside the guest**, an egress policy for
  the guest, and `bulwark ssh --hardened` against it.
- **Not measured: containers.** Docker Desktop and devcontainers as the place to
  run agents were not tried.
- **Not measured in the WSL2 profile:** a whole agent job run through the wrapper
  of step 5; what the editor's loopback listener accepts from another user;
  removable and network drives; a drive attached after the distribution started.
- **A separate Windows user is not a substitute.** We tried it: it closes your
  profile to the agent and leaves the rest of the machine readable, and every
  per-user tool and login has to be set up again.
