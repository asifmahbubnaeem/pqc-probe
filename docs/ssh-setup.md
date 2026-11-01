# Setting up OQS-OpenSSH client for pqc-probe experimental SSH mode

For `pqc-probe probe --protocol ssh --mode both`, you need two `ssh` client
binaries: the mainline one (already on your laptop as `/usr/bin/ssh`) and
OQS-OpenSSH, which adds pre-standard PQ KEX algorithms the mainline client
doesn't know.

Tested on Ubuntu 24.04 x86_64. ~15 min end to end. Builds OpenSSH 10.4 fork
with liboqs 2026-08 as of this writing.

## Prerequisites

- liboqs from `docs/oqs-setup.md` (Week 2), installed at `/opt/liboqs` with
  `-DCMAKE_INSTALL_LIBDIR=lib`
- OpenSSL 3.5.x installed at `/opt/openssl-3.5`
- Build toolchain:

```bash
sudo apt-get install -y build-essential zlib1g-dev libssl-dev autoconf automake git
```

## 1. Make the loader aware of your OpenSSL 3.5.x install

Required or the OQS-OpenSSH configure step hits "OpenSSL's headers do not
match your library" because it finds system `libssl.so.3` (OpenSSL 3.0.x)
instead of our 3.5.x build.

```bash
sudo bash -c 'echo /opt/openssl-3.5/lib > /etc/ld.so.conf.d/openssl-3.5.conf'
sudo ldconfig

# Verify
ldconfig -p | grep /opt/openssl-3.5
# Expect two lines showing libssl.so.3 and libcrypto.so.3 at /opt/openssl-3.5/lib/
```

## 2. Discover the latest OQS-OpenSSH branch

OQS-OpenSSH tracks upstream OpenSSH's version in branch names (`OQS-v8`,
`OQS-v9`, etc.). Pick the newest.

```bash
git ls-remote --heads https://github.com/open-quantum-safe/openssh \
    | grep -E 'OQS-v[0-9]' | sort -V | tail -5
# Use the highest OQS-vN shown.
```

## 3. Clone and configure

```bash
cd /tmp
git clone --depth=1 --branch OQS-v9 \
    https://github.com/open-quantum-safe/openssh.git oqs-openssh
cd oqs-openssh

autoreconf -fi

# CPPFLAGS forces compile against our 3.5.x headers.
# LDFLAGS + rpath forces link + runtime against our 3.5.x library.
CPPFLAGS="-I/opt/openssl-3.5/include" \
LDFLAGS="-L/opt/openssl-3.5/lib -Wl,-rpath,/opt/openssl-3.5/lib" \
./configure \
    --prefix=/opt/oqs-openssh \
    --with-libs=-ldl \
    --with-ssl-dir=/opt/openssl-3.5 \
    --with-liboqs-dir=/opt/liboqs \
    --sysconfdir=/opt/oqs-openssh/etc
```

Expected configure summary includes:

```
OpenSSH has been configured with the following options:
                     User binaries: /opt/oqs-openssh/bin
                       PAM support: no
                   libedit support: no
     Preprocessor flags: ... -I/opt/liboqs/include -I/opt/openssl-3.5/include ...
           Linker flags: ... -L/opt/liboqs/lib -L/opt/openssl-3.5/lib -Wl,-rpath,/opt/openssl-3.5/lib ...
              Libraries: -loqs -lcrypto -ldl
```

## 4. Build and install

```bash
make -j$(nproc)
sudo make install
```

## 5. Verify both clients

```bash
/usr/bin/ssh -V
#  OpenSSH_9.6p1 Ubuntu-3ubuntu13.19, OpenSSL 3.0.13 ...

/opt/oqs-openssh/bin/ssh -V
#  OpenSSH_10.4-2026-08_p1, Open Quantum Safe 2026-08, OpenSSL 3.5.2 ...
```

Compare which KEX each client supports:

```bash
/usr/bin/ssh -Q kex | sort > /tmp/mainline-kex.txt
/opt/oqs-openssh/bin/ssh -Q kex | sort > /tmp/oqs-kex.txt
diff /tmp/mainline-kex.txt /tmp/oqs-kex.txt | head -30
```

Expect OQS to list many extras (bike-*, classic-mceliece-*, frodokem-*,
kyber-*, and `ecdh-nistpN-X-sha256@openquantumsafe.org` hybrid variants).

## 6. Point pqc-probe at both

```bash
export PQC_PROBE_SSH=/usr/bin/ssh
export PQC_PROBE_SSH_OQS=/opt/oqs-openssh/bin/ssh

./target/release/pqc-probe probe github.com:22 --protocol ssh --mode both
```

Expected against github.com:22: diff shows what OQS-OpenSSH negotiates that
mainline ssh can't. Against github in late 2026 this is typically
`mlkem768x25519-sha256` and `sntrup761x25519-sha512` (standardized names
that newer mainline 9.9+ also has — OQS-OpenSSH tracks a newer upstream
base than Ubuntu 24.04 LTS's 9.6).

## Troubleshooting

**`configure: error: Your OpenSSL headers do not match your library`**  
Step 1's `ldconfig` or the CPPFLAGS/LDFLAGS environment vars were skipped.
Run them, then `make distclean && autoreconf -fi && ./configure ...` again.

**`fatal: Remote branch OQS-vN not found`**  
Branch name wrong. Rerun step 2's `git ls-remote` and use whatever shows up.

**`configure: error: *** liboqs not found`**  
liboqs installed to a multiarch path. Either rebuild it from `oqs-setup.md`
with `-DCMAKE_INSTALL_LIBDIR=lib`, or pass the real path to configure:
`--with-liboqs-dir=/opt/liboqs/lib/x86_64-linux-gnu`.

**`error while loading shared libraries: liboqs.so.X`**  
`/etc/ld.so.conf.d/liboqs.conf` missing or `ldconfig` not run. From
`oqs-setup.md`:
```bash
sudo bash -c 'echo /opt/liboqs/lib > /etc/ld.so.conf.d/liboqs.conf'
sudo ldconfig
```

**Probe hangs on first SSH call**  
Target port is firewalled or down. mainline ssh waits `ConnectTimeout` (5s)
then exits. If the probe hangs longer, check your `--timeout` flag.

**`a09ebb4f` or similar hash as server version**  
Normal — github's custom SSH server (babeld) returns a short commit SHA
rather than a human-readable version string. The probe reports whatever
openssh reads out of the server banner.
