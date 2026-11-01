# Setting up OQS-OpenSSH client for pqc-probe experimental SSH mode

For `pqc-probe probe --protocol ssh --mode both`, you need two `ssh` client
binaries: the mainline one (already on your laptop as `/usr/bin/ssh`) and
OQS-OpenSSH, which adds pre-standard PQ KEX algorithms the mainline client
doesn't know.

Tested on Ubuntu 24.04. ~15 min end to end.

## Prerequisites

- liboqs from the Week 2 setup, installed at `/opt/liboqs` with `-DCMAKE_INSTALL_LIBDIR=lib`
- `build-essential`, `zlib1g-dev`, `libssl-dev`, `autoconf`, `automake`, `git`

```bash
sudo apt-get install -y build-essential zlib1g-dev libssl-dev autoconf automake git
```

## Build OQS-OpenSSH

OQS-OpenSSH is a fork of OpenSSH that calls into liboqs for its PQ KEX
implementations. We install it to `/opt/oqs-openssh/` to keep it separate
from the system `ssh`.

```bash
cd /tmp
git clone --depth=1 --branch OQS-v8 https://github.com/open-quantum-safe/openssh.git oqs-openssh
cd oqs-openssh

autoreconf -fi
./configure \
    --prefix=/opt/oqs-openssh \
    --with-libs=-ldl \
    --with-ssl-dir=/opt/openssl-3.5 \
    --with-liboqs-dir=/opt/liboqs \
    --sysconfdir=/opt/oqs-openssh/etc
make -j$(nproc)
sudo make install
```

## Verify both clients

```bash
/usr/bin/ssh -V
#  OpenSSH_9.6p1 Ubuntu-3ubuntu13.19, OpenSSL 3.0.13 ...

/opt/oqs-openssh/bin/ssh -V
#  OpenSSH_X.Xp1 with OQS liboqs ...

# Check which KEX algorithms each supports
/usr/bin/ssh -Q kex 2>&1 | sort > /tmp/mainline-kex.txt
/opt/oqs-openssh/bin/ssh -Q kex 2>&1 | sort > /tmp/oqs-kex.txt
diff /tmp/mainline-kex.txt /tmp/oqs-kex.txt
# Expect: OQS lists several extra algorithms like
#   mlkem512-sha256
#   p256_mlkem512
#   x25519_mlkem512
#   sntrup761x25519-sha512
#   kyber512-sha256
#   ...
```

The diff above IS the first-cut answer to "what does OQS-OpenSSH add?" at
the client level. pqc-probe takes it further: it probes a specific target and
reports which of those extra algorithms the target actually accepts.

## Point pqc-probe at both

```bash
export PQC_PROBE_SSH=/usr/bin/ssh
export PQC_PROBE_SSH_OQS=/opt/oqs-openssh/bin/ssh

./target/release/pqc-probe probe github.com:22 --protocol ssh --mode both
```

Expected against github.com:22:
- Server offers: curve25519-sha256, ecdh-sha2-nistp256/384/521, diffie-hellman-group*,
  and (as of 2026) sntrup761x25519-sha512@openssh.com, mlkem768x25519-sha256
- Mainline client negotiates: whichever modern algorithms it knows (depends on
  Ubuntu version; 24.04 ships OpenSSH 9.6 which has sntrup761)
- OQS client negotiates: same + any OQS-specific names github happens to offer
  (unlikely — github serves standard mainline OpenSSH)

For a target that WOULD show a meaningful diff: an OQS-OpenSSH sshd (your
pqc-bench port 2222 bench instance, when running). That server advertises the
pre-standard `kyber*` and `frodo*` KEX names that mainline sshd doesn't offer.
Mainline client can see the names in the offer but can't negotiate them. OQS
client can.

## Troubleshooting

**`configure: error: *** liboqs not found`**
Pass the right `--with-liboqs-dir`. If liboqs lives at `/opt/liboqs/lib/x86_64-linux-gnu/`
(no `-DCMAKE_INSTALL_LIBDIR=lib` on your liboqs build), either rebuild liboqs
with that flag or pass the multiarch path explicitly.

**`error while loading shared libraries: liboqs.so.X`**
`/etc/ld.so.conf.d/liboqs.conf` not set up, or `ldconfig` not run. From the
Week 2 setup:
```bash
sudo bash -c 'echo /opt/liboqs/lib > /etc/ld.so.conf.d/liboqs.conf'
sudo ldconfig
```

**Probe hangs on first SSH call**
The target port is firewalled or down. Mainline ssh waits for `ConnectTimeout`
(5s per our args) then exits. If the probe hangs longer than that, check your
`--timeout` CLI flag.
