# Setting up oqs-provider for pqc-probe experimental mode

For `pqc-probe probe --mode experimental` or `--mode both`, you need a second
OpenSSL binary with oqs-provider activated. Here's how to build it alongside
your existing OpenSSL 3.5.x install.

Tested on Ubuntu 24.04 x86_64 and arm64 (ThinkPad E14 Gen 6, c7g.large).
~15 min end to end.

## Prerequisites

- Existing `/opt/openssl-3.5/bin/openssl` from Week 1
- `cmake`, `ninja-build`, `git` on `$PATH`

```bash
sudo apt-get install -y cmake ninja-build git
```

## 1. Build liboqs

**Important:** pass `-DCMAKE_INSTALL_LIBDIR=lib` explicitly. Otherwise CMake's
`GNUInstallDirs` module picks a multiarch path (e.g. `lib/x86_64-linux-gnu`),
and oqs-provider's `find_package(liboqs)` won't find the cmake config.

```bash
cd /tmp
git clone --depth=1 --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
cmake -S . -B build -GNinja \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_USE_OPENSSL=OFF \
    -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
    -DCMAKE_INSTALL_LIBDIR=lib
cmake --build build
sudo cmake --install build

# Verify the cmake config landed at the expected path
find /opt/liboqs -name "liboqsConfig.cmake"
# Expect: /opt/liboqs/lib/cmake/liboqs/liboqsConfig.cmake

sudo bash -c 'echo /opt/liboqs/lib > /etc/ld.so.conf.d/liboqs.conf'
sudo ldconfig
```

## 2. Build oqs-provider against your existing OpenSSL 3.5.x

```bash
cd /tmp
git clone --depth=1 --branch main https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
cmake -S . -B build -GNinja \
    -DOPENSSL_ROOT_DIR=/opt/openssl-3.5 \
    -Dliboqs_DIR=/opt/liboqs/lib/cmake/liboqs \
    -DCMAKE_INSTALL_PREFIX=/opt/openssl-3.5 \
    -DCMAKE_INSTALL_LIBDIR=lib
cmake --build build
sudo cmake --install build

# Verify
ls -la /opt/openssl-3.5/lib/ossl-modules/oqsprovider.so
```

## 3. Create the oqs-enabled openssl.cnf

We want vanilla and experimental to coexist. Separate config file, pointed
to at probe time via `OPENSSL_CONF`.

```bash
sudo mkdir -p /opt/openssl-3.5/ssl-oqs
sudo tee /opt/openssl-3.5/ssl-oqs/openssl.cnf > /dev/null <<'CNF'
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
CNF
```

## 4. Create the openssl-oqs wrapper

```bash
sudo tee /opt/openssl-3.5/bin/openssl-oqs > /dev/null <<'EOF'
#!/usr/bin/env bash
exec env OPENSSL_CONF=/opt/openssl-3.5/ssl-oqs/openssl.cnf \
    /opt/openssl-3.5/bin/openssl "$@"
EOF
sudo chmod +x /opt/openssl-3.5/bin/openssl-oqs
```

Two binaries now:

- `/opt/openssl-3.5/bin/openssl` — vanilla (default-only)
- `/opt/openssl-3.5/bin/openssl-oqs` — oqs-provider activated

## 5. Verify both stacks

```bash
/opt/openssl-3.5/bin/openssl list -providers
#  default only

/opt/openssl-3.5/bin/openssl-oqs list -providers
#  default AND oqsprovider
```

## 6. Point pqc-probe at both

```bash
export PQC_PROBE_OPENSSL=/opt/openssl-3.5/bin/openssl
export PQC_PROBE_OPENSSL_OQS=/opt/openssl-3.5/bin/openssl-oqs

./target/release/pqc-probe probe google.com:443 --mode both
```

Expected output on google.com: diff section says "No TLS algorithms unlocked
by oqs-provider on this target" — that's the Phase 4 finding, operationalized.
Against a target that WOULD show a diff (e.g. an nginx + oqs-provider staging
endpoint with experimental codepoints advertised), the experimental column
would show additional negotiated algorithms.

## Troubleshooting

**`Could not find a package configuration file provided by "liboqs"`**  
You skipped the `-DCMAKE_INSTALL_LIBDIR=lib` on the liboqs step and the cmake
config landed under `lib/x86_64-linux-gnu/`. Rebuild liboqs from step 1 with
that flag, OR point oqs-provider at the real path via
`-Dliboqs_DIR=/opt/liboqs/lib/x86_64-linux-gnu/cmake/liboqs`.

**`/opt/liboqs: No such file or directory`**  
You ran `cmake --build build` but not `sudo cmake --install build`. The build
succeeded in the local `build/` dir but nothing was copied to `/opt/`. Rerun
the install step.

**`openssl-oqs list -providers` shows only `default`**  
The wrapper isn't picking up the config. Check that
`/opt/openssl-3.5/ssl-oqs/openssl.cnf` exists and the wrapper's `env` line
points at it.
