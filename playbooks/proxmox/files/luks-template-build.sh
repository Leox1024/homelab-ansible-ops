#!/bin/bash
# Builds the disk of the LUKS-encrypted Debian cloud template. Run it as root inside a
# helper VM cloned from the plain cloud template, with two extra disks:
#   <source>  root partition of an untouched clone of the plain template (read-only)
#   <target>  empty disk that becomes the template disk:
#             1 MiB BIOS boot, 512 MiB /boot (kernel and initramfs only), LUKS2 root
# Attach the source disk after the helper has booted: it has the same partition UUIDs as
# the helper's own root.
#
# The root opens at boot with a key file kept in the initramfs. Every clone shares it
# until vm-create.yml re-encrypts the disk with a key of its own and binds it to Tang.
#
# Usage: luks-template-build.sh <source-partition> <target-disk>
set -euo pipefail

SRC=${1:-}
DST=${2:-}
MAP=root_crypt   # /etc/crypttab name: the initramfs only unlocks the root under this name
T=/mnt/target
S=/mnt/source

die() { echo "luks-template-build: $*" >&2; exit 1; }

cleanup() {
  umount -R -l "$T" 2>/dev/null || true
  umount "$S" 2>/dev/null || true
  cryptsetup close "$MAP" 2>/dev/null || true
}

[ "$(id -u)" = 0 ] || die "run as root"
[ -b "$SRC" ] && [ -b "$DST" ] || die "usage: $0 <source-partition> <target-disk>"
[ -z "$(lsblk -no FSTYPE,PARTTYPE "$DST" | tr -d '[:space:]')" ] || die "$DST is not empty"
[ ! -e /dev/mapper/$MAP ] || die "/dev/mapper/$MAP is already open"
trap cleanup EXIT

export DEBIAN_FRONTEND=noninteractive
apt-get -qq update
apt-get -qq install -y cryptsetup gdisk rsync >/dev/null

echo "== partitions"
# The root ends on a 1 MiB boundary: LUKS with 4096-byte sectors needs a whole number of them.
root_end=$(($(sgdisk -E "$DST" | tail -1) / 2048 * 2048 - 1))
sgdisk -n1:0:+1M -t1:ef02 -c1:bios -n2:0:+512M -t2:8300 -c2:boot \
  -n3:0:$root_end -t3:8309 -c3:root "$DST"
blockdev --rereadpt "$DST"
udevadm settle

echo "== LUKS2 root"
install -d -m 0700 /root/luks
head -c 64 /dev/urandom >/root/luks/template.key
# A random 512-bit key needs no slow key derivation.
cryptsetup luksFormat -q --type luks2 --label "$MAP" --sector-size 4096 \
  --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --key-file /root/luks/template.key "${DST}3"
cryptsetup open --allow-discards --key-file /root/luks/template.key "${DST}3" "$MAP"
mkfs.ext4 -q -L root /dev/mapper/$MAP
mkfs.ext4 -q -L boot "${DST}2"

echo "== copy the plain template"
mkdir -p "$T" "$S"
mount -o ro "$SRC" "$S"
mount /dev/mapper/$MAP "$T"
mkdir -p "$T/boot"
mount "${DST}2" "$T/boot"
rsync -aHAX --numeric-ids "$S/" "$T/"
umount "$S"

echo "== system configuration"
for d in dev dev/pts proc sys; do mount --bind "/$d" "$T/$d"; done
mount -t tmpfs tmpfs "$T/run"
mv "$T/etc/resolv.conf" "$T/etc/resolv.conf.build"
echo "nameserver $(ip -4 route show default | awk '{print $3; exit}')" >"$T/etc/resolv.conf"
printf '#!/bin/sh\nexit 101\n' >"$T/usr/sbin/policy-rc.d"
chmod 0755 "$T/usr/sbin/policy-rc.d"

install -d -m 0700 "$T/etc/luks"
install -m 0400 /root/luks/template.key "$T/etc/luks/template.key"
echo "$MAP UUID=$(cryptsetup luksUUID "${DST}3") /etc/luks/template.key luks,discard" >"$T/etc/crypttab"
cat >"$T/etc/fstab" <<EOF
/dev/mapper/$MAP / ext4 rw,discard,errors=remount-ro 0 1
UUID=$(blkid -s UUID -o value "${DST}2") /boot ext4 defaults 0 2
EOF

chroot "$T" apt-get -qq update
chroot "$T" apt-get -qq install -y cryptsetup cryptsetup-initramfs clevis clevis-luks \
  clevis-initramfs qemu-guest-agent curl >/dev/null

echo 'KEYFILE_PATTERN="/etc/luks/*.key"' >>"$T/etc/cryptsetup-initramfs/conf-hook"
printf 'UMASK=0077\nMODULES=most\n' >"$T/etc/initramfs-tools/conf.d/luks-template"

# vm-create.yml grows the disk after re-encrypting it: cloud-init cannot grow LUKS.
cat >"$T/etc/cloud/cloud.cfg.d/90-luks-template.cfg" <<'EOF'
growpart:
  mode: "off"
resize_rootfs: false
EOF

cat >"$T/etc/ssh/sshd_config.d/00-pubkey-only.conf" <<'EOF'
# Managed by Ansible (homelab-ansible-ops: playbooks/linux/ssh-pubkey-only.yml)
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
AuthenticationMethods publickey
PermitRootLogin prohibit-password
EOF

# The cloud image boots from root=PARTUUID=, which a LUKS root does not have.
printf 'GRUB_DISABLE_LINUX_UUID=true\nGRUB_DISABLE_LINUX_PARTUUID=true\n' \
  >"$T/etc/default/grub.d/90-luks-template.cfg"

echo "== boot loader and initramfs"
chroot "$T" grub-install --target=i386-pc "$DST"
chroot "$T" update-grub 2>&1 | grep -v '^Warning: os-prober' || true
chroot "$T" update-initramfs -u -k all
initrd=$(cd "$T" && ls boot/initrd.img-* | tail -1)
content=$(chroot "$T" lsinitramfs "/$initrd")
for f in cryptroot/keyfiles/ dm-crypt clevis virtio_net; do
  grep -q "$f" <<<"$content" || die "initramfs is missing $f"
done
grep -q "root=/dev/mapper/$MAP\|root=UUID=$(blkid -s UUID -o value /dev/mapper/$MAP)" "$T/boot/grub/grub.cfg" \
  || die "grub.cfg does not boot from /dev/mapper/$MAP"

echo "== clean up"
chroot "$T" apt-get -qq clean
rm -f "$T/usr/sbin/policy-rc.d"
mv -f "$T/etc/resolv.conf.build" "$T/etc/resolv.conf"
rm -f "$T"/etc/ssh/ssh_host_*
truncate -s 0 "$T/etc/machine-id"
rm -rf "$T/var/lib/cloud"/* "$T/var/log/journal"/*
fstrim "$T/boot"
fstrim "$T"
umount -R "$T"
cryptsetup close "$MAP"
shred -u /root/luks/template.key
echo "== done: $DST is ready to become the template disk"
