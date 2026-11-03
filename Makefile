# Rook: build, run and test the Keep and its user programs.
#   make          build build/keep.bin
#   make run      boot it in a QEMU window (serial log in this terminal)
#   make test     lints, review checks and boot tests
#   make screen   boot headless and save the screen to build/screen.png
#   make iso      build a bootable GRUB ISO (build/rook.iso) for a real VM
#   make run-iso  boot that ISO in QEMU through BIOS + GRUB (serial here)

KERNEL   := target/x86_64-unknown-none/release/keep
USER_DIR := target/x86_64-unknown-none/release
IMAGE    := build/keep.bin
DISK     := build/disk.img
ISO      := build/rook.iso
QEMU     := qemu-system-x86_64 -cpu max -m 128M -no-reboot
DRIVE    := -drive file=$(DISK),format=raw,if=ide
NET      := -netdev user,id=n0 -device ne2k_isa,netdev=n0

.PHONY: all build user run test check screen iso run-iso disk clean FORCE

all: build

# The user programs are built first: the Keep embeds their ELF images.
user:
	cargo build --release -p user

# The boot image is a flat binary of the ELF file, starting at 1 MiB; its
# Multiboot header says where everything goes. The ELF file keeps the
# symbols, for debugging.
build: $(IMAGE)

$(IMAGE): user FORCE
	ROOK_USER_DIR=$(abspath $(USER_DIR)) cargo build --release -p keep
	mkdir -p build
	objcopy -O binary $(KERNEL) $(IMAGE)

# The Vault's disk: a raw image with a small filesystem, built by mkvault.
disk: $(DISK)

$(DISK):
	mkdir -p build
	python3 tools/mkvault.py $(DISK)

run: build $(DISK)
	$(QEMU) -kernel $(IMAGE) $(DRIVE) $(NET) -serial stdio

check:
	cargo fmt --check
	cargo clippy --release -- -D warnings
	cargo test -p courier -p crypto -p drawbridge -p net -p seal -p signet -p vault --target x86_64-unknown-linux-gnu
	python3 tools/check.py

test: build check $(DISK)
	python3 tests/boot_test.py $(IMAGE)
	python3 tests/net_test.py $(IMAGE)

screen: build $(DISK)
	python3 tools/screenshot.py $(IMAGE) build/screen.png

# A bootable GRUB ISO: GRUB loads the Keep as a Multiboot kernel and boots
# it in "console" mode (no disk or NIC assumed). Boots on a real BIOS VM —
# Hyper-V Gen 1, VirtualBox — or bare metal, not only QEMU's -kernel.
iso: $(ISO)

$(ISO): build tools/grub.cfg
	rm -rf build/iso
	mkdir -p build/iso/boot/grub
	cp $(IMAGE) build/iso/boot/keep.bin
	cp tools/grub.cfg build/iso/boot/grub/grub.cfg
	grub-mkrescue --install-modules="multiboot normal" -o $(ISO) build/iso
	@echo "built $(ISO)"

# Boot the ISO the way a real machine would: BIOS firmware, then GRUB, then
# the Keep — no -kernel shortcut. Serial log in this terminal.
run-iso: $(ISO)
	$(QEMU) -cdrom $(ISO) -serial stdio

clean:
	cargo clean
	rm -rf build

FORCE:
