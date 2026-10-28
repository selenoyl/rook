# Rook: build, run and test the Keep and its user programs.
#   make          build build/keep.bin
#   make run      boot it in a QEMU window (serial log in this terminal)
#   make test     lints, review checks and boot tests
#   make screen   boot headless and save the screen to build/screen.png

KERNEL   := target/x86_64-unknown-none/release/keep
USER_DIR := target/x86_64-unknown-none/release
IMAGE    := build/keep.bin
DISK     := build/disk.img
QEMU     := qemu-system-x86_64 -cpu max -m 128M -no-reboot
DRIVE    := -drive file=$(DISK),format=raw,if=ide

.PHONY: all build user run test check screen disk clean FORCE

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
	$(QEMU) -kernel $(IMAGE) $(DRIVE) -serial stdio

check:
	cargo fmt --check
	cargo clippy --release -- -D warnings
	cargo test -p courier -p crypto -p drawbridge -p seal -p signet -p vault --target x86_64-unknown-linux-gnu
	python3 tools/check.py

test: build check $(DISK)
	python3 tests/boot_test.py $(IMAGE)

screen: build $(DISK)
	python3 tools/screenshot.py $(IMAGE) build/screen.png

clean:
	cargo clean
	rm -rf build

FORCE:
