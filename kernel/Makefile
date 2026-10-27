# SPDX-License-Identifier: Apache-2.0
# Out-of-tree build of the Rust module.
#   make KDIR=/path/to/kernel/build LLVM=1
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) LLVM=1 modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) LLVM=1 clean
