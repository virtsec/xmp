# **xMP: Selective Memory Protection for Kernel and User Space**

xMP introduces *Selective Memory Protection* primitives to assist operating
systems (OSes) in thwarting data-oriented attacks. This README presents a brief
description of the xMP primitives that are distributed among the associated
[Xen](https://github.com/virtsec/xmp-xen) and
[Linux](https://github.com/virtsec/xmp-linux) repositories in this
organization. Please refer to these two repositories to check out the xMP
primitives. Also, we provide a [small
example](https://github.com/virtsec/xmp-examples) in form of a kernel module
that demonstrates how to use some of the xMP primitives.

Generally, xMP leverages Intel's virtualization extensions (VT-x) to define
efficient memory isolation domains (xMP domains) for both kernel and user
space. Specifically, xMP provides Linux with the following primitives:

1. Partition selected memory regions into isolated xMP domains
1. Empower Linux to enforce fine-grained memory permissions in xMP domains
1. Protect the integrity of pointers to xMP domains

To avoid interactions with the Virtual Machine Monitor (VMM), we use Intel’s
fast EPTP switching and Virtualization Exception (#VE) capabilities. In this
way, we lend Linux the ability to dynamically switch among different xMP
domains without outsourcing the entire logic to the VMM.
To implement the xMP primitives, we utilize the *alternate p2m* (altp2m)
subsystem of the Xen Project hypervisor. (Please note that we use Xen altp2m
only to reduce the implementation overhead. The altp2m functionality is not
bound to any VMM. In fact, it could be even implemented as a kernel module.)

You can find more details of xMP in our
[paper](https://www.computer.org/csdl/proceedings-article/sp/2020/349700a603/1j2LfOS0dLa).

The preview to our talk at IEEE S&P 2020 is available on YouTube:
<a href="http://www.youtube.com/watch?feature=player_embedded&v=oyJO5gmcMpk" target="_blank"><img src="https://img.youtube.com/vi/oyJO5gmcMpk/0.jpg" alt="Talk preview of xMP at IEEE S&P 2020" width=560 height=340   /></a>



>Note, in this repository, we introduce a **modified** version of xMP, which provides
more generic primitives than the ones presented in the original paper. This
comes with additional benefits but also limitations. Please consider the
*Disclaimer* section for more details.


## **Disclaimer**

This repository does *not* aim to provide a way to evaluate artifacts.
Instead, it is meant to assist OS security developers and researchers with
novel primitives for implementing effective virtualization-assisted security
mechanisms. That said, the published code provides developers with the
primitives only, without any incentives that suggest which memory to protect
(this is in contrast to our paper's intention that specifically isolates the
Linux kernel's `page table structures` and all instances of `struct cred`).

The performance of the published xMP primitives may marginally differ
from the performance evaluation stated in the paper. This is because the xMP
primitives in this repository provide a generic and convenient means to isolate
selective memory. (The original implementation was trimmed for performance
targeting the protected data structures to show the full capacity of the xMP
primitives; similar techniques can be ported to the published implementation as
well, yet, they were not a priority in this version.) The potential performance
drop can result mainly from not caching the computed HMACs. A generic data
structure agnostic implementation may be published in the future.

Besides, the published primitives focus on isolating selected memory pages
through the Buddy allocator only. The published code does neither include user
space related primitives nor primitives for the Slab allocator. We plan to
publish the remaining xMP primitives (based on our initial implementation) to
support the Slab allocator in the near future.

>The published primitives are work-in-progress; potentially unforeseen crashes
are possible at this point of the re-implementation of the xMP primitives.

## **Implementation**

This section summarizes the main implementation details of the Linux kernel as
well as the Xen Project hypervisor. First, we describe the individual xMP
primitives. Then, we briefly depict the modification details of the Xen
hypervisor. In both cases, we provide the reader with API details that can be
used for arbitrary purposes.

### **xMP Primitives**

In the following paragraphs, we briefly summarize the purpose of the individual
xMP primitives. To give an idea of how to use the xMP primitives in the Linux
kernel, we describe their API.

> In the current version, not all xMP primitives have been implemented yet. We will add the missing xMP primitives to the official repository in the near future.

#### **1. Memory Partitioning through xMP Domains**

The first xMP primitive partitions selected (potentially sensitive) memory
regions into disjoint xMP domains.  Generally, we require 2 altp2m views to set
up 1 xMP Domain. We dedicate one view (the restricted view) to unify the
memory acces restrictions of all xMP domains.  This is the default view on all
vCPUs. We use the second view to relax the restrictions (unprotect) a given xMP
domain and to allow access to its data.  Further, creating xMP domains involves
generating a secret xMP key for each newly allocated domain (which remains
accessible/readable only inside the particular domain). The following excerpt
from the xMP header file (`include/xen/interface/xmp.h`) shows the functions
that can be used for creating and freeing an xMP domain.

```c
int xmp_alloc_pdomain(void);
void xmp_free_pdomain(void);
```

For every newly generated xMP domain through `xmp_alloc_pdomain`, we randomly
generate a secret key and place it into a fixed location/guest-frame number
(GFN). (We provide additional primitives, which use the generated key, e.g., to
sign and authenticate pointers.) By additionally remapping the GFN (that holds
the secret key) to a different machine-frame-number (MFN) we manage to grant
access to the secret key (which remains at the same GFN for every xMP domain)
only from inside the particular xMP domain. Hence an xMP domains cannot access
the key that is assigned to another xMP domain. (Access to the GFN holding the
key from the restricted domain---which is active by default---is prohibited, as
the restricted domain marks this page as non-readable.) This concept applies to
every xMP domain, except for the restricted domain (which is created by
default) in which we accumulate all restrictions across the existing altp2m
views. 

To free an xMP domain, we can simply use `xmp_free_pdomain`.

#### **2. Isolating xMP Domains**

The memory isolation primitive allows us to enforce fine-grained memory access
permissions to selected memory pages that belong to a particular xMP domain To
achieve this, we provide the following functions:

```c
int xmp_isolate_pages(uint16_t altp2m_id, struct page *page,
    unsigned int num_pages, xenmem_access_t r_access, xenmem_access_t p_access);

int xmp_isolate_page(uint16_t altp2m_id, struct page *page,
    xenmem_access_t r_access, xenmem_access_t p_access);

int xmp_release_pages(struct page *page, unsigned int num_pages);
```

The functions `xmp_isolate_page`, `xmp_isolate_pages`, and `xmp_release_pages`
leverage the central isolation function `__xmp_isolate_pages` which either
isolates or releases pages in the specified xMP domain (represented through the
associated `altp2m_id` view). The function `__xmp_isolate_pages` is a wrapper
for a Xen hypercall that allows the Linux kernel to interface Xen's altp2m
subsystem.  At the same time, to restrict access to the
memory region in question in *all* other xMP domains, we have to propagate
access restrictions of all xMP domains across all available altp2m views.
Therefore, the wrapper function configures the (unprotected, or private) access
permissions (`p_access`) for the specified altp2m view and
the restricted (`r_access`) permissions for all other available views.

Once the kernel frees a page we have to release it by calling
`xmp_release_pages` in order to not accidentally cause a `#VE` even though the
page is not used anymore.

##### **Modifications in the Buddy and Slab (SLUB) Allocator**

We cause the Buddy allocator to place the requested allocated memory pages into
a specific xMP domain. For this, we adjust the core function
`__alloc_pages_nodemask` in the Buddy Allocator.  Specifically, we encode an
xMP domain’s index into the `gfp_t` allocation flags (which are typically
passed as argument to `get_free_page(s)`). In this way, the allocator receives
sufficient information to inform Xen altp2m and to place the allocation into
the provided xMP domain.

Every time the `kmem_cache` structure runs out of free slabs, it requests a new set of pages from the Buddy Allocator. When xMP is enabled, we also encode the `altp2m_id` from the altered `kmem_cache` structure in the slab allocation flags in order to receive a pointer to an isolated slab.

To free a set of pages from a specific xMP domain, we call the function
`xmp_release_pages`. This function causes the Xen altp2m subsystem to reset the
original permissions of the given pages.

#### **3. Context-bound Pointer Integrity**

To ensure the integrity of selected pointers to sensitive data inside xMP
domains, we equip pointers with HMACs. Specifically, we use `SipHash` generated
HMACs to authenticate selected pointers. We  truncate the generated HMAC to 15
bit of the most-significant-bits of the pointer’s address.  To achieve this, we
can pass a pointer to the function `xmp_sign_ptr`. This function takes
a *context* (which should be a unique and immutable value, such as the address
of a `struct task_struct` instance) as well as an `altp2m_id` value. 

```c
void *xmp_sign_ptr(void *ptr, void *ctx, uint16_t altp2m_id);
void *xmp_auth_ptr(void *ptr, void *ctx, uint16_t altp2m_id);
```

To verify the authenticity of a pointer at a given location in the code, the
developer has to call `xmp_auth_ptr` which receives a signed pointer and the
same remaining arguments.  The verification re-generates the SipHash value for
this pointer and the given context in the specified altp2m view and compares it
to the value encoded in the pointer. If the values do not match the integrity
of the pointer has been corrupted and the kernel crashes.

### **Xen interface**

This section briefly summarizes the modifications to the Xen interface which
are necessary to isolate a memory page in a dedicated xMP domain.

#### **Hypercall `HVMOP_altp2m_isolate_pdomain`**

To isolate pages in a given domain, we provide a new hypercall (HVMOP)
`HVMOP_altp2m_isolate_pdomain` which iterates over all available altp2m views
and updates the permissions for each view accordingly. Internally, the HVMOP
calls the newly introduced function `altp2m_isolate_pdomain`. This function
applies the relaxed permissions to the altp2m view that represents the the
targeted xMP domain; all other altp2m views receive the restricted permissions
to the provided GFN.

```c
int altp2m_isolate_pdomain(uint16_t altp2m_id, xen_pfn_t gfn,
    xenmem_access_t r_access, xenmem_access_t p_access,
    bool suppress_ve);
```

>Note that we require an additional argument `suppress_ve` which states if the
corresponding EPT entry for the specified GFN will have its `suppress_ve` bit
(bit 63) set or not. This extension is necessary since Xen [initializes the EPT
entries with this bit
set](https://github.com/xen-project/xen/commit/2a2903e779d2f3fb7511a483f87b7dc152c5e441).
If this bit is set, then no `#VE` will be triggered when trying to access the
GFN. We implemented the `xmp_isolate_pages` and `xmp_release_pages` so that
they clear the bit when we isolate a page and set the bit again upon releasing
(freeing) them in the kernel.

## **Configuring DomU**

The following provides a miminal example configuration script for the
unprivileged domain, `DomU`:

```bash
name = "domu-linux"
arch = "x86-64"

kernel = "/path/to/bzImage"
ramdisk = "/path/to/initrd"

type = "hvm"
altp2m = "mixed"
maxmem = <MAX_MEMORY_FOR_DOMU>
memory = <MEMORY_FOR_DOMU>
vcpus = <NR_vCPUs>
disk = ['phy:/dev/domu,xvda,1']
extra = "root=/dev/xvda rw console=hvc0 rcu_nocbs=0"
vif = ['type=ioemu, model=e1000, mac=12:34:56:89:9A:BC, bridge=xenbr0']

on_poweroff = "destroy"
on_reboot = "destroy"
on_crash = "destroy"

shadow_memory = 756
ept = ["no-pml, no-ad"]
```


## **About the Authors**

[Sergej Proskurin](mailto:proskurin@sec.in.tum.de), [Marius
Momeu](mailto:momeu@sec.in.tum.de) and [Christopher
Roemheld](mailto:roemheld@in.tum.de) are researchers at the [Chair of IT
Security](https://www.sec.in.tum.de/i20/) at the [Technical University of
Munich](https://www.tum.de/). Their work covers many low-level security
aspects with a focus on virtualization-assisted OS security and malware
analysis using Virtual Machine Introspection (VMI). More information about
previous publications and projects as well as current undergoing projects can
be found on the authors' academic [web
page](https://www.sec.in.tum.de/i20/people/sergej-proskurin).

[Seyedhamed Ghavamnia](mailto:sghavamnia@cs.stonybrook.edu), [Vasileios P.
Kemerlis](https://cs.brown.edu/~vpk/), and [Michalis
Polychronakis](https://www3.cs.stonybrook.edu/~mikepo/) from the Stony Brook
University and Brown University are co-authors of the published
[paper](https://www.computer.org/csdl/proceedings-article/sp/2020/349700a603/1j2LfOS0dLa).
