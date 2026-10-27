# GPU isolation: design only (not implemented, not tested)

> **Status: unverified.** The machines this repository was built and tested on
> have no GPU. Nothing in this document is exercised by the test suite or CI.
> `gpu_devices` in a policy compiles to warning `C9W105` and is not enforced.

## ES

La tesis 3 habla de clusters con GPU. Lo que sí se prueba en este repo es la
parte de memoria del host: una carga que simula cargar los shards de un modelo
se aísla en su cgroup y el OOM ocurre adentro, no en el host. La parte GPU
quedaría así, y queda pendiente hasta tener hardware:

1. **Acceso a dispositivos.** cgroup v2 no tiene archivo `devices.*`; el control
   se hace con un programa eBPF `BPF_PROG_TYPE_CGROUP_DEVICE` adjunto al cgroup de
   la carga. La política listaría los nodos permitidos (`/dev/nvidia0`,
   `/dev/nvidiactl`, `/dev/nvidia-uvm`; mayor 195 y el mayor dinámico de `nvidia-uvm`)
   y el programa devolvería 0 para cualquier otro dispositivo de carácter.
2. **Memoria de GPU.** cgroup v2 no contabiliza VRAM. El límite tendría que
   venir del runtime (MIG o `CUDA_MPS_PINNED_DEVICE_MEM_LIMIT`), y el supervisor solo
   podría vigilarlo vía NVML. Esto no es aislamiento a nivel kernel y se dice así.
3. **Memoria pinned del host.** `cudaHostAlloc` sí se carga al `memory.max` del
   cgroup, que es justo lo que este repo prueba con la carga simulada.

## EN

Thesis 3 is about GPU clusters. What this repository does prove is the host
memory side: a workload that simulates loading model shards is isolated in its
own cgroup and the OOM happens inside it, not on the host. The GPU side would
look like this and stays pending until there is hardware:

1. **Device access.** cgroup v2 has no `devices.*` file; access control is a
   `BPF_PROG_TYPE_CGROUP_DEVICE` program attached to the workload cgroup. The
   policy would list the allowed nodes (`/dev/nvidia0`, `/dev/nvidiactl`,
   `/dev/nvidia-uvm`; major 195 plus the dynamic `nvidia-uvm` major) and the
   program would return 0 for every other character device.
2. **GPU memory.** cgroup v2 does not account VRAM. A limit would have to come
   from the runtime (MIG or `CUDA_MPS_PINNED_DEVICE_MEM_LIMIT`) and the supervisor
   could only watch it through NVML. That is not kernel-level isolation and is
   stated as such.
3. **Pinned host memory.** `cudaHostAlloc` is charged to the cgroup's
   `memory.max`, which is exactly what the simulated workload here exercises.
