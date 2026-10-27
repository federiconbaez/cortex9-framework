// SPDX-License-Identifier: GPL-2.0
//! cortex9 packet classifier as a Rust-for-Linux module.
//!
//! The decision procedure is not re-implemented here: `engine.rs` from the
//! `c9-classify` crate is compiled verbatim into this module. The module
//! registers `/dev/c9-classify`, a misc device that classifies batches of
//! frames written by userspace, so the in-kernel build can be checked
//! against the userspace oracle on the same inputs.
//!
//! Wire format of a write: repeated records `[u16 little-endian length][frame]`.
//! A following read returns one byte per record: the `Reason` code.

use kernel::{
    fs::{File, Kiocb},
    iov::{IovIterDest, IovIterSource},
    miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration},
    new_mutex,
    prelude::*,
    sync::Mutex,
};

#[path = "../crates/c9-classify/src/engine.rs"]
#[allow(dead_code, unreachable_pub)]
mod engine;

use engine::{classify, vectors, Flags, Reason, StaticRules};

/// Upper bound for one write, so a caller cannot make us allocate without limit.
const MAX_BATCH_BYTES: usize = 1 << 20;

module! {
    type: C9Module,
    name: "c9_classifier",
    authors: ["Federico Nicolas Baez Rizzo"],
    description: "cortex9 shared packet classifier (Rust)",
    license: "GPL",
    params: {
        flags: u32 {
            default: 3,
            description: "bit0 drop_malformed, bit1 drop_fragments",
        },
    },
}

#[pin_data]
struct C9Module {
    #[pin]
    _dev: MiscDeviceRegistration<C9Device>,
}

impl kernel::InPlaceModule for C9Module {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        let failures = vectors::run_all();
        let total = vectors::CASES.len();
        if failures != 0 {
            pr_err!("c9: selftest FAILED {}/{}\n", failures, total);
        } else {
            pr_info!("c9: selftest ok {}/{}\n", total, total);
        }
        let options = MiscDeviceOptions { name: c"c9-classify" };
        try_pin_init!(Self { _dev <- MiscDeviceRegistration::register(options) })
    }
}

struct State {
    verdicts: KVVec<u8>,
}

#[pin_data]
struct C9Device {
    #[pin]
    state: Mutex<State>,
    rules: StaticRules<4>,
}

fn record_reasons(input: &[u8], rules: &StaticRules<4>, out: &mut KVVec<u8>) -> Result<usize> {
    let mut rest = input;
    let mut n = 0usize;
    while !rest.is_empty() {
        let (len, tail) = match rest {
            [a, b, tail @ ..] => (u16::from_le_bytes([*a, *b]) as usize, tail),
            _ => return Err(EINVAL),
        };
        let frame = tail.get(..len).ok_or(EINVAL)?;
        let reason: Reason = classify(frame, rules);
        out.push(reason as u8, GFP_KERNEL)?;
        rest = &tail[len..];
        n += 1;
    }
    Ok(n)
}

#[vtable]
impl MiscDevice for C9Device {
    type Ptr = Pin<KBox<Self>>;

    fn open(_file: &File, _misc: &MiscDeviceRegistration<Self>) -> Result<Pin<KBox<Self>>> {
        let flags = Flags::from_bits(*module_parameters::flags.value());
        KBox::try_pin_init(
            try_pin_init!(C9Device {
                state <- new_mutex!(State { verdicts: KVVec::new() }),
                rules: vectors::rules(flags),
            }),
            GFP_KERNEL,
        )
    }

    fn write_iter(mut kiocb: Kiocb<'_, Self::Ptr>, iov: &mut IovIterSource<'_>) -> Result<usize> {
        let me = kiocb.file();
        let mut buf = KVVec::new();
        let len = iov.copy_from_iter_vec(&mut buf, GFP_KERNEL)?;
        if len > MAX_BATCH_BYTES {
            return Err(E2BIG);
        }
        let mut st = me.state.lock();
        st.verdicts.clear();
        record_reasons(&buf, &me.rules, &mut st.verdicts)?;
        *kiocb.ki_pos_mut() = 0;
        Ok(len)
    }

    fn read_iter(mut kiocb: Kiocb<'_, Self::Ptr>, iov: &mut IovIterDest<'_>) -> Result<usize> {
        let me = kiocb.file();
        let st = me.state.lock();
        iov.simple_read_from_buffer(kiocb.ki_pos_mut(), &st.verdicts)
    }
}
