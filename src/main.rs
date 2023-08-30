use argh::FromArgs;
use crossbeam_channel::{unbounded, Receiver};
use sha2::{digest::generic_array::GenericArray, Digest, Sha256};
use std::{mem::transmute, thread};

#[derive(FromArgs)]
/// hashsearch
struct Args {
    /// number of zeroes desired hash must end with
    #[argh(option, short = 'N')]
    num_zeros: usize,
    /// desired number of results,
    /// defaults to 1
    #[argh(option, short = 'K', default = "1")]
    count: usize,
    /// number of worker threads,
    /// defaults to number of CPU threads
    #[argh(option, short = 'W')]
    workers: Option<usize>,
}

fn main() {
    let args: Args = argh::from_env();
    search(
        args.num_zeros,
        args.count,
        args.workers.unwrap_or_else(num_cpus::get),
    );
}

fn search(num_zeros: usize, mut count: usize, workers: usize) {
    let result_rx = spawn_workers(num_zeros, workers);
    while count > 0 {
        let (n, hash) = result_rx
            .recv()
            .expect("Catastrophic failure, all worker threads are dead");

        println!("{n}: {hash}");
        count -= 1;
    }
}

fn spawn_workers(num_zeros: usize, workers: usize) -> Receiver<(usize, String)> {
    const BATCH_SIZE: usize = 100;
    let mask = make_check_mask(num_zeros);

    let (result_tx, result_rx) = unbounded();

    for i in 0..workers {
        let th_result_tx = result_tx.clone();

        thread::spawn(move || {
            let mut results_buf = Vec::with_capacity(BATCH_SIZE);
            let mut start = BATCH_SIZE * i + 1;
            let mut hasher = Sha256::new();
            let mut hash = GenericArray::default();
            loop {
                for n in start..start + BATCH_SIZE {
                    hasher.update(n.to_le_bytes());
                    hasher.finalize_into_reset(&mut hash);

                    // SAFETY:
                    // GenericArray<T, S> wraps [T, S] and
                    // it is generally safe to transmute arrays of matching byte size
                    // Reasoning:
                    // after profiling with `perf` and `flamegraph`
                    // this approach proved to decrease CPU time spent
                    // outside `Sha256::finalize` by about 20%
                    // when compared to naive byte-wise iterator
                    let valid = unsafe {
                        let hash = transmute::<_, [u64; 4]>(hash);
                        hash.into_iter().zip(mask).all(|(hb, mb)| hb & mb == 0)
                    };

                    if valid {
                        results_buf.push((n, format!("{hash:x}")))
                    }
                }

                for (n, hash) in results_buf.drain(..) {
                    if th_result_tx.send((n, hash)).is_err() {
                        return;
                    }
                }

                start += BATCH_SIZE * workers;
            }
        });
    }
    result_rx
}

/// Produces an array where all bits
/// except for last `num_zeros` nibbles are set to 0
fn make_check_mask(num_zeros: usize) -> [u64; 4] {
    let bytes_to_check = num_zeros / 2 + num_zeros % 2;
    let extra_nibble = num_zeros % 2 != 0;
    let bytes = std::array::from_fn(|i| match 32 - i {
        ri if ri == bytes_to_check && extra_nibble => 0x0f,
        ri if ri <= bytes_to_check => 0xff,
        _ => 0x00,
    });
    // SAFETY: it is generally safe to transmute arrays of matching byte size
    unsafe { transmute::<[u8; 32], [u64; 4]>(bytes) }
}
