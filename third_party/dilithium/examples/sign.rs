// Command for changing the stack size:
// cargo run --example sign --features std -- --stack-size-kb (new value in KB)

extern crate dilithium;
extern crate rand;
extern crate structopt;

use dilithium::sign::SecKey;
use rand::rngs::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use std::thread;
use structopt::StructOpt;

const DEFAULT_STACK_SIZE_KB: &str = "81";

#[derive(Debug, StructOpt)]
struct Opts {
    #[structopt(long, default_value=DEFAULT_STACK_SIZE_KB)]
    stack_size_kb: usize,
}

fn run() {
    let mut rng = StdRng::seed_from_u64(0);

    let sk = SecKey::gensk(&mut rng);
    let mut message = [0; 59];
    rng.fill_bytes(&mut message);
    sk.sign(&message);
}

fn main() {
    let stack_size_kb = Opts::from_args().stack_size_kb;

    // We bound the stack size for generating keys and signing in Dilithium.
    let child = thread::Builder::new()
        .stack_size(stack_size_kb * 1024)
        .spawn(run)
        .unwrap();

    // Wait for thread to join
    child.join().unwrap();
}
