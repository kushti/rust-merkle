extern crate ring;
extern crate rust_base58;

use ring::*;
use ring::digest::Digest;
use std::error::Error;
use std::io::{Read, Write};
use std::fs;
use std::borrow::ToOwned;
use rust_base58::ToBase58;

struct MerkleAuth {
    leafs_num: u32,
    root_value: Digest
}

fn print_usage(program_name: &str) {
    let program_file_name = std::path::Path::new(program_name)
        .file_name().unwrap().to_str().unwrap();

    println!(
        "Usage: {} sha256|sha384|sha512 <directory>\n\
         \n\
         On success Merkle tree root hash value is printed, and 0 is returned.\n\
         On failure, an error message is printed, and a non-zero value is returned\n\
         \n\
         Example:\n\
         {} sha256 \
           files",
        program_file_name, program_file_name);
}


fn file_digest(digest_alg: &'static digest::Algorithm, file_path: &std::path::Path) -> Result<Digest, std::string::String> {
    std::fs::File::open(file_path).map_err(|why| {
        format!("couldn't open {}: {}", file_path.display(), why.description())
    }).and_then(|mut file| {
        let mut ctx: Result<digest::Context, std::string::String> = Ok(digest::Context::new(digest_alg));
        let mut chunk = vec![0u8; 128 * 1024];

        loop {
            match file.read(&mut chunk[..]) {
                Ok(0) => break,
                Ok(bytes_read) => ctx = ctx.map(|mut x| {
                    x.update(&chunk[0..bytes_read]);
                    x
                }),
                Err(why) => {
                    ctx = Err(format!("couldn't read {}: {}", file_path.display(), why.description()));
                    break
                }
            }
        }
        ctx.map(|x| x.finish())
    })
}

// Calculate closest bigger number of form 2^n, where n is unsigned int
#[inline]
fn bigger2n(k: u32) -> u32 {
    let lz = k.leading_zeros();
    let tz = k.trailing_zeros();
    match lz + tz {
        31 => k,
        _ => 2_u32.pow(32 - lz)
    }
}

fn root(digest_alg: &'static digest::Algorithm, prev_level: &Vec<&[u8]>) -> Digest {
    #[inline]
    fn two_elems_hash(digest_alg: &'static digest::Algorithm, left: &[u8], right: &[u8]) -> Digest {
        let mut ctx = digest::Context::new(digest_alg);
        ctx.update(left);
        ctx.update(right);
        ctx.finish()
    }

    let prev_length = prev_level.len();
    assert_eq!(prev_length % 2, 0);

    match prev_level.len() {
        2 => two_elems_hash(digest_alg, prev_level[0], prev_level[1]),
        _ => {
            let level_size = prev_length / 2;
            let mut level: Vec<Vec<u8>> = Vec::with_capacity(level_size);

            for idx in 0..level_size {
                let ed = two_elems_hash(digest_alg, prev_level[idx * 2], prev_level[idx * 2 + 1]);
                let e: &[u8] = ed.as_ref();
                level.push(e.to_owned());   //todo: how to return slice?
            };

            assert_eq!(level.len(), prev_length / 2);
            let l = level.iter().map(|e| e.as_slice()).collect();
            root(digest_alg, &l)
        }
    }
}

fn merkle(digest_alg: &'static digest::Algorithm, non_empty_leafs: &Vec<Digest>) -> MerkleAuth {
    let digest_size = digest_alg.output_len;
    let zero_hash_vec = vec![0 as u8; digest_size];
    let zero_hash = zero_hash_vec.as_slice();

    let ne_count = non_empty_leafs.len() as u32;
    let l_count = bigger2n(ne_count);

    let mut leafs: Vec<&[u8]> = Vec::with_capacity(l_count as usize);
    let neleafs: Vec<&[u8]> = non_empty_leafs.iter().map(|d| d.as_ref()).collect();
    leafs.clone_from(&neleafs);

    if l_count > ne_count {
        let mut eleafs: Vec<&[u8]> = vec![zero_hash; (l_count - ne_count) as usize];
        leafs.append(&mut eleafs)
    }

    MerkleAuth {leafs_num: ne_count, root_value: root(digest_alg, &leafs)}
}

fn folder_merkle(digest_alg: &'static digest::Algorithm,
                 folder_path: &std::path::Path) -> Result<MerkleAuth, std::string::String> {
    match fs::read_dir(folder_path) {
        Ok(dir) => {
            let digests = dir.filter_map(|entry| {
                entry.map_err(|why| {
                    format!("couldn't open {}", why.description())
                }).and_then(|e|
                    file_digest(digest_alg, e.path().as_path())
                ).ok() //todo: silent conversion from result to option
            }).collect::<Vec<Digest>>();
            Ok(merkle(digest_alg, &digests))
        },
        Err(s) => {
            Err(format!("{}", s))
        }
    }
}

fn run(digest_name: &str, folder_path: &std::path::Path) -> Result<(), String> {
    let digest_alg = match digest_name {
        "sha256" => &digest::SHA256,
        "sha384" => &digest::SHA384,
        "sha512" => &digest::SHA512,
        _ => { return Err(format!("unsupported digest algorithm: {}", digest_name)); }
    };

    match folder_merkle(digest_alg, folder_path){
        Ok(ma) => {
            println!("number of non-zero elements in a tree: {}", ma.leafs_num);
            println!("tree authenticating root: {}", ma.root_value.as_ref().to_base58());
            Ok(())
        },
        Err(s) => Err(s)
    }

}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|arg| arg == "-h") {
        print_usage(&args[0]);
        return
    } else if args.len() < 3 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    match run(&args[1], std::path::Path::new(&args[2])) {
        Ok(x) => x,
        Err(s) => {
            let _ = writeln!(&mut std::io::stderr(), "{}", s);
            std::process::exit(1)
        }
    }
}
