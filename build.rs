use libbpf_cargo::SkeletonBuilder;
use std::fmt::Write;
use std::fs;
use std::io::Result;
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct Config {
    bpf_suffix: String,
    skeleton_suffix: String,
    input_dir: PathBuf,
    skeleton_dir: PathBuf,
}

// .bpf.cで定義されるeBPFのプログラムモジュール
// 入力となるソースファイルとlibbpf-cargoが生成するスケルトンの出力先を持つ
#[derive(Debug)]
struct BpfModule {
    name: String,
    source_path: PathBuf,
    skeleton_path: PathBuf,
}

impl BpfModule {
    fn new<P: AsRef<Path>>(config: &Config, source_path: P) -> BpfModule {
        let name = source_path
            .as_ref()
            .file_name()
            .expect("bad source path encoding")
            .to_string_lossy()
            .replace(&config.bpf_suffix, "");
        let mut skeleton_path = PathBuf::from(&config.skeleton_dir);
        skeleton_path.push(format!("{}{}", name, config.skeleton_suffix));
        BpfModule {
            name,
            source_path: source_path.as_ref().to_owned(),
            skeleton_path,
        }
    }
}

// 自動生成されたモジュールをexposeするモジュールを定義する
fn gen_mods(modules: &[BpfModule]) -> Result<()> {
    if modules.is_empty() {
        return Ok(());
    }

    let mut path = modules[0].skeleton_path.clone();
    path.pop();
    path.push("mod.rs");

    let mut contents = String::new();
    for module in modules {
        write!(
            contents,
            "#[path = \"{skeleton}\"]\nmod {name}_skel;\npub use {name}_skel::*;\n",
            skeleton = module
                .skeleton_path
                .file_name()
                .expect("skeleton file name")
                .to_string_lossy(),
            name = module.name
        )
        .unwrap();
    }

    fs::write(path, &contents.as_bytes())
}


// ビルド対象のeBPFコードを走査してBpfModuleに組み立てる
fn scan_input(config: &Config) -> Result<Vec<BpfModule>> {
    let mut result: Vec<BpfModule> = Vec::new();
    for entry in (config.input_dir.read_dir()?).flatten() {
        let path = entry.path();
        let metadata = path.metadata()?;
        let filename = path
            .file_name()
            .expect("file name should be got")
            .to_str()
            .expect("os string should be convert to str");
        if filename.ends_with(".bpf.c") && metadata.is_file() {
            println!(
                "cargo:rerun-if-changed={}",
                path.as_os_str().to_str().unwrap()
            );
            result.push(BpfModule::new(config, path));
        }
    }
    Ok(result)
}

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    // どっかからmetadataもらってもいいかもしれない
    let config = Config {
        bpf_suffix: String::from(".bpf.c"),
        skeleton_suffix: String::from(".skel.rs"),
        input_dir: PathBuf::from("src/bpf/c"),
        skeleton_dir: PathBuf::from("src/bpf"),
    };

    let scanned_modules = scan_input(&config)?;
    for bpf_module in scanned_modules.iter() {
        SkeletonBuilder::new(&bpf_module.source_path)
            .debug(true)
            .generate(&bpf_module.skeleton_path)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    }
    gen_mods(&scanned_modules)?;
    Ok(())
}
