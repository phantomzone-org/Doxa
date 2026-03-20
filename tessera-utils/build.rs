extern crate bindgen;

use std::{
	env,
	path::{Path, PathBuf},
	process::Command,
};

fn main() {
	let target = env::var("TARGET").unwrap_or_default();
	println!("cargo:rerun-if-env-changed=TARGET");
	if target.contains("wasm32") {
		return;
	}

	let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
	println!("out_path: {:?}", out_path);

	let static_filepath = out_path.join("libgo.a");
	let header_filepath = out_path.join("libgo.h");
	let go_filepath = Path::new("ffi/main.go");

	if !static_filepath.exists()
		|| static_filepath.metadata().unwrap().modified().unwrap()
			< go_filepath.metadata().unwrap().modified().unwrap()
	{
		// Some environments (CI/sandboxes) restrict writes to ~/.cache/go-build.
		// Force the Go build cache to live under OUT_DIR so c-archive builds succeed.
		let go_cache = out_path.join("gocache");
		std::fs::create_dir_all(&go_cache).expect("create GOCACHE dir");

		// go build -buildmode=c-archive -o libgo.a ffi/main.go
		let mut go_build = Command::new("go");
		go_build
			.arg("build")
			.arg("-buildmode=c-archive")
			.arg("-o")
			.arg(static_filepath)
			.arg(go_filepath)
			.env("GOCACHE", &go_cache);

		go_build.status().expect("Go build failed");

		let bindings = bindgen::Builder::default()
			.header(header_filepath.to_str().unwrap())
			.parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
			.generate()
			.expect("Unable to generate bindings");

		bindings
			.write_to_file(out_path.join("bindings.rs"))
			.expect("Couldn't write bindings!");
	}

	println!("cargo:rerun-if-changed={}", go_filepath.to_str().unwrap());
	println!(
		"cargo:rustc-link-search=native={}",
		out_path.to_str().unwrap()
	);
	println!("cargo:rustc-link-lib=static=go");
}
