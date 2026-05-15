fn main() {
	groth_build::build();
}

/// No-op stub used when the `groth` feature is disabled.
///
/// Satisfies the `groth_build::build()` call in `main()` without pulling in
/// Go, CGo, or bindgen.
#[cfg(not(feature = "groth"))]
mod groth_build {
	pub fn build() {}
}

/// Build script logic that is only active when the `groth` feature is enabled.
///
/// When `groth` is disabled (e.g. `default-features = false`), `build()` is a
/// no-op and neither Go nor bindgen is invoked, keeping CI and lightweight
/// builds fast.
#[cfg(feature = "groth")]
mod groth_build {

	extern crate bindgen;

	use std::{
		env,
		path::{Path, PathBuf},
		process::Command,
	};

	pub fn build() {
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

		let bindings_filepath = out_path.join("bindings.rs");
		if !static_filepath.exists()
			|| !bindings_filepath.exists()
			|| static_filepath.metadata().unwrap().modified().unwrap()
				< go_filepath.metadata().unwrap().modified().unwrap()
		{
			let go_cache = out_path.join("gocache");
			std::fs::create_dir_all(&go_cache).expect("create GOCACHE dir");

			let mut go_build = Command::new("go");
			go_build
				.arg("build")
				.arg("-buildmode=c-archive")
				.arg("-o")
				.arg(&static_filepath)
				.arg(go_filepath)
				.env("GOCACHE", &go_cache);

			let status = go_build.status().expect("failed to run Go build");
			assert!(status.success(), "Go build exited with: {status}");

			let bindings = bindgen::Builder::default()
				.header(header_filepath.to_str().unwrap())
				.parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
				.generate()
				.expect("Unable to generate bindings");

			bindings
				.write_to_file(&bindings_filepath)
				.expect("Couldn't write bindings!");
		}

		println!("cargo:rerun-if-changed={}", go_filepath.to_str().unwrap());
		println!(
			"cargo:rustc-link-search=native={}",
			out_path.to_str().unwrap()
		);
		println!("cargo:rustc-link-lib=static=go");
	}
}
