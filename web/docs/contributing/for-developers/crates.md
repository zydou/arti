---
title: Adding Crates
---

# Adding new crates

To add a new crate to the project:

### Create crate directory

After cloning the Arti project, create a new directory in the `crates/{NAME}` format. Replace `{NAME}` with your crate's actual name, and make sure the [crate naming convention](/contributing/for-developers/architecture) is followed.

### Add necessary files

Ensure that the directory contains the following:

- **`Cargo.toml` file:** This file specifies metadata about the crate and its dependencies.
    
    ```toml
    # Example Cargo.toml
    
    [package]
    name = "your_crate_name"
    version = "0.1.0"
    edition = "2023"
    license = "MIT OR Apache-2.0"
    
    [lib]
    path = "src/lib.rs"
    
    [dependencies]
    # Add dependencies if needed
    
    ```
    
- **`src` directory:** This directory will contain your source code.
- **At least one source file:** Create either `src/lib.rs` for a library crate or `src/main.rs` for an executable crate.
- **`README.md` file:** Provide documentation about your crate, including usage, examples, and any other relevant information.
- **A conforming license:** Include a license in your `Cargo.toml` file, ideally `"MIT OR APACHE-2.0"`.

### Maintain Arti’s standards

- Check that your source code complies with the project’s standards and [contribution guidelines](/contributing/).

- **Use the same boilerplate in `lib.rs`:**
  Throughout our codebase, we apply a consistent set of warning and lint parameters. Our standard lint block can be copied into your `lib.rs` when you create a new crate; a copy can be found at [`crates/tor-error/src/lib.rs`](https://gitlab.torproject.org/tpo/core/arti/-/tree/main/crates/tor-error). 

  We also suggest that you copy the `docsrs` attribute from [`tor-error`](https://gitlab.torproject.org/tpo/core/arti/-/tree/main/crates/tor-error) to your crate. This attribute ensures that your crate’s documentation is available on [docs.rs](https://docs.rs/).

### Add crate to top-level `Cargo.toml`

Edit the top-level `Cargo.toml` workspace file to include your new crate in dependency order. Place it after all other crates it depends on and before any crates that depend on it.

```toml
# Example Cargo.toml (top-level)

[workspace]

members = [
  "crates/first_crate",
  "crates/second_crate",
  # Add the path to your new crate
  "crates/your_crate_name",
]

# Rest of the file

```

### Ensure tests pass

Our standard practice is to have tests for all our nontrivial functionality. Before committing your changes, ensure that all tests in the project pass, and fix any issues that may arise during testing to maintain a stable and reliable project. Learn more about [testing in Arti](/contributing/for-developers/testing).
