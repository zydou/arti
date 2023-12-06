---
title: Adding Crates
---

# Adding new crates

When adding new crates to Arti, it is important to ensure consistency, compatibility, and maintainability. To add a new crate to the project:

### Create crate directory

After cloning the Arti project, create a new directory in the `crates/{NAME}` format. Replace `{NAME}` with your crate's actual name, and make sure the [crate naming convention](https://www.notion.so/adding-new-crates-05cee9e69c0b4a33a5aeed86432f3b0b?pvs=21) is followed.

### Add necessary files

Ensure that the directory contains the following:

- **`Cargo.toml` file:** This file specifies metadata about the crate and its dependencies.
    
    ```toml
    # Example Cargo.toml
    
    [package]
    name = "your_crate_name"
    version = "0.1.0"
    edition = "2023"
    
    [lib]
    path = "src/lib.rs"
    
    [dependencies]
    # Add dependencies if needed
    
    ```
    
- **`src` directory:** This directory will contain your source code.
- **At least one source file:** Create either `src/lib.rs` for a library crate or `src/main.rs` for an executable crate.
- **`README.md` file:** Provide documentation about your crate, including usage, examples, and any other relevant information.

### Maintain Arti’s standards

Check that your source code complies with the project’s standards and [contribution guidelines](https://www.notion.so/adding-new-crates-05cee9e69c0b4a33a5aeed86432f3b0b?pvs=21):

- **Use a conforming license:** Include a license in your `Cargo.toml` file, ideally `"MIT OR APACHE-2.0"`.
    
    ```toml
    # Example Cargo.toml with license
    
    [package]
    name = "your_crate_name"
    version = "0.1.0"
    edition = "2021"
    license = "MIT OR Apache-2.0"
    
    [lib]
    path = "src/lib.rs"
    
    [dependencies]
    # Add dependencies if needed
    
    ```
    
- **Use the same boilerplate in `lib.rs`:** Maintain consistency with other `lib.rs` files in the project.

> To ensure consistency with our coding standards, check out the [tor-error](https://gitlab.torproject.org/tpo/core/arti/-/tree/main/crates/tor-error) crate.
> 

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

Before committing your changes, ensure that all tests in the project pass. Fix any issues that arise during testing to maintain a stable and reliable project.
