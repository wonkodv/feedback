#![allow(dead_code, unused_variables, unused_imports)] // TODO

use thiserror;

mod server;
mod state;

fn main() {
    server::run();
}
