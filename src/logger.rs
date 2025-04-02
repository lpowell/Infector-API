// Module for logging support

use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write, BufWriter};

use std::time::{SystemTime, UNIX_EPOCH};
use chrono::prelude::*;

use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::{fmt, EnvFilter};

pub fn init_logger() {
    let transaction_log = OpenOptions::new()
        .append(true)
        .create(true)
        .open("/var/log/infector_api/transaction.log")
        .expect("Failed to open or create file");

        let writer = move || BufWriter::new(transaction_log.try_clone().expect("Failed to clone log file"));

    fmt()
        .with_writer(writer)
        .with_env_filter(EnvFilter::from_default_env())
        .with_max_level(tracing::Level::DEBUG)
        .init();
}

// Function to write content to log fs
pub fn writelog (
    LogSource: &str,
    Content: String
) -> io::Result<()>{
    // Assume log exists, create on error

    let time = Utc::now();
    let _content = format!("[{}] {}", time, Content);
    
    match LogSource {
        // Keeping everything non-db in access is probably best tbh
        "access" => {
            let file = OpenOptions::new()
                .append(true)
                .create(true)
                .open("/var/log/infector_api/access.log");
            match file {
                    Ok(ref file) => file,
                    Err(ref e) => {
                        fs::create_dir("/var/log/infector_api")?;
                        &OpenOptions::new()
                            .write(true)
                            .append(true)
                            .create(true)
                            .open("/var/log/infector_api/access.log")?
                    },
                };

            writeln!(file?, "{}", _content).unwrap();
        },
        "transaction" => {
            let file = OpenOptions::new()
                .append(true)
                .create(true)
                .open("/var/log/infector_api/transaction.log");
            match file {
                    Ok(ref file) => file,
                    Err(ref e) => {
                        fs::create_dir("/var/log/infector_api")?;
                        &OpenOptions::new()
                            .write(true)
                            .append(true)
                            .create(true)
                            .open("/var/log/infector_api/transaction.log")?
                    },
                };

            writeln!(file?, "{}", _content).unwrap();
        },
        // currently unused. Might do something with it in the future.
        "resource" => {
            let file = OpenOptions::new()
                .append(true)
                .create(true)
                .open("/var/log/infector_api/resource.log");
            match file {
                    Ok(ref file) => file,
                    Err(ref e) => {
                        fs::create_dir("/var/log/infector_api")?;
                        &OpenOptions::new()
                            .write(true)
                            .append(true)
                            .create(true)
                            .open("/var/log/infector_api/resource.log")?
                    },
                };

            writeln!(file?, "{}", _content).unwrap();
        },
        _ => {
            return Ok(());
        }
    }

    return Ok(())

}