use std::io::{prelude::*, BufReader};

mod network_types;

use network_types::NetworkTypeProducer;

impl<R: Read> NetworkTypeProducer for BufReader<R> {}
