use std::io::{prelude::*, BufReader, BufWriter};

mod network;

use network::types::{NetworkTypeReader, NetworkTypeWriter, Varint};

impl<R: Read> NetworkTypeReader for BufReader<R> {}

impl<W: Write> NetworkTypeWriter for BufWriter<W> {}
