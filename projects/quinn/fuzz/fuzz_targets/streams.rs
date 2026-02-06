#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

extern crate proto;
use proto::fuzzing::{ConnectionState, ResetStream, Retransmits, StreamsState};
use proto::{Dir, Side, StreamId, VarInt};
use proto::{SendStream, Streams};

#[derive(Arbitrary, Debug)]
struct StreamParams {
    side: Side,
    max_remote_uni: u16,
    max_remote_bi: u16,
    send_window: u16,
    receive_window: u16,
    stream_receive_window: u16,
    dir: Dir,
}

#[derive(Arbitrary, Debug)]
enum Operation {
    Open,
    Accept(Dir),
    Finish(StreamId),
    ReceivedStopSending(StreamId, VarInt),
    ReceivedReset(ResetStream),
    Reset(StreamId),
}

fuzz_target!(|input: (StreamParams, Vec<Operation>)| {
    let (params, operations) = input;
    let (mut pending, conn_state) = (Retransmits::default(), ConnectionState::Established);
    let mut state = StreamsState::new(
        params.side,
        params.max_remote_uni.into(),
        params.max_remote_bi.into(),
        params.send_window.into(),
        params.receive_window.into(),
        params.stream_receive_window.into(),
    );

    for operation in operations {
        match operation {
            Operation::Open => {
                Streams::new(&mut state, &conn_state).open(params.dir);
            }
            Operation::Accept(dir) => {
                Streams::new(&mut state, &conn_state).accept(dir);
            }
            Operation::Finish(id) => {
                let _ = SendStream::new(id, &mut state, &mut pending, &conn_state).finish();
            }
            Operation::ReceivedStopSending(sid, err_code) => {
                Streams::new(&mut state, &conn_state)
                    .state()
                    .received_stop_sending(sid, err_code);
            }
            Operation::ReceivedReset(rs) => {
                let _ = Streams::new(&mut state, &conn_state)
                    .state()
                    .received_reset(rs);
            }
            Operation::Reset(id) => {
                let _ =
                    SendStream::new(id, &mut state, &mut pending, &conn_state).reset(0u32.into());
            }
        }
    }
});
