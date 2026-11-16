// SPDX-License-Identifier: CC0-1.0
use encoding::{Decodable, Decoder};
use tidecoin_p2p_messages::{
    message::{
        CommandString, NetworkMessage, V1NetworkMessage, V2NetworkMessage, MAX_MSG_SIZE,
        MAX_V2_CONTENTS_SIZE,
    },
    Magic,
};

#[test]
fn rc3_message_size_boundaries_for_slice_and_incremental_decoding() {
    for size in [MAX_MSG_SIZE - 1, MAX_MSG_SIZE, MAX_MSG_SIZE + 1] {
        let message = NetworkMessage::Unknown {
            command: CommandString::try_from_static("rc3test").unwrap(),
            payload: vec![0; size],
        };
        let v1 = V1NetworkMessage::new(Magic::TIDECOIN, message.clone());
        let encoded = encoding::encode_to_vec(&v1);
        assert_eq!(
            encoding::decode_from_slice::<V1NetworkMessage>(&encoded).is_ok(),
            size <= MAX_MSG_SIZE
        );
        let v2 = V2NetworkMessage::new(message);
        let encoded = encoding::encode_to_vec(&v2);
        assert_eq!(encoded.len(), size + 13);
        assert_eq!(
            encoding::decode_from_slice::<V2NetworkMessage>(&encoded).is_ok(),
            encoded.len() <= MAX_V2_CONTENTS_SIZE
        );
        let mut decoder = V2NetworkMessage::decoder();
        let mut accepted = true;
        for chunk in encoded.chunks(65536) {
            if decoder.push_bytes(&mut &chunk[..]).is_err() {
                accepted = false;
                break;
            }
        }
        assert_eq!(accepted, size <= MAX_MSG_SIZE);
        if accepted {
            assert_eq!(decoder.end().unwrap(), v2);
        }
    }
}
