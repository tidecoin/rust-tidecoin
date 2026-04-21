use std::{env, fs, path::Path};

use network::Network;
use tidecoin_p2p_messages::Magic;

#[test]
fn tidecoin_node_chainparams_message_start_matches_rust_magic_constants() {
    let node_repo = match env::var("TIDECOIN_NODE_REPO") {
        Ok(path) => path,
        Err(_) => return,
    };

    let chainparams = fs::read_to_string(Path::new(&node_repo).join("src/kernel/chainparams.cpp"))
        .expect("read Tidecoin node chainparams.cpp");

    let tidecoin = extract_message_start(&chainparams, "CMainParams");
    let testnet = extract_message_start(&chainparams, "CTestNetParams");
    let regtest = extract_message_start(&chainparams, "CRegTestParams");

    assert_eq!(tidecoin, Magic::from(Network::Tidecoin).to_bytes());
    assert_eq!(testnet, Magic::from(Network::Testnet).to_bytes());
    assert_eq!(regtest, Magic::from(Network::Regtest).to_bytes());

    assert_ne!(tidecoin, testnet);
    assert_ne!(tidecoin, regtest);
    assert_ne!(testnet, regtest);
}

fn extract_message_start(source: &str, class_name: &str) -> [u8; 4] {
    let class_start = source
        .find(class_name)
        .unwrap_or_else(|| panic!("missing {class_name} in chainparams.cpp"));
    let after_class = &source[class_start..];
    let mut bytes = [0u8; 4];

    for (index, slot) in bytes.iter_mut().enumerate() {
        let needle = format!("pchMessageStart[{index}] = ");
        let offset =
            after_class.find(&needle).unwrap_or_else(|| panic!("missing {needle}{class_name}"));
        let value_start = offset + needle.len();
        let value = &after_class[value_start..value_start + 4];
        *slot = u8::from_str_radix(value.trim_start_matches("0x"), 16)
            .unwrap_or_else(|_| panic!("invalid pchMessageStart byte `{value}` in {class_name}"));
    }

    bytes
}
