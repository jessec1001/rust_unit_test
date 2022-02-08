use std::env;
use std::str::FromStr;
use secp256k1::{SecretKey};
use web3::contract::tokens::Tokenize;
use web3::contract::{Contract, Options};
use web3::types::{Address, Bytes, TransactionParameters, H160, U256, BlockNumber, U64, SignedTransaction};
use web3::ethabi::Uint;
use std::{thread, time::Duration};
use serde::{Deserialize, Serialize};
use std::process;
extern crate serde;
use std::fs::File;
use std::io::Read;
use web3::transports::Http;
use web3::Web3;
use web3::ethabi::ethereum_types::H256;
use web3_rust_wrapper::Web3Manager;


#[tokio::main]
async fn main() -> web3::Result<()> {
    dotenv::dotenv().ok();

    // init web3 conection
    let web3HttpUrl = "https://api.avax-test.network/ext/bc/C/rpc";
    let web3WebsocketUrl = "wss://api.avax-test.network/ext/bc/C/ws";
    let mut web3m: Web3Manager = Web3Manager::new(web3HttpUrl, web3WebsocketUrl).await;

    // load acount from .env file
    web3m.load_accounts(&env::var("ACCOUNT_ADDRESS").unwrap(),
                        &env::var("PRIVATE_TEST_KEY").unwrap());

    web3m.get_accounts();


    // init contract
    let contract_address = "0xcd43d09624D420e2d105155B1E16fB69549a0235";

    let contract_instance: Contract<Http>
        = Contract::from_json(web3m.web3http.eth(),
                              Address::from_str(contract_address).unwrap(),
                              include_bytes!("../abi/TokenAbi.json")).unwrap();

    println!("contract_instance_address: {}", contract_instance.address().to_string());

    // query contract
    let balance_of: Uint = contract_instance.query("balanceOf",
                                                   web3m.get_account(),
                                                   None,
                                                   Options::default(),
                                                   None).await.unwrap();
    println!("balance_of tokens: {}", balance_of);


    // send tokens
    // set function parameters
    let contract_function = "transfer";
    let val = U256::from_dec_str("10000").unwrap();
    let recipient_address: Address = Address::from_str("0xB06a4327FF7dB3D82b51bbD692063E9a180b79D9").unwrap(); // test
    let contract_function_parameters = (recipient_address, val);

    // estimate gas for call this function with this parameters
    let estimated_tx_gas: U256 = web3m.estimate_tx_gas(contract_instance.clone(),
                                                       contract_function,
                                                       contract_function_parameters).await;
    println!("estimated_tx_gas: {}", estimated_tx_gas);

    // enconde tx data
    let tx_data: Bytes = web3m.encode_tx_data(contract_instance.clone(),
                                              contract_function,
                                              contract_function_parameters).await;
    println!("tx_data: {:?}", tx_data);

    // get last nonce
    let nonce = web3m.web3http
        .eth()
        .transaction_count(web3m.get_account(), None)
        .await
        .unwrap();
    println!("nonce: {}", nonce);

    // build tx parameters
    let tx_parameters: TransactionParameters = web3m.encode_tx_parameters(nonce,
                                                                          contract_instance.address(),
                                                                          U256::from_dec_str("0").unwrap(),
                                                                          estimated_tx_gas, tx_data).await;
    println!("tx_parameters: {:?}", tx_parameters);

    // sign tx
    let private_key: secp256k1::SecretKey = SecretKey::from_str(&env::var("PRIVATE_TEST_KEY").unwrap()).unwrap();
    let signed_transaction: SignedTransaction = web3m.web3http
        .accounts()
        .sign_transaction(tx_parameters, &private_key)
        .await
        .unwrap();

    // send tx
    let result: H256 = web3m.web3http
        .eth()
        .send_raw_transaction(signed_transaction.raw_transaction)
        .await
        .unwrap();

    println!("Transaction successful with hash: {}{:?}", &env::var("EXPLORER").unwrap(), result);

    Ok(())
}