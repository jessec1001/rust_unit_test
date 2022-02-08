use std::env;
use std::str::FromStr;
use secp256k1::{SecretKey};
use web3::contract::tokens::{Tokenize, Detokenize};
use web3::contract::{Contract, Options};
use web3::types::{Address, Bytes, TransactionParameters, H160, U256, BlockNumber, U64, SignedTransaction, TransactionRequest};
use web3::ethabi::Uint;
use std::{thread, time::Duration};
use serde::{Deserialize, Serialize};
use std::process;
use web3::transports::{Http, WebSocket};
use web3::{Web3, Error};
use std::collections::HashMap;
use web3::ethabi::ethereum_types::H256;
use std::any::{Any, TypeId};
use web3::futures::future::ok;
use std::ops::Div;
use std::convert::{From, TryFrom};
use web3::api::Eth;
use colored::Colorize;
use std::ptr::null;
use std::future::Future;

trait InstanceOf
    where
        Self: Any,
{
    fn instance_of<U: ?Sized + Any>(&self) -> bool {
        TypeId::of::<Self>() == TypeId::of::<U>()
    }
}

// implement this trait for every type that implements `Any` (which is most types)
impl<T: ?Sized + Any> InstanceOf for T {}

pub struct Web3Manager {
    accounts: Vec<H160>,
    pub web3http: Web3<Http>,
    pub web3WebSocket: Web3<WebSocket>,
    accounts_map: HashMap<H160, SecretKey>,
}

impl Web3Manager {
    /*
    pub async fn instance_contract(&mut self, plain_contract_address: &str, abi_path: &str) -> Contract<Http> {
        let contract_instance: Contract<Http>
            = Contract::from_json(self.web3s.eth(),
                                  Address::from_str(plain_contract_address).unwrap(),
                                  include_bytes!("{}", abi_path)).unwrap();
        return contract_instance;
    }
    */


    pub async fn get_token_balances(&mut self) -> U256 {
        let block: Option<BlockNumber> = BlockNumber::Pending.into();
        let nonce: U256 = self.web3http
            .eth()
            .transaction_count(self.accounts[0], block)
            .await
            .unwrap();
        return nonce;
    }

    pub async fn get_nonce(&mut self) -> U256 {
        let block: Option<BlockNumber> = BlockNumber::Pending.into();
        let nonce: U256 = self.web3http
            .eth()
            .transaction_count(self.accounts[0], block)
            .await
            .unwrap();
        return nonce;
    }

    pub async fn query_contract<R, P, T>(&mut self, func: &str, contract: Contract<Http>, params: P) -> web3::contract::Result<R>
        where
            R: Detokenize,
            P: Tokenize {

        /*
            let balance_of: Uint = contract_instance.query("balanceOf", web3m.get_account(), None, Options::default(), None).await.unwrap();
    println!("balance_of: {}", balance_of);
         */

        //println!("msg is ComplexMessage: {}", params.instance_of::<bool>());

        let res = contract
            .query(func, params, self.accounts[0], Options::default(), None)
            .await;

        return res;
    }

    pub fn load_accounts(&mut self, plain_address: &str, plain_private_key: &str) -> &mut Web3Manager {
        let private_key: SecretKey = SecretKey::from_str(plain_private_key).unwrap();
        let wallet: H160 = H160::from_str(plain_address).unwrap();

        self.accounts_map.insert(wallet, private_key);
        self.accounts.push(wallet);

        println!("wallet: {:?}", wallet);
        return self;
    }

    pub fn get_accounts(&mut self) -> &mut Web3Manager {
        //let keys = self.accountss.into_keys();


        //println!("keysd: {:?}", keysd);
        return self;
    }

    pub fn load_account(&mut self, plain_address: &str, plain_private_key: &str) -> &mut Web3Manager {
        //let account: Address = Address::from_str(plain_address).unwrap();


        self.accounts.push(H160::from_str(plain_address).unwrap());

        //let account: Address = Address::from_str("0xB06a4327FF7dB3D82b51bbD692063E9a180b79D9").unwrap(); // test

        //self.accounts.push(account);

        println!("self.accounts: {:?}", self.accounts);
        return self;
    }

    pub async fn new(url: &str, websocketUrl: &str) -> Web3Manager {
        let web3http: Web3<Http> = web3::Web3::new(web3::transports::Http::new(url).unwrap());
        let web3WebSocket = web3::Web3::new(web3::transports::WebSocket::new(websocketUrl).await.unwrap());

        let accounts: Vec<Address> = vec![];
        let accounts_map: HashMap<H160, SecretKey> = HashMap::new();

        return Web3Manager { accounts, web3http, web3WebSocket, accounts_map };
    }

    pub async fn gas_price(&mut self) -> U256 {
        let gas_price: U256 = self.web3http.eth().gas_price().await.unwrap();
        return gas_price;
    }

    pub async fn get_block(&mut self) -> U64 {
        let result: U64 = self.web3http
            .eth()
            .block_number().
            await.
            unwrap();
        return result;
    }

    pub async fn send_raw_transaction(&mut self, raw_transaction: Bytes) -> H256 {
        let result: H256 = self.web3http
            .eth()
            .send_raw_transaction(raw_transaction)
            .await
            .unwrap();
        return result;
    }

    pub async fn sign_transaction(&mut self, transact_obj: TransactionParameters, secret_key: &str) -> SignedTransaction {
        let private_key: secp256k1::SecretKey = SecretKey::from_str(secret_key).unwrap();
        let signed_transaction: SignedTransaction = self.web3http
            .accounts()
            .sign_transaction(transact_obj, &private_key)
            .await
            .unwrap();
        return signed_transaction;
    }

    pub async fn encode_tx_parameters(&mut self, nonce: U256, to: Address, value: U256, gas: U256, data: Bytes) -> TransactionParameters {
        let gas_price: U256 = self.web3http.eth().gas_price().await.unwrap();
        println!("gas price: {}", gas_price);

        let chain_id: Option<u64> = Option::Some(u64::try_from(self.web3http.eth().chain_id().await.unwrap()).unwrap());

        let transact_obj = TransactionParameters {
            nonce: Some(nonce),
            to: Some(to),
            value,
            gas_price: Some(gas_price),
            gas,
            data,
            chain_id,
            ..Default::default()
        };

        return transact_obj;
    }


    pub async fn encode_tx_data<P>(&mut self, contract: Contract<Http>, func: &str, params: P) -> Bytes
        where P: Tokenize, {
        let data = contract
            .abi()
            .function(func)
            .unwrap()
            .encode_input(&params.into_tokens())
            .unwrap();
        return data.into();
    }


    pub async fn dddd<P>(&mut self, contract: Contract<Http>, func: &str, params: P) {}

    pub async fn estimate_tx_gas<P>(&mut self, contract: Contract<Http>, func: &str, params: P) -> U256
        where P: Tokenize, {
        let out_gas_estimate: U256 = contract
            .estimate_gas(func,
                          params,
                          self.accounts[0],
                          Options {
                              value: Some(U256::from_dec_str("0").unwrap()),
                              gas: Some(U256::from_dec_str("80000000").unwrap()),
                              ..Default::default()
                          },
            )
            .await.unwrap();
        return out_gas_estimate;
    }

    pub fn get_account(&mut self) -> H160 {
        return self.accounts[0];
    }


    pub async fn send_eth(&mut self, to: Address, value: U256) -> H256 {
        let gas_price: U256 = self.web3http.eth().gas_price().await.unwrap();


        // Insert the 20-byte "from" address in hex format (prefix with 0x)
        //let from = Address::from_str("0xC48ad5fd060e1400a41bcf51db755251AD5A2475").unwrap();
        let from = self.get_account();

        // Insert the 20-byte "to" address in hex format (prefix with 0x)
        //let to = Address::from_str(to).unwrap();

        // Build the tx object
        let tx_object = TransactionRequest {
            from,
            to: Some(to),
            value: Some(U256::from(value)),
            ..Default::default()
        };

        // Send the tx to localhost
        let result = self.web3http.eth().send_transaction(tx_object).await.unwrap();

        println!("Tx succeeded with hash: {}", result);
        return result;
    }
}


fn chunks(data: Vec<Uint>, chunk_size: usize) -> Vec<Vec<Uint>> {
    let mut results = vec![];
    let mut current = vec![];
    for i in data {
        if current.len() >= chunk_size {
            results.push(current);
            current = vec![];
        }
        current.push(i);
    }
    results.push(current);

    return results;
}

mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use std::cmp::Ordering;

    // init web3 conection
    let web3HttpUrl = "https://api.avax-test.network/ext/bc/C/rpc";
    let web3WebsocketUrl = "wss://api.avax-test.network/ext/bc/C/ws";
    let mut web3m: Web3Manager = Web3Manager::new(web3HttpUrl, web3WebsocketUrl).await;

    #[test]
    fn test_gas_price() {
        let result = gas_price(mut)
        assert_eq!(Ordering::Greater, result);
    }

    #[test]
    fn test_get_block() {
        let result = get_account(mut)
        assert_eq!(Ordering::Greater, result);
    }

  
}