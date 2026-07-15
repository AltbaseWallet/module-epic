// Copyright 2019 The Epic Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::config::{EpicboxConfig, TorConfig};
use crate::epicbox::protocol::{
    ProtocolError, ProtocolRequest, ProtocolRequestV2, ProtocolResponseV2,
};
use crate::keychain::Keychain;
use crate::libwallet::crypto::{sign_challenge, Hex};
use crate::libwallet::message::EncryptedMessage;
use crate::util::secp::key::PublicKey;

use crate::libwallet::wallet_lock;
use crate::libwallet::{
    address, Address, EpicboxAddress, TxProof, DEFAULT_EPICBOX_PORT_443, DEFAULT_EPICBOX_PORT_80,
};
use crate::libwallet::{NodeClient, WalletInst, WalletLCProvider};

use crate::Error;

use crate::libwallet::{Slate, SlateVersion, VersionedSlate};
use crate::util::secp::key::SecretKey;
use crate::util::Mutex;

use std::collections::HashMap;
use std::fmt::{self, Debug};

use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::thread::JoinHandle;

use crate::libwallet::api_impl::foreign;
use crate::libwallet::api_impl::owner;

use epic_wallet_util::epic_core::core::amount_to_hr_string;
use rand::rng;
use rand::seq::SliceRandom;
use std::env;
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::string::ToString;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::thread::spawn;
use std::time::Duration;

use tungstenite::client::{uri_mode, IntoClientRequest};
use tungstenite::handshake::HandshakeError;
use tungstenite::Error as tungsteniteError;
use tungstenite::{client_tls_with_config, Error as ErrorTungstenite, Message};
use tungstenite::{protocol::WebSocket, stream::MaybeTlsStream};
// Copyright 2019 The vault713 Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const CONNECTION_ERR_MSG: &str = "\nCan't connect to the epicbox server!\n\
	Check your epic-wallet.toml settings and make sure epicbox domain is correct.\n";

const EPICBOX_PROTOCOL_VERSION: &str = "3.0.0";
const EPICBOX_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const EPICBOX_IO_TIMEOUT: Duration = Duration::from_secs(12);
const EPICBOX_SEND_COMPLETION_TIMEOUT: Duration = Duration::from_secs(90);

type SendCompletion = Result<Slate, String>;
static SEND_COMPLETIONS: OnceLock<StdMutex<HashMap<String, Sender<SendCompletion>>>> =
    OnceLock::new();
static ACTIVE_PUBLISHERS: OnceLock<StdMutex<HashMap<String, EpicboxPublisher>>> = OnceLock::new();

fn send_completions() -> &'static StdMutex<HashMap<String, Sender<SendCompletion>>> {
    SEND_COMPLETIONS.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn register_send_completion(slate_id: &str, sender: Sender<SendCompletion>) {
    if let Ok(mut completions) = send_completions().lock() {
        completions.insert(slate_id.to_string(), sender);
    }
}

struct SendCompletionRegistration(String);

impl Drop for SendCompletionRegistration {
    fn drop(&mut self) {
        remove_send_completion(&self.0);
    }
}

fn remove_send_completion(slate_id: &str) {
    if let Ok(mut completions) = send_completions().lock() {
        completions.remove(slate_id);
    }
}

fn complete_send(slate_id: &str, result: SendCompletion) {
    let sender = send_completions()
        .lock()
        .ok()
        .and_then(|mut completions| completions.remove(slate_id));
    if let Some(sender) = sender {
        let _ = sender.send(result);
    }
}

fn active_publishers() -> &'static StdMutex<HashMap<String, EpicboxPublisher>> {
    ACTIVE_PUBLISHERS.get_or_init(|| StdMutex::new(HashMap::new()))
}

fn epicbox_io_error(message: impl Into<String>) -> ErrorTungstenite {
    ErrorTungstenite::Io(io::Error::new(io::ErrorKind::TimedOut, message.into()))
}

fn connect_epicbox_socket(
    url: &str,
) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, ErrorTungstenite> {
    let request = url.into_client_request()?;
    let uri = request.uri();
    let mode = uri_mode(uri)?;
    let host = uri
        .host()
        .ok_or_else(|| epicbox_io_error("epicbox host is missing"))?;
    let host = if host.starts_with('[') {
        &host[1..host.len() - 1]
    } else {
        host
    };
    let port = uri.port_u16().unwrap_or(match mode {
        tungstenite::stream::Mode::Plain => DEFAULT_EPICBOX_PORT_80,
        tungstenite::stream::Mode::Tls => DEFAULT_EPICBOX_PORT_443,
    });

    let mut last_error: Option<io::Error> = None;
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, EPICBOX_CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                stream.set_read_timeout(Some(EPICBOX_IO_TIMEOUT))?;
                stream.set_write_timeout(Some(EPICBOX_IO_TIMEOUT))?;
                let (socket, _) =
                    client_tls_with_config(request, stream, None, None).map_err(|e| match e {
                        HandshakeError::Failure(error) => error,
                        HandshakeError::Interrupted(_) => {
                            epicbox_io_error("epicbox websocket handshake interrupted")
                        }
                    })?;
                return Ok(socket);
            }
            Err(error) => last_error = Some(error),
        }
    }

    Err(ErrorTungstenite::Io(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("epicbox connect timeout: {url}"),
        )
    })))
}

/// Epicbox 'plugin' implementation
pub enum CloseReason {
    Normal,
    Abnormal(Error),
}

#[derive(Clone)]
pub struct EpicboxSubscriber {
    address: EpicboxAddress,
    broker: EpicboxBroker,
    secret_key: SecretKey,
    wallet_mode: String,
    is_node_synced: Arc<AtomicBool>,
}
#[derive(Clone)]
pub struct EpicboxPublisher {
    address: EpicboxAddress,
    broker: EpicboxBroker,
    secret_key: SecretKey,
    wallet_mode: String,
}

pub struct EpicboxListener {
    pub address: EpicboxAddress,
    pub publisher: EpicboxPublisher,
    pub subscriber: EpicboxSubscriber,
    pub handle: JoinHandle<()>,
}

#[derive(Clone)]
pub struct EpicboxChannel {
    dest: String,
    epicbox_config: Option<EpicboxConfig>,
}

#[derive(Clone)]
pub struct EpicboxListenChannel {
    _priv: (),
}

impl EpicboxListenChannel {
    pub fn new() -> Result<EpicboxListenChannel, Error> {
        Ok(EpicboxListenChannel { _priv: () })
    }
    pub fn listen<L, C, K>(
        &self,
        wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
        keychain_mask: Arc<Mutex<Option<SecretKey>>>,
        epicbox_config: EpicboxConfig,
        reconnections: &mut u32,
        is_node_synced: Arc<AtomicBool>,
        tor_config: TorConfig,
    ) -> Result<(), Error>
    where
        L: WalletLCProvider<'static, C, K> + 'static,
        C: NodeClient + 'static,
        K: Keychain + 'static,
    {
        let (address, sec_key) = {
            let a_keychain = keychain_mask.clone();
            let a_wallet = wallet.clone();
            let mask = a_keychain.lock();
            let mut w_lock = a_wallet.lock();
            let lc = w_lock.lc_provider()?;
            let w_inst = lc.wallet_inst()?;
            let k = w_inst.keychain((&mask).as_ref())?;
            let parent_key_id = w_inst.parent_key_id();
            let sec_key = address::address_from_derivation_path(&k, &parent_key_id, 0)?;
            let pub_key = PublicKey::from_secret_key(k.secp(), &sec_key).unwrap();

            let address = EpicboxAddress::new(
                pub_key.clone(),
                epicbox_config.epicbox_domain.clone(),
                epicbox_config.epicbox_port,
            );

            (address, sec_key)
        };
        let url = {
            let cloned_address = address.clone();
            match epicbox_config.epicbox_protocol_unsecure.unwrap_or(false) {
                true => format!(
                    "ws://{}:{}",
                    cloned_address.domain,
                    cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT_80)
                ),
                false => format!(
                    "wss://{}:{}",
                    cloned_address.domain,
                    cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT_443)
                ),
            }
        };
        let (tx, _rx): (Sender<bool>, Receiver<bool>) = channel();

        debug!("Connecting to the epicbox server at {} ..", url.clone());
        let socket = connect_epicbox_socket(&url).map_err(|e| {
            warn!("{}", Error::EpicboxTungstenite(format!("{}", e).into()));
            *reconnections += 1;
            Error::EpicboxTungstenite(format!("{}", e).into())
        })?;

        let publisher =
            EpicboxPublisher::new(address.clone(), sec_key, socket, tx, "listener".to_string())?;

        let mut subscriber = EpicboxSubscriber::new(&publisher, is_node_synced)?;

        let container = Container::new(epicbox_config.clone());
        let cpublisher = publisher.clone();
        let mask = keychain_mask.lock();
        let km = mask.clone();
        let controller = EpicboxController::new(
            container,
            cpublisher,
            wallet,
            km,
            reconnections,
            tor_config.clone(),
        )
        .expect("Could not init epicbox listener!");

        let publisher_key = address.to_string();
        if let Ok(mut publishers) = active_publishers().lock() {
            publishers.insert(publisher_key.clone(), publisher.clone());
        }
        info!("Starting epicbox listener for: {}", address);
        let result = subscriber.start(controller);
        if let Ok(mut publishers) = active_publishers().lock() {
            publishers.remove(&publisher_key);
        }
        result
    }

    pub fn send_via_listener(
        &self,
        from: &str,
        to: &str,
        slate: &Slate,
    ) -> Result<Slate, Error> {
        let publisher = (0..100)
            .find_map(|_| {
                let publisher = active_publishers()
                    .lock()
                    .ok()
                    .and_then(|publishers| publishers.get(from).cloned());
                if publisher.is_none() {
                    std::thread::sleep(Duration::from_millis(100));
                }
                publisher
            })
            .ok_or_else(|| Error::GenericError("Epicbox listener is not ready".to_string()))?;
        let destination = EpicboxAddress::from_str(to)?;
        let slate_id = slate.id.to_string();
        let (completion_tx, completion_rx) = channel::<SendCompletion>();
        register_send_completion(&slate_id, completion_tx);
        let _completion_registration = SendCompletionRegistration(slate_id.clone());
        let versioned = VersionedSlate::into_version(slate.clone(), SlateVersion::V2);
        publisher
            .post_slate(&versioned, &destination, false)
            .map_err(|error| {
                Error::GenericError(format!(
                    "Epicbox transaction {slate_id} publish outcome is uncertain: {error}"
                ))
            })?;

        match completion_rx.recv_timeout(EPICBOX_SEND_COMPLETION_TIMEOUT) {
            Ok(Ok(finalized_slate)) => Ok(finalized_slate),
            Ok(Err(message)) => Err(Error::GenericError(format!(
                "Epicbox transaction {slate_id} was published but finalization failed: {message}"
            ))),
            Err(RecvTimeoutError::Timeout) => Err(Error::GenericError(format!(
                "Epicbox transaction {slate_id} was published and is awaiting finalization"
            ))),
            Err(RecvTimeoutError::Disconnected) => Err(Error::GenericError(format!(
                "Epicbox transaction {slate_id} was published but its completion channel closed unexpectedly"
            ))),
        }
    }
}
impl EpicboxChannel {
    /// new epicbox.
    pub fn new(
        dest: &String,
        epicbox_config: Option<EpicboxConfig>,
    ) -> Result<EpicboxChannel, Error> {
        Ok(EpicboxChannel {
            dest: dest.clone(),
            epicbox_config: epicbox_config.clone(),
        })
    }

    pub fn send<L, C, K>(
        &self,
        wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
        keychain_mask: Option<SecretKey>,
        slate: &Slate,
        is_node_synced: Arc<AtomicBool>,
        tor_config: TorConfig,
    ) -> Result<Slate, Error>
    where
        L: WalletLCProvider<'static, C, K> + 'static,
        C: NodeClient + 'static,
        K: Keychain + 'static,
    {
        let config = match self.epicbox_config.clone() {
            None => EpicboxConfig::default(),
            Some(epicbox_config) => epicbox_config,
        };

        let container = Container::new(config.clone());
        let slate_id = slate.id.to_string();
        let (completion_tx, completion_rx) = channel::<SendCompletion>();
        register_send_completion(&slate_id, completion_tx);
        let _completion_registration = SendCompletionRegistration(slate_id.clone());

        let (tx, _rx): (Sender<bool>, Receiver<bool>) = channel();
        let listener = start_epicbox(
            container.clone(),
            wallet.clone(),
            keychain_mask.clone(),
            config,
            tx,
            is_node_synced,
            tor_config.clone(),
        )?;

        container
            .lock()
            .listeners
            .insert(ListenerInterface::Epicbox, listener);

        let vslate = VersionedSlate::into_version(slate.clone(), SlateVersion::V2);

        match container
            .lock()
            .listener(ListenerInterface::Epicbox)?
            .publish(&vslate, &self.dest)
        {
            Ok(_) => (),
            Err(e) => return Err(e),
        };

        {
            wallet_lock!(wallet, w);
            owner::tx_lock_outputs(
                &mut **w,
                keychain_mask.as_ref(),
                slate,
                0,
                Some(self.dest.clone()),
            )?;
        }

        let completion = completion_rx.recv_timeout(EPICBOX_SEND_COMPLETION_TIMEOUT);
        match completion {
            Ok(Ok(finalized_slate)) => Ok(finalized_slate),
            Ok(Err(message)) => Err(Error::GenericError(message)),
            Err(RecvTimeoutError::Timeout) => Err(Error::GenericError(format!(
                "Epicbox transaction {slate_id} was not finalized and accepted by the node within {} seconds",
                EPICBOX_SEND_COMPLETION_TIMEOUT.as_secs()
            ))),
            Err(RecvTimeoutError::Disconnected) => Err(Error::GenericError(format!(
                "Epicbox transaction {slate_id} completion channel closed unexpectedly"
            ))),
        }
    }
}

pub fn start_epicbox<L, C, K>(
    container: Arc<Mutex<Container>>,
    wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
    keychain_mask: Option<SecretKey>,
    config: EpicboxConfig,
    tx: Sender<bool>,
    is_node_synced: Arc<AtomicBool>,
    tor_config: TorConfig,
) -> Result<Box<dyn Listener>, Error>
where
    L: WalletLCProvider<'static, C, K> + 'static,
    C: NodeClient + 'static,
    K: Keychain + 'static,
{
    let (address, sec_key) = {
        let a_wallet = wallet.clone();
        let mut w_lock = a_wallet.lock();
        let lc = w_lock.lc_provider()?;
        let w_inst = lc.wallet_inst()?;
        let k = w_inst.keychain(keychain_mask.as_ref())?;
        let parent_key_id = w_inst.parent_key_id();
        let sec_key = address::address_from_derivation_path(&k, &parent_key_id, 0)?;
        let pub_key = PublicKey::from_secret_key(k.secp(), &sec_key).unwrap();

        let address = EpicboxAddress::new(
            pub_key.clone(),
            config.epicbox_domain.clone(),
            config.epicbox_port,
        );
        (address, sec_key)
    };
    let url = {
        let cloned_address = address.clone();
        match config.epicbox_protocol_unsecure.unwrap_or(false) {
            true => format!(
                "ws://{}:{}",
                cloned_address.domain,
                cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT_80)
            ),
            false => format!(
                "wss://{}:{}",
                cloned_address.domain,
                cloned_address.port.unwrap_or(DEFAULT_EPICBOX_PORT_443)
            ),
        }
    };
    debug!("Connecting to the epicbox server at {} ..", url.clone());
    let socket = connect_epicbox_socket(&url)
        .map_err(|e| Error::EpicboxTungstenite(format!("{CONNECTION_ERR_MSG}{}", e).into()))?;

    let publisher =
        EpicboxPublisher::new(address.clone(), sec_key, socket, tx, "send".to_string())?;
    let subscriber = EpicboxSubscriber::new(&publisher, is_node_synced)?;

    let mut csubscriber = subscriber.clone();
    let cpublisher = publisher.clone();
    let mut reconnections = 0;

    let handle = spawn(move || {
        let controller = EpicboxController::new(
            container,
            cpublisher,
            wallet,
            keychain_mask,
            &mut reconnections,
            tor_config.clone(),
        )
        .expect("Could not init epicbox controller!");

        csubscriber
            .start(controller)
            .expect("Could not start epicbox controller!");
        ()
    });

    Ok(Box::new(EpicboxListener {
        address,
        publisher,
        subscriber,
        handle,
    }))
}

impl Listener for EpicboxListener {
    /// keep :)
    fn interface(&self) -> ListenerInterface {
        ListenerInterface::Epicbox
    }

    fn address(&self) -> String {
        self.address.stripped()
    }
    /// post slate
    fn publish(&self, slate: &VersionedSlate, to: &String) -> Result<(), Error> {
        let address = EpicboxAddress::from_str(to)?;
        self.publisher.post_slate(slate, &address, true)
    }

    /// stops wss connection
    fn stop(self: Box<Self>) -> Result<(), Error> {
        let s = *self;
        s.subscriber.stop();
        let _ = s.handle.join();
        Ok(())
    }
}

impl EpicboxPublisher {
    pub fn new(
        address: EpicboxAddress,
        secret_key: SecretKey,
        socket: WebSocket<MaybeTlsStream<TcpStream>>,
        tx: Sender<bool>,
        wallet_mode: String,
    ) -> Result<Self, Error> {
        Ok(Self {
            address,
            broker: EpicboxBroker::new(socket, tx)?,
            secret_key,
            wallet_mode,
        })
    }
}

impl Publisher for EpicboxPublisher {
    fn post_slate(
        &self,
        slate: &VersionedSlate,
        to: &EpicboxAddress,
        close_connection: bool,
    ) -> Result<(), Error> {
        self.broker
            .post_slate(slate, &to, &self.address, &self.secret_key)?;
        if close_connection {
            let _ = self.broker.stop();
        }
        Ok(())
    }
}
impl EpicboxSubscriber {
    pub fn new(
        publisher: &EpicboxPublisher,
        is_node_synced: Arc<AtomicBool>,
    ) -> Result<Self, Error> {
        Ok(Self {
            address: publisher.address.clone(),
            broker: publisher.broker.clone(),
            secret_key: publisher.secret_key.clone(),
            wallet_mode: publisher.wallet_mode.clone(),
            is_node_synced, // default to true, can be set later
        })
    }
}

pub struct EpicboxController<'a, P, L, C, K>
where
    P: Publisher,
    L: WalletLCProvider<'static, C, K> + 'static,
    C: NodeClient + 'static,
    K: Keychain + 'static,
{
    publisher: P,
    /// Wallet instance
    pub wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
    /// Keychain mask
    pub keychain_mask: Option<SecretKey>,
    pub reconnections: &'a mut u32,
    pub tor_config: TorConfig,
}
pub struct Container {
    pub config: EpicboxConfig,
    pub account: String,
    pub listeners: HashMap<ListenerInterface, Box<dyn Listener>>,
}
impl Container {
    pub fn new(config: EpicboxConfig) -> Arc<Mutex<Self>> {
        let container = Self {
            config,
            account: String::from("default"),
            //TODO: reduce listeners
            listeners: HashMap::with_capacity(4),
        };
        Arc::new(Mutex::new(container))
    }

    pub fn listener(&self, interface: ListenerInterface) -> Result<&Box<dyn Listener>, Error> {
        self.listeners
            .get(&interface)
            .ok_or(Error::NoListener(format!("{}", interface)))
    }
}

pub trait Listener: Send + 'static {
    fn interface(&self) -> ListenerInterface;
    fn address(&self) -> String;
    fn publish(&self, slate: &VersionedSlate, to: &String) -> Result<(), Error>;
    fn stop(self: Box<Self>) -> Result<(), Error>;
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub enum ListenerInterface {
    Epicbox,
}
impl fmt::Display for ListenerInterface {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ListenerInterface::Epicbox => write!(f, "Epicbox"),
        }
    }
}

impl<'a, P, L, C, K> EpicboxController<'a, P, L, C, K>
where
    P: Publisher,
    L: WalletLCProvider<'static, C, K> + 'static,
    C: NodeClient + 'static,
    K: Keychain + 'static,
{
    pub fn new(
        // TODO: check if container is required
        _container: Arc<Mutex<Container>>,
        publisher: P,
        wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
        keychain_mask: Option<SecretKey>,
        reconnections: &'a mut u32,
        tor_config: TorConfig,
    ) -> Result<Self, Error> {
        Ok(Self {
            publisher,
            wallet,
            keychain_mask,
            reconnections,
            tor_config,
        })
    }

    fn process_incoming_slate(
        &self,
        address: Option<String>,
        slate: &mut Slate,
        _tx_proof: Option<&mut TxProof>,
    ) -> Result<bool, Error> {
        // Case 1: Receiving a new transaction (not finalized)
        if slate.num_participants > slate.participant_data.len() {
            if slate.tx.inputs().is_empty() {
                // TODO: invoicing
            } else {
                info!("Receive new transaction (foreign::receive_tx)");
                wallet_lock!(self.wallet, w);
                match foreign::receive_tx(
                    &mut **w,
                    self.keychain_mask.as_ref(),
                    &slate,
                    None,
                    None,
                    address,
                    false,
                ) {
                    Ok(ret_slate) => {
                        *slate = ret_slate;
                    }
                    Err(e) => return Err(Error::EpicboxReceiveTx(format!("{:?}", e)).into()),
                };
            }
            return Ok(false);
        }

        // Case 2: Finalizing and posting the transaction
        info!("Finalize transaction (owner::finalize_tx)");
        let (finalized_slate, mut onion_addresses, node_client) = {
            wallet_lock!(self.wallet, w);
            let finalized_slate = owner::finalize_tx(&mut **w, self.keychain_mask.as_ref(), slate)?;
            // Get onion addresses and node client while wallet is still locked
            let onion_addresses = w.w2n_client().get_onion_addresses().unwrap_or_default();
            let node_client = w.w2n_client().clone();
            (finalized_slate, onion_addresses, node_client)
        };

        onion_addresses.shuffle(&mut rng());

        if let Some(tor_node_url) = onion_addresses.first() {
            if self.tor_config.use_tor_listener {
                info!("Post transaction to Tor address: {}", tor_node_url);
                match owner::post_tx_tor(&node_client, &finalized_slate.tx, tor_node_url) {
                    Ok(_) => {}
                    Err(_) => {
                        owner::post_tx(&node_client, &finalized_slate.tx, false)?;
                    }
                }
            } else {
                // Tor not enabled, use Dandelion/HTTP fallback
                owner::post_tx(&node_client, &finalized_slate.tx, false)?;
            }
        } else {
            owner::post_tx(&node_client, &finalized_slate.tx, false)?;
        }

        Ok(true)
    }
}
pub trait SubscriptionHandler: Send {
    fn on_slate(&self, from: &EpicboxAddress, slate: &VersionedSlate, proof: Option<&mut TxProof>);
    fn on_close(&self, result: CloseReason);
}

impl<'a, P, L, C, K> SubscriptionHandler for EpicboxController<'a, P, L, C, K>
where
    P: Publisher,
    L: WalletLCProvider<'static, C, K> + 'static,
    C: NodeClient + 'static,
    K: Keychain + 'static,
{
    fn on_slate(
        &self,
        from: &EpicboxAddress,
        slate: &VersionedSlate,
        tx_proof: Option<&mut TxProof>,
    ) {
        let version = slate.version();
        let mut slate: Slate = slate.into();

        if slate.num_participants > slate.participant_data.len() {
            debug!(
                "Slate [{}] received from [{}] for [{}] epics",
                slate.id.to_string(),
                from.to_string(),
                amount_to_hr_string(slate.amount, false)
            );
        } else {
            debug!(
                "Slate [{}] received back from [{}] for [{}] epics",
                slate.id.to_string(),
                from.to_string(),
                amount_to_hr_string(slate.amount, false)
            );
        };

        let slate_id = slate.id.to_string();
        let result = self
            .process_incoming_slate(Some(from.to_string()), &mut slate, tx_proof)
            .and_then(|is_finalized| {
                if !is_finalized {
                    let _id = slate.id.clone();
                    let slate = VersionedSlate::into_version(slate, version);

                    self.publisher
                        .post_slate(&slate, from, false)
                        .map_err(|e| {
                            error!("{}: {}", "ERROR", e);
                            e
                        })
                        .expect("failed posting slate!");
                } else {
                    info!("Slate [{}] finalized successfully", slate.id.to_string());
                    complete_send(&slate_id, Ok(slate.clone()));
                }
                Ok(())
            });

        match result {
            Ok(()) => {}
            Err(e) => {
                complete_send(&slate_id, Err(e.to_string()));
                error!("Error process incoming slate. {:?}", e)
            }
        }
    }

    fn on_close(&self, reason: CloseReason) {
        match reason {
            CloseReason::Normal => {
                debug!("Listener stopped, normal exit.")
            }
            CloseReason::Abnormal(error) => {
                error!("{:?}", error.to_string())
            }
        }
    }
}

impl EpicboxSubscriber {
    fn start<P, L, C, K>(&mut self, handler: EpicboxController<P, L, C, K>) -> Result<(), Error>
    where
        P: Publisher,
        L: WalletLCProvider<'static, C, K> + 'static,
        C: NodeClient + 'static,
        K: Keychain + 'static,
    {
        self.broker.subscribe(
            &self.address,
            &self.secret_key,
            handler,
            &self.wallet_mode,
            self.is_node_synced.clone(),
        )
    }

    fn stop(&self) {
        let _ = self.broker.stop();
    }
}

pub trait Publisher: Send {
    fn post_slate(
        &self,
        slate: &VersionedSlate,
        to: &EpicboxAddress,
        close_connection: bool,
    ) -> Result<(), Error>;
}

///TODO: reduce to broker
#[derive(Clone)]
pub struct EpicboxBroker {
    inner: Arc<Mutex<WebSocket<MaybeTlsStream<TcpStream>>>>,
    tx: Sender<bool>,
}
impl EpicboxBroker {
    /// Create a EpicboxBroker,
    pub fn new(
        inner: WebSocket<MaybeTlsStream<TcpStream>>,

        tx: Sender<bool>,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            tx,
        })
    }

    /// Start a listener, passing received messages to the wallet api directly
    pub fn subscribe<P, L, C, K>(
        &mut self,
        address: &EpicboxAddress,
        secret_key: &SecretKey,
        handler: EpicboxController<P, L, C, K>,
        wallet_mode: &String,
        is_node_synced: Arc<AtomicBool>,
    ) -> Result<(), Error>
    where
        P: Publisher,
        L: WalletLCProvider<'static, C, K> + 'static,
        C: NodeClient + 'static,
        K: Keychain + 'static,
    {
        let handler = Arc::new(Mutex::new(handler));
        let sender = self.inner.clone();
        let mut first_run = true;

        let mut client = EpicboxClient {
            sender,
            handler: handler.clone(),
            challenge: None,
            address: address.clone(),
            secret_key: secret_key.clone(),
            tx: self.tx.clone(),
        };

        //let subscribe = DEFAULT_CHALLENGE_RAW;
        let ver = EPICBOX_PROTOCOL_VERSION;
        let wallet_mode = wallet_mode;

        let res = loop {
            // Pause if node is not synced
            if !is_node_synced.load(std::sync::atomic::Ordering::SeqCst) {
                warn!("Node not synced, pausing Epicbox message processing...");
                std::thread::sleep(std::time::Duration::from_secs(5));
                continue;
            }

            let err = client.sender.lock().read();

            match err {
                Err(e) => {
                    *handler.lock().reconnections += 1;
                    error!("Error reading message {:?}", e);
                    handler.lock().on_close(CloseReason::Abnormal(
                        Error::EpicboxWebsocketAbnormalTermination,
                    ));
                    match client.sender.lock().close(None) {
                        Ok(_) => error!("Client closed connection"),
                        Err(e) => error!("Client closed connection {:?}", e),
                    }

                    break Err(Error::EpicboxWebsocketAbnormalTermination);
                }
                Ok(message) => match message {
                    Message::Text(_) | Message::Binary(_) => {
                        let response = match serde_json::from_str::<ProtocolResponseV2>(
                            &message.to_string(),
                        ) {
                            Ok(x) => x,
                            Err(e) => {
                                error!(
                                    "Could not parse response: {:?}\nMessage was: {}",
                                    e,
                                    message.to_string()
                                );
                                return Ok(());
                            }
                        };

                        *handler.lock().reconnections = 0;

                        match response {
                            ProtocolResponseV2::Challenge { str } => {
                                client.challenge = Some(str.clone());

                                if first_run {
                                    client.client_details(wallet_mode.clone())?;

                                    first_run = false;

                                    info!("Starting epicbox subscription...");
                                }

                                let signature = sign_challenge(&str, &secret_key)?.to_hex();
                                let request_sub = ProtocolRequestV2::Subscribe {
                                    address: client.address.public_key.to_string(),
                                    ver: ver.to_string(),
                                    signature,
                                };

                                let _ = client.send(&request_sub).map_err(|e| {
                                    error!("Error attempting to send Subscribe {:?}", e)
                                });
                            }
                            ProtocolResponseV2::Slate {
                                from,
                                str,
                                challenge: _challenge,
                                signature,
                                ver: _, // unused, ignore
                                epicboxmsgid,
                            } => {
                                let (slate, mut tx_proof) = match TxProof::from_response(
                                    from,
                                    str,
                                    signature,
                                    &client.secret_key,
                                    Some(&client.address),
                                ) {
                                    Ok(x) => x,
                                    Err(e) => {
                                        error!("{}", e.to_string());
                                        return Ok(());
                                    }
                                };

                                let address = tx_proof.address.clone();
                                client.handler.lock().on_slate(
                                    &address,
                                    &slate,
                                    Some(&mut tx_proof),
                                );

                                let signature = sign_challenge(
                                    &client.challenge.clone().unwrap(),
                                    &secret_key,
                                )?
                                .to_hex();
                                let request_sub = ProtocolRequestV2::Subscribe {
                                    address: client.address.public_key.to_string(),
                                    ver: ver.to_string(),
                                    signature,
                                };

                                match client.send(&request_sub) {
                                    Ok(()) => {
                                        //send feedback to epicbox that we successfully finalize
                                        match client.made_send(epicboxmsgid.clone()) {
                                            Ok(()) => { /* do nothing */ }
                                            Err(e) => {
                                                error!(
                                                    "Error attempting to send 'made' message!: {}",
                                                    e.to_string()
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            "Could not send subscribe request: {}",
                                            e.to_string()
                                        );
                                    }
                                };
                            }
                            ProtocolResponseV2::GetVersion { str } => {
                                trace!("ProtocolResponseV2::GetVersion {}", str);
                            }
                            ProtocolResponseV2::Error {
                                ref kind,
                                description: _,
                            } => match kind {
                                ProtocolError::InvalidRequest {} => {
                                    error!(
                                        "Invalid Request! Ensure you are connected to an \
											epicbox that supports protocol 3.0.0!"
                                    );
                                }
                                _ => {
                                    error!("ProtocolResponse::Error {}", response);
                                }
                            },
                            ProtocolResponseV2::Ok {} => {
                                debug!("Response Ok.");
                            }
                        }
                    }
                    Message::Ping(_) => {}
                    Message::Pong(_) => {}
                    Message::Frame(_) => {}
                    Message::Close(_) => {
                        info!("Close connection");
                        handler.lock().on_close(CloseReason::Normal);
                        let _ = client.sender.lock().close(None);
                        break Ok(());
                    }
                },
            };
        }; //end loop

        res
    }

    fn post_slate(
        &self,
        slate: &VersionedSlate,
        to: &EpicboxAddress,
        from: &EpicboxAddress,
        secret_key: &SecretKey,
    ) -> Result<(), Error> {
        let pkey = to.public_key()?;

        let skey = secret_key.clone();

        let message =
            EncryptedMessage::new(serde_json::to_string(&slate).unwrap(), &to, &pkey, &skey)?;

        let message_ser = serde_json::to_string(&message).unwrap();
        let mut challenge = String::new();
        challenge.push_str(&message_ser);

        let signature = sign_challenge(&challenge, secret_key)?.to_hex();
        let request = ProtocolRequest::PostSlate {
            from: from.stripped(),
            to: to.stripped(),
            str: message_ser,
            signature,
        };

        let slate: Slate = slate.into();
        debug!("Starting to send slate with id [{}]", slate.id.to_string());

        self.inner
            .lock()
            .send(Message::Text(
                serde_json::to_string(&request).unwrap().into(),
            ))
            .unwrap();

        debug!("Slate sent successfully!");

        Ok(())
    }
    fn stop(&self) -> Result<(), tungsteniteError> {
        self.inner.lock().close(None)
    }
}

struct EpicboxClient<'a, P, L, C, K>
where
    L: WalletLCProvider<'static, C, K> + 'static,
    C: NodeClient + 'static,
    K: Keychain + 'static,
    P: Publisher,
{
    sender: Arc<Mutex<WebSocket<MaybeTlsStream<TcpStream>>>>,
    handler: Arc<Mutex<EpicboxController<'a, P, L, C, K>>>,
    challenge: Option<String>,
    address: EpicboxAddress,
    secret_key: SecretKey,
    tx: Sender<bool>,
}

/// client with handler from ws package
impl<'a, P, L, C, K> EpicboxClient<'a, P, L, C, K>
where
    P: Publisher,
    L: WalletLCProvider<'static, C, K> + 'static,
    C: NodeClient + 'static,
    K: Keychain + 'static,
{
    fn made_send(&self, epicboxmsgid: String) -> Result<(), Error> {
        let signature = sign_challenge(&epicboxmsgid, &self.secret_key)?.to_hex();
        let request = ProtocolRequestV2::Made {
            address: self.address.public_key.to_string(),
            signature,
            epicboxmsgid,
            ver: EPICBOX_PROTOCOL_VERSION.to_string(),
        };

        match self.send(&request) {
            Ok(_) => {
                self.tx.send(true).unwrap();
                Ok(())
            }
            Err(e) => Err(Error::EpicboxTungstenite(
                format!("Could not send 'Made' request! {}", e).into(),
            )),
        }
    }

    fn client_details(&self, wallet_mode: String) -> Result<(), Error> {
        let version = env!("CARGO_PKG_VERSION");

        let request = ProtocolRequestV2::ClientDetails {
            wallet_version: version.to_string(),
            wallet_mode,
            protocol_version: EPICBOX_PROTOCOL_VERSION.to_string(),
        };

        match self.send(&request) {
            Ok(_) => Ok(()),
            Err(e) => Err(Error::EpicboxTungstenite(
                format!("Could not send 'ClientDetails' request! {}", e).into(),
            )),
        }
    }

    fn send(&self, request: &ProtocolRequestV2) -> Result<(), ErrorTungstenite> {
        let request = serde_json::to_string(&request).unwrap();
        self.sender.lock().send(Message::Text(request.into()))
    }
}
